import { config } from '../../config/environment.js';
import { logger } from '../../utils/logger.js';
import { renderTelegram } from './render.js';
import type { MessageKind, MessageSpec, RenderedMessage, SendResult } from './types.js';

const API_BASE = 'https://api.telegram.org';
const CHUNK_LIMIT = 3_800;
const REQUEST_TIMEOUT_MS = 10_000;

interface TelegramApiResponse {
  ok?: boolean;
  result?: { message_id?: number };
  description?: string;
  parameters?: { retry_after?: number };
}

interface ApiCallResult {
  status: number;
  body: TelegramApiResponse | null;
  networkError?: string;
}

export interface SendOptions {
  chatId?: string | number;
  kind?: MessageKind;
  dryRun?: boolean;
  replyMarkup?: RenderedMessage['replyMarkup'];
}

function resolveChatId(opts?: SendOptions): string {
  return String(opts?.chatId ?? config.telegram.chatId ?? '');
}

function isDryRun(opts?: SendOptions): boolean {
  return opts?.dryRun ?? config.telegram.dryRun;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function callApi(method: string, payload: Record<string, unknown>): Promise<ApiCallResult> {
  try {
    const response = await fetch(`${API_BASE}/bot${config.telegram.botToken}/${method}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    const raw = await response.text().catch(() => '');
    let body: TelegramApiResponse | null = null;
    try {
      body = raw ? JSON.parse(raw) as TelegramApiResponse : null;
    } catch {
      body = null;
    }
    return { status: response.status, body };
  } catch (err) {
    return { status: 0, body: null, networkError: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Divide texto HTML em blocos que o Telegram aceita, sem cortar tags no meio.
 * Blocos maiores que o limite caem para texto puro (melhor perder formatação
 * do que perder a mensagem inteira por parse error).
 */
export function chunkTelegramText(text: string, limit = CHUNK_LIMIT): string[] {
  if (text.length <= limit) return [text];

  const chunks: string[] = [];
  let current = '';

  const flush = () => {
    if (current.trim().length > 0) chunks.push(current);
    current = '';
  };

  for (const block of text.split(/\n{2,}/)) {
    const candidate = current ? `${current}\n\n${block}` : block;
    if (candidate.length <= limit) {
      current = candidate;
      continue;
    }

    flush();
    if (block.length <= limit) {
      current = block;
      continue;
    }

    for (const line of block.split('\n')) {
      const lineCandidate = current ? `${current}\n${line}` : line;
      if (lineCandidate.length <= limit) {
        current = lineCandidate;
        continue;
      }

      flush();
      if (line.length <= limit) {
        current = line;
        continue;
      }

      const plain = line.replace(/<[^>]+>/g, '');
      for (let i = 0; i < plain.length; i += limit) {
        chunks.push(plain.slice(i, i + limit));
      }
    }
  }

  flush();
  return chunks.length > 0 ? chunks : [text.slice(0, limit)];
}

async function sendChunk(
  chatId: string,
  text: string,
  replyMarkup: SendOptions['replyMarkup'],
  kind: MessageKind | undefined,
  dryRun: boolean,
): Promise<SendResult> {
  const startedAt = Date.now();
  const basePayload: Record<string, unknown> = {
    chat_id: chatId,
    text,
    parse_mode: 'HTML',
    disable_web_page_preview: true,
  };
  if (replyMarkup) basePayload.reply_markup = replyMarkup;

  if (dryRun) {
    logger.info({ kind, chatId, chars: text.length, preview: text.slice(0, 120) }, 'telegram_send (dry run)');
    return { ok: true, messageId: -1, latencyMs: Date.now() - startedAt, chatId, dryRun: true };
  }

  let payload = { ...basePayload };
  let attemptedPlain = false;

  for (let attempt = 0; attempt < 3; attempt++) {
    const result = await callApi('sendMessage', payload);

    if (result.networkError) {
      if (attempt === 0) {
        await sleep(300);
        continue;
      }
      const latencyMs = Date.now() - startedAt;
      logger.warn({ kind, chatId, latencyMs, error: result.networkError }, 'telegram_send failed');
      return { ok: false, error: result.networkError, latencyMs };
    }

    if (result.status === 429 && attempt < 2) {
      const retryAfter = result.body?.parameters?.retry_after ?? 1;
      await sleep(Math.min(retryAfter, 3) * 1_000);
      continue;
    }

    if (result.status >= 500 && attempt === 0) {
      await sleep(500);
      continue;
    }

    const description = result.body?.description ?? '';
    if (result.status === 400 && !attemptedPlain && /parse entities|can't parse/i.test(description)) {
      attemptedPlain = true;
      const plainPayload = { ...payload };
      delete plainPayload.parse_mode;
      payload = plainPayload;
      continue;
    }

    const latencyMs = Date.now() - startedAt;
    if (result.body?.ok) {
      const messageId = result.body.result?.message_id;
      logger.info({ kind, chatId, messageId, status: result.status, latencyMs, chars: text.length }, 'telegram_send');
      return { ok: true, messageId, status: result.status, latencyMs, chatId };
    }

    logger.warn({ kind, chatId, status: result.status, description: description.slice(0, 200), latencyMs }, 'telegram_send failed');
    return { ok: false, status: result.status, error: description || 'unknown Telegram error', latencyMs };
  }

  return { ok: false, error: 'retries exhausted', latencyMs: Date.now() - startedAt };
}

export class TelegramSender {
  async sendSpec(spec: MessageSpec, opts?: SendOptions): Promise<SendResult> {
    const rendered = renderTelegram(spec);
    return this.sendRendered(rendered, { ...opts, kind: opts?.kind ?? spec.kind });
  }

  async sendRendered(rendered: RenderedMessage, opts?: SendOptions): Promise<SendResult> {
    const chatId = resolveChatId(opts);
    if (!chatId || !config.telegram.botToken) {
      logger.debug({ kind: opts?.kind }, 'telegram_send skipped (not configured)');
      return { ok: false, error: 'telegram not configured', latencyMs: 0 };
    }

    const chunks = chunkTelegramText(rendered.text);
    let last: SendResult = { ok: false, error: 'no chunks', latencyMs: 0 };

    for (let i = 0; i < chunks.length; i++) {
      const suffix = chunks.length > 1 ? `\n\n<i>(continuação ${i + 1}/${chunks.length})</i>` : '';
      const text = chunks[i]! + suffix;
      last = await sendChunk(
        chatId,
        text,
        i === 0 ? rendered.replyMarkup : undefined,
        opts?.kind,
        isDryRun(opts),
      );
      if (!last.ok) break;
    }

    return last;
  }

  async sendText(text: string, opts?: SendOptions): Promise<SendResult> {
    return this.sendRendered({ text, replyMarkup: opts?.replyMarkup }, opts);
  }

  async editSpec(chatId: string | number, messageId: number, spec: MessageSpec): Promise<SendResult> {
    const rendered = renderTelegram(spec);
    return this.editText(chatId, messageId, rendered.text, { kind: spec.kind, replyMarkup: rendered.replyMarkup });
  }

  async editText(
    chatId: string | number,
    messageId: number,
    text: string,
    opts?: SendOptions,
  ): Promise<SendResult> {
    const targetChatId = String(chatId);
    if (isDryRun(opts)) {
      logger.info({ kind: opts?.kind, chatId, messageId, chars: text.length }, 'telegram_edit (dry run)');
      return { ok: true, messageId, latencyMs: 0, dryRun: true };
    }

    const payload: Record<string, unknown> = {
      chat_id: targetChatId,
      message_id: messageId,
      text,
      parse_mode: 'HTML',
      disable_web_page_preview: true,
      reply_markup: opts?.replyMarkup ?? { inline_keyboard: [] },
    };

    const startedAt = Date.now();
    const result = await callApi('editMessageText', payload);
    const latencyMs = Date.now() - startedAt;
    const description = result.body?.description ?? '';

    if (result.body?.ok || /message is not modified/i.test(description)) {
      logger.info({ kind: opts?.kind, chatId, messageId, latencyMs }, 'telegram_edit');
      return { ok: true, messageId, status: result.status, latencyMs, chatId: targetChatId };
    }

    logger.warn({ kind: opts?.kind, chatId, messageId, status: result.status, description }, 'telegram_edit failed');
    return { ok: false, status: result.status, error: description || 'edit failed', latencyMs };
  }

  async answer(callbackId: string, text: string): Promise<void> {
    if (isDryRun()) return;
    try {
      await callApi('answerCallbackQuery', { callback_query_id: callbackId, text });
    } catch (err) {
      logger.debug({ err }, 'answerCallbackQuery failed');
    }
  }
}

export const telegram = new TelegramSender();
