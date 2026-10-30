import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { chunkTelegramText, telegram } from '../src/telegram/messaging/sender.js';
import type { MessageSpec } from '../src/telegram/messaging/types.js';

function response(status: number, body: unknown): Record<string, unknown> {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  };
}

function lastPayload(): Record<string, unknown> {
  const calls = vi.mocked(global.fetch).mock.calls;
  const init = calls[calls.length - 1]?.[1] as RequestInit | undefined;
  return JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
}

const spec: MessageSpec = {
  kind: 'incident',
  severity: 'high',
  title: 'Teste',
  lead: 'Mensagem de teste',
  action: { required: false, title: 'Nada a fazer', steps: ['Nada a fazer.'] },
};

describe('telegram sender', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends a spec and returns the message id', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(response(200, { ok: true, result: { message_id: 77 } }));

    const result = await telegram.sendSpec(spec);

    expect(result.ok).toBe(true);
    expect(result.messageId).toBe(77);
    expect(vi.mocked(global.fetch)).toHaveBeenCalledTimes(1);
    expect(lastPayload().parse_mode).toBe('HTML');
  });

  it('chunks long messages instead of failing at 4096 chars', async () => {
    vi.mocked(global.fetch).mockImplementation(async () => response(200, { ok: true, result: { message_id: 1 } }));

    const long = Array.from({ length: 120 }, (_, i) => `linha ${i} ${'x'.repeat(60)}`).join('\n');
    const result = await telegram.sendText(long);

    expect(result.ok).toBe(true);
    expect(vi.mocked(global.fetch).mock.calls.length).toBeGreaterThan(1);
    for (const call of vi.mocked(global.fetch).mock.calls) {
      const body = JSON.parse(String((call[1] as RequestInit).body)) as { text: string };
      expect(body.text.length).toBeLessThanOrEqual(4096);
    }
  });

  it('retries without parse_mode when Telegram rejects the HTML', async () => {
    vi.mocked(global.fetch)
      .mockResolvedValueOnce(response(400, { ok: false, description: "Bad Request: can't parse entities" }))
      .mockResolvedValueOnce(response(200, { ok: true, result: { message_id: 10 } }));

    const result = await telegram.sendSpec(spec);

    expect(result.ok).toBe(true);
    expect(lastPayload().parse_mode).toBeUndefined();
  });

  it('respects 429 retry_after and tries again', async () => {
    vi.mocked(global.fetch)
      .mockResolvedValueOnce(response(429, { ok: false, parameters: { retry_after: 0 } }))
      .mockResolvedValueOnce(response(200, { ok: true, result: { message_id: 11 } }));

    const result = await telegram.sendSpec(spec);

    expect(result.ok).toBe(true);
    expect(vi.mocked(global.fetch)).toHaveBeenCalledTimes(2);
  });

  it('does not call the API in dry run', async () => {
    const result = await telegram.sendSpec(spec, { dryRun: true });
    expect(result.ok).toBe(true);
    expect(result.dryRun).toBe(true);
    expect(vi.mocked(global.fetch)).not.toHaveBeenCalled();
  });

  it('edits a message and clears the keyboard', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(response(200, { ok: true, result: { message_id: 5 } }));

    const result = await telegram.editText('12345', 5, 'Editado');

    expect(result.ok).toBe(true);
    expect(vi.mocked(global.fetch)).toHaveBeenCalledTimes(1);
    const [url, init] = vi.mocked(global.fetch).mock.calls[0]!;
    expect(String(url)).toContain('editMessageText');
    const body = JSON.parse(String((init as RequestInit).body)) as Record<string, unknown>;
    expect(body.reply_markup).toEqual({ inline_keyboard: [] });
  });

  it('chunkTelegramText never splits a tag in half', () => {
    const text = `<b>${'a'.repeat(30)}</b>\n\n${'b'.repeat(50)}`;
    const chunks = chunkTelegramText(text, 40);
    expect(chunks.length).toBeGreaterThan(1);
    for (const chunk of chunks) {
      expect((chunk.match(/<b>/g) ?? []).length).toBe((chunk.match(/<\/b>/g) ?? []).length);
    }
  });
});
