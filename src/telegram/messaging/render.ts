import type { InlineKeyboardMarkup, MessageAction, MessageSpec, RenderedMessage } from './types.js';
import { callbackDataFits, escapeHtml, formatWhen, severityIcon } from './style.js';

type Mode = 'html' | 'plain';

function text(value: string, mode: Mode): string {
  return mode === 'html' ? escapeHtml(value) : value;
}

function strong(value: string, mode: Mode): string {
  return mode === 'html' ? `<b>${escapeHtml(value)}</b>` : value;
}

function code(value: string, mode: Mode): string {
  return mode === 'html' ? `<code>${escapeHtml(value)}</code>` : value;
}

function italic(value: string, mode: Mode): string {
  return mode === 'html' ? `<i>${escapeHtml(value)}</i>` : value;
}

function actionLines(action: MessageAction, mode: Mode, hasButtons: boolean): string[] {
  const lines: string[] = [strong(action.title, mode)];

  if (action.steps.length === 1) {
    lines.push(text(action.steps[0]!, mode));
  } else if (action.steps.length > 1) {
    action.steps.slice(0, 3).forEach((step, index) => {
      lines.push(`${index + 1}. ${text(step, mode)}`);
    });
  } else if (!action.required) {
    lines.push(text('Não precisa fazer nada.', mode));
  }

  if (action.deadline) {
    lines.push(text(`Responda até ${formatWhen(action.deadline)}.`, mode));
  }
  if (action.ifIgnored) {
    lines.push(text(action.ifIgnored, mode));
  }
  if (action.fallbackCommand && (mode === 'plain' || !hasButtons)) {
    lines.push(
      mode === 'html'
        ? `Sem botão? Use ${code(action.fallbackCommand, mode)}.`
        : `Sem botão? Use ${action.fallbackCommand}.`,
    );
  }

  return lines;
}

function renderBlocks(spec: MessageSpec, mode: Mode): string[] {
  const blocks: string[] = [];
  const hasButtons = (spec.buttons?.length ?? 0) > 0;

  blocks.push(`${severityIcon(spec.severity)} ${strong(spec.title, mode)}`);
  blocks.push(text(spec.lead, mode));

  if (spec.facts && spec.facts.length > 0) {
    const facts = spec.facts.slice(0, 5).map(fact => {
      const value = fact.code ? code(fact.value, mode) : text(fact.value, mode);
      return `• ${strong(`${fact.label}:`, mode)} ${value}`;
    });
    blocks.push(facts.join('\n'));
  }

  if (spec.meaning) {
    blocks.push(strong('O que isso significa', mode));
    blocks.push(text(spec.meaning, mode));
  }

  if (spec.action) {
    blocks.push(actionLines(spec.action, mode, hasButtons).join('\n'));
  }

  for (const section of spec.sections ?? []) {
    blocks.push(strong(section.title, mode));
    blocks.push(section.lines.map(line => text(line, mode)).join('\n'));
  }

  if (spec.footer) {
    blocks.push(italic(spec.footer, mode));
  }

  return blocks;
}

export function renderKeyboard(spec: MessageSpec): InlineKeyboardMarkup | undefined {
  const buttons = (spec.buttons ?? []).filter(button => callbackDataFits(button.id));
  if (buttons.length === 0) return undefined;

  const rows: InlineKeyboardMarkup['inline_keyboard'] = [];
  for (let i = 0; i < buttons.length; i += 2) {
    rows.push(buttons.slice(i, i + 2).map(button => ({
      text: button.label,
      callback_data: button.id,
    })));
  }
  return { inline_keyboard: rows };
}

export function renderTelegram(spec: MessageSpec): RenderedMessage {
  const text = renderBlocks(spec, 'html').join('\n\n');
  return { text, replyMarkup: renderKeyboard(spec) };
}

/** Versão sem HTML para Slack/Discord/E-mail/WhatsApp. */
export function renderPlain(spec: MessageSpec): string {
  return renderBlocks(spec, 'plain').join('\n\n');
}
