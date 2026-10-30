import type { MessageSeverity } from './types.js';

const HTML_ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
};

/** Escapa texto dinâmico para o modo HTML do Telegram. */
export function escapeHtml(value: unknown): string {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[&<>"]/g, ch => HTML_ESCAPES[ch] ?? ch);
}

/**
 * Normaliza texto vindo de log, IA ou banco: remove controles, colapsa
 * espaços e limita o tamanho. Não escapa HTML — chame escapeHtml depois.
 */
export function cleanText(value: unknown, max = 200): string {
  if (value === null || value === undefined) return '';
  const text = Array.from(String(value)).map(ch => {
    const code = ch.charCodeAt(0);
    const isControl = code <= 8 || code === 11 || code === 12 || (code >= 14 && code <= 31) || code === 127;
    return isControl ? ' ' : ch;
  }).join('').replace(/\s+/g, ' ').trim();
  return truncate(text, max);
}

export function truncate(text: string, max: number): string {
  if (max <= 0) return '';
  if (text.length <= max) return text;
  if (max === 1) return '…';
  return `${text.slice(0, max - 1).trimEnd()}…`;
}

export function severityIcon(severity: MessageSeverity | string): string {
  switch (severity) {
    case 'critical': return '🔴';
    case 'high': return '🟠';
    case 'medium': return '🟡';
    case 'low': return '🔵';
    default: return '⚪';
  }
}

export function severityWord(severity: MessageSeverity | string): string {
  switch (severity) {
    case 'critical': return 'crítica';
    case 'high': return 'alta';
    case 'medium': return 'média';
    case 'low': return 'baixa';
    default: return 'desconhecida';
  }
}

const BRT_FORMATTER = new Intl.DateTimeFormat('pt-BR', {
  timeZone: 'America/Sao_Paulo',
  day: '2-digit',
  month: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
});

const RELATIVE_FORMATTER = new Intl.RelativeTimeFormat('pt-BR', { numeric: 'auto' });

export function formatWhen(date?: Date | null, now = new Date()): string {
  if (!date || Number.isNaN(date.getTime())) return 'agora';
  const absolute = `${BRT_FORMATTER.format(date)} (BRT)`;
  const diffMs = now.getTime() - date.getTime();
  if (diffMs < 60_000) return absolute;
  const minutes = Math.round(diffMs / 60_000);
  if (minutes < 60) return `${absolute} · ${RELATIVE_FORMATTER.format(-minutes, 'minute')}`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${absolute} · ${RELATIVE_FORMATTER.format(-hours, 'hour')}`;
  const days = Math.round(hours / 24);
  return `${absolute} · ${RELATIVE_FORMATTER.format(-days, 'day')}`;
}

export function formatNumber(value: number): string {
  if (!Number.isFinite(value)) return '0';
  return new Intl.NumberFormat('pt-BR').format(value);
}

/** callback_data do Telegram é limitado a 64 bytes. */
export function callbackDataFits(id: string, maxBytes = 64): boolean {
  return Buffer.byteLength(id, 'utf8') <= maxBytes;
}

/** Remove tags HTML de texto gerado internamente antes de reescapar. */
export function stripHtml(value: string): string {
  return value.replace(/<[^>]+>/g, '');
}
