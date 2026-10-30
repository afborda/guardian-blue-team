/**
 * Contrato único das mensagens do Guardian.
 *
 * `MessageSpec` descreve o conteúdo em termos humanos; o renderer decide
 * layout/HTML e o sender cuida de entrega. Nenhum worker deve montar HTML
 * ou chamar a API do Telegram diretamente.
 */

export type MessageKind =
  | 'incident'
  | 'approval'
  | 'cve'
  | 'login'
  | 'block'
  | 'anomaly'
  | 'report'
  | 'system';

export type MessageSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface MessageFact {
  label: string;
  value: string;
  /** true para IPs, IDs e comandos (renderiza em <code>). */
  code?: boolean;
}

export interface MessageButton {
  /** callback_data do Telegram (máx. 64 bytes). */
  id: string;
  label: string;
  style: 'primary' | 'danger' | 'neutral';
}

export interface MessageSection {
  title: string;
  /** Linhas já em texto puro; o renderer escapa. */
  lines: string[];
}

export interface MessageAction {
  /** true = "preciso de você"; false = "não precisa fazer nada". */
  required: boolean;
  title: string;
  /** No máximo 3 passos. */
  steps: string[];
  deadline?: Date;
  ifIgnored?: string;
  /** Comando para quem usa um cliente sem botões. */
  fallbackCommand?: string;
}

export interface MessageSpec {
  kind: MessageKind;
  severity: MessageSeverity;
  /** Sentence case, curto. */
  title: string;
  /** Uma frase: o que aconteceu. */
  lead: string;
  facts?: MessageFact[];
  /** Até 2 frases, sem jargão. */
  meaning?: string;
  action?: MessageAction;
  /** Blocos de detalhe (relatórios), renderizados depois da ação. */
  sections?: MessageSection[];
  footer?: string;
  buttons?: MessageButton[];
  /** Deduplicação best-effort no processo. */
  dedupeKey?: string;
}

export interface InlineKeyboardButton {
  text: string;
  callback_data: string;
}

export interface InlineKeyboardMarkup {
  inline_keyboard: InlineKeyboardButton[][];
}

export interface RenderedMessage {
  text: string;
  replyMarkup?: InlineKeyboardMarkup;
}

export interface SendResult {
  ok: boolean;
  messageId?: number;
  status?: number;
  error?: string;
  latencyMs: number;
  chatId?: string;
  /** true quando o envio foi apenas registrado (TELEGRAM_DRY_RUN). */
  dryRun?: boolean;
}
