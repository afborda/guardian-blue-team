import { config } from '../../config/environment.js';
import type { MessageKind } from './types.js';

/**
 * Rollout das mensagens v2.
 *
 * - `all` (padrão): todas as famílias migradas.
 * - `legacy`: volta ao formato antigo onde ainda existe caminho legado
 *   (incidentes e avisos de playbook).
 *
 * Listas por família ficam reservadas para uma segunda etapa; hoje o código
 * não mantém dois renderizadores para CVE/login/bloqueio.
 */
export function copyV2Enabled(kind: MessageKind): boolean {
  const value = (config.telegram.copyV2 ?? 'all').trim().toLowerCase();
  if (value === 'legacy') return false;
  if (!value || value === 'all') return true;
  return value.split(',').map(part => part.trim()).includes(kind);
}
