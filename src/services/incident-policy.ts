/**
 * Decide se um incidente pode entrar no auto-enforce de bloqueio.
 *
 * `egress` é o caso perigoso: o `sourceIp` do evento é o DESTINO do scan,
 * não a origem. Bloquear esse IP pune a vítima e resolve o incidente sem
 * conter o container. A contenção de egress é feita pelo playbook
 * `container-egress-containment`, não por block-ip.
 */
export function shouldAutoEnforceIncident(category?: string | null): boolean {
  return category !== 'egress';
}
