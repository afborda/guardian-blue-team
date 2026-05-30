import { SSHCollector } from '../../collectors/ssh-collector.js';
import type { ServerService } from '../../services/server.service.js';
import { logger } from '../../utils/logger.js';

export const GUARDIAN_CHAIN = 'GUARDIAN-INPUT';

type SSHTarget = ReturnType<typeof ServerService.toSSHTarget>;

// Per-server cache: once we've ensured the chain exists in the current Guardian
// process lifetime, skip the four SSH probes. Reset on process restart so an
// operator who flushed the chain manually triggers a re-check.
const chainEnsured = new Set<number>();

/**
 * Idempotently ensure GUARDIAN-INPUT chain exists and INPUT jumps to it.
 *
 * Why: rate-limit and block-ip iptables fallbacks insert into INPUT directly
 * today. If the operator runs `iptables -F INPUT` (common during firewall
 * troubleshooting), Guardian rules vanish silently. Putting our rules in a
 * dedicated chain means flush of INPUT removes only the jump (which we restore
 * here on next call), and `iptables -F GUARDIAN-INPUT` is the only command
 * that can wipe Guardian rules — making accidents harder.
 *
 * Returns false if any step fails (caller should fall back or surface error);
 * does NOT throw because the caller usually has a meaningful response path.
 */
export async function ensureGuardianChain(
  target: SSHTarget,
  serverId: number,
): Promise<boolean> {
  if (chainEnsured.has(serverId)) return true;

  // Step 1: create chain if missing. `-N` errors if it exists, so we check first.
  const exists = await SSHCollector.run(
    target,
    `sudo iptables -S ${GUARDIAN_CHAIN} 2>/dev/null | head -1`,
    5_000,
  );
  if (!exists.success || !exists.stdout.trim()) {
    const create = await SSHCollector.run(target, `sudo iptables -N ${GUARDIAN_CHAIN} 2>&1`, 5_000);
    // Race: two concurrent callers pass the `-S` probe and both run `-N`. The
    // loser sees "Chain already exists" — that's the state we wanted, so treat
    // it as success rather than aborting the rate-limit/block.
    const alreadyExists = !create.success && /already exists/i.test(create.error ?? create.stdout ?? '');
    if (!create.success && !alreadyExists) {
      logger.warn({ serverId, err: create.error }, 'ensureGuardianChain: iptables -N failed');
      return false;
    }
  }

  // Step 2: ensure INPUT jumps to GUARDIAN-INPUT. `-C` returns success if rule
  // exists, failure otherwise — that's exactly the test we want.
  const hasJump = await SSHCollector.run(
    target,
    `sudo iptables -C INPUT -j ${GUARDIAN_CHAIN} 2>/dev/null`,
    5_000,
  );
  if (!hasJump.success) {
    // Insert at top so Guardian rules are evaluated before any operator-defined
    // INPUT rules. Position 1 because lower numbers = earlier evaluation.
    const addJump = await SSHCollector.run(
      target,
      `sudo iptables -I INPUT 1 -j ${GUARDIAN_CHAIN}`,
      5_000,
    );
    if (!addJump.success) {
      logger.warn({ serverId, err: addJump.error }, 'ensureGuardianChain: iptables -I INPUT jump failed');
      return false;
    }
  }

  chainEnsured.add(serverId);
  logger.debug({ serverId }, `${GUARDIAN_CHAIN} chain ensured`);
  return true;
}

/**
 * Forget the cached "ensured" state for a server. Call when reconcile worker
 * detects the chain was wiped, or after explicit operator action.
 */
export function invalidateChainCache(serverId: number): void {
  chainEnsured.delete(serverId);
}
