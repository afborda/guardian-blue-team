import { db, dbTrue, dbFalse, dbNow } from '../database/connection.js';
import { rateLimitedIps, securityEvents } from '../database/schema.js';
import { and, eq, gte } from 'drizzle-orm';
import { blockIP } from '../playbooks/actions/block-ip.js';
import { removeRateLimit } from '../playbooks/actions/rate-limit.js';
import { ServerService } from '../services/server.service.js';
import { NotifierManager } from '../plugins/notifier-manager.js';
import { logger } from '../utils/logger.js';
import { CONSTANTS } from '../config/constants.js';

export class DDoSEscalationWorker {
  private static intervalId: NodeJS.Timeout | null = null;

  static start(): void {
    if (this.intervalId) return;
    this.intervalId = setInterval(() => {
      this.check().catch(err => logger.error({ err }, 'DDoS escalation check error'));
    }, CONSTANTS.ddos.escalationCheckIntervalMs);
    logger.info('DDoS escalation worker started');
  }

  static async check(): Promise<void> {
    const activeRateLimits = await db.select().from(rateLimitedIps)
      .where(eq(rateLimitedIps.active, dbTrue));

    if (activeRateLimits.length === 0) return;

    const escalationCutoff = new Date(Date.now() - CONSTANTS.ddos.escalationWindowMs);

    for (const rl of activeRateLimits) {
      // Check if this IP triggered new DDoS events since being rate-limited.
      //
      // syn_flood is intentionally NOT in this list. SYN floods are trivially
      // spoofed at the IP layer (no completed three-way handshake means the
      // source address is attacker-controlled), so escalating to a permanent
      // block on srcIP would let an attacker convince Guardian to ban arbitrary
      // third parties — e.g. flooding with srcIP=8.8.8.8 to break DNS for the
      // host. The local rate-limit in GUARDIAN-INPUT applied at first detection
      // is fine (it just drops; bans no one), but escalation is not.
      const newEvents = await db.select().from(securityEvents)
        .where(and(
          eq(securityEvents.sourceIp, rl.ip),
          gte(securityEvents.timestamp, rl.appliedAt),
          gte(securityEvents.timestamp, escalationCutoff),
        ))
        .then(rows => rows.filter(e =>
          e.eventType === 'connection_rate_spike' || e.eventType === 'connection_flood'
        ));

      if (newEvents.length > 0) {
        // Escalate: remove rate-limit, apply permanent block
        const server = await ServerService.getEnabled().then(s => s.find(srv => srv.id === rl.serverId));
        if (!server) continue;

        const ctx = { serverId: rl.serverId, serverName: server.name, sourceIp: rl.ip, triggeredBy: 'ddos-escalation', variables: {} };

        await removeRateLimit(ctx, { ip: rl.ip });
        const blockResult = await blockIP(ctx, { duration: 'permanent' });

        await db.update(rateLimitedIps)
          .set({ escalatedAt: dbNow(), active: dbFalse })
          .where(eq(rateLimitedIps.id, rl.id));

        if (blockResult.success) {
          await NotifierManager.notify({
            title: 'DDoS Escalation',
            body: `IP ${rl.ip} escalated from rate-limit to PERMANENT BLOCK on ${server.name}\nReason: ${newEvents.length} DDoS event(s) detected after rate-limit`,
            severity: 'critical',
            metadata: { type: 'ddos_escalation', ip: rl.ip },
          });
          logger.info({ ip: rl.ip, server: server.name, events: newEvents.length }, 'DDoS escalation: rate-limit -> permanent block');
        }
      }
    }
  }

  static async stop(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    logger.info('DDoS escalation worker stopped');
  }
}
