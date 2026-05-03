import { HostSecurityService } from '../services/host-security.service.js';
import { ServerService } from '../services/server.service.js';
import { db, dbDate } from '../database/connection.js';
import { securityEvents, socIncidents } from '../database/schema.js';
import { gte, ne, desc, count, eq, and } from 'drizzle-orm';
import { NotifierManager } from '../plugins/notifier-manager.js';
import { logger } from '../utils/logger.js';

export class DailyReportWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static readonly CHECK_INTERVAL_MS = 60 * 1000;

  static start(): void {
    if (this.intervalId) return;

    this.intervalId = setInterval(() => {
      this.checkAndSend().catch(err => logger.error({ err }, 'Daily report check error'));
    }, this.CHECK_INTERVAL_MS);

    logger.info('Daily report worker started (sends at 08:00 BRT)');
  }

  private static lastSentDate: string | null = null;

  private static async checkAndSend(): Promise<void> {
    const now = new Date();
    const brt = new Date(now.toLocaleString('en-US', { timeZone: 'America/Sao_Paulo' }));
    const hour = brt.getHours();
    const dateKey = brt.toISOString().split('T')[0];

    if (hour === 8 && this.lastSentDate !== dateKey) {
      this.lastSentDate = dateKey;
      await this.sendReport();
    }
  }

  static async sendReport(): Promise<void> {
    logger.info('Generating daily security report...');

    const servers = await ServerService.getEnabled();
    const since24h = new Date(Date.now() - 24 * 3600 * 1000);
    const since24hDb = dbDate(since24h);

    const lines: string[] = [
      `📊 <b>RELATÓRIO DIÁRIO</b>`,
      `📅 ${new Date().toLocaleDateString('pt-BR')}`,
      `🖥️ ${servers.length} servidores monitorados`,
    ];

    const [totalEvents] = await db.select({ cnt: count() })
      .from(securityEvents).where(gte(securityEvents.timestamp, since24hDb));
    const [totalIncidents] = await db.select({ cnt: count() })
      .from(socIncidents).where(gte(socIncidents.firstSeenAt, since24hDb));
    const [openIncidents] = await db.select({ cnt: count() })
      .from(socIncidents).where(eq(socIncidents.status, 'open'));

    lines.push(
      ``,
      `📈 <b>Últimas 24h:</b>`,
      `   • ${totalEvents.cnt} eventos coletados`,
      `   • ${totalIncidents.cnt} novos incidentes (${openIncidents.cnt} abertos)`,
    );

    const topAttackers = await db.select({
      ip: securityEvents.sourceIp,
      cnt: count(),
    })
      .from(securityEvents)
      .where(and(
        gte(securityEvents.timestamp, since24hDb),
        ne(securityEvents.severity, 'info'),
      ))
      .groupBy(securityEvents.sourceIp)
      .orderBy(desc(count()))
      .limit(5);

    if (topAttackers.length > 0) {
      lines.push(``, `🎯 <b>Top Atacantes:</b>`);
      for (let i = 0; i < topAttackers.length; i++) {
        const a = topAttackers[i];
        if (a.ip) lines.push(`   ${i + 1}. <code>${a.ip}</code> — ${a.cnt} eventos`);
      }
    }

    for (const server of servers) {
      const target = ServerService.toSSHTarget(server);
      const snapshot = await HostSecurityService.getSnapshot(target, 24);
      lines.push(``, `━━━━━━━━━━━━━━━━━━━━━━`);
      this.appendSnapshotLines(lines, snapshot);
    }

    const message = lines.join('\n');

    await NotifierManager.notify({
      title: 'Relatório Diário de Segurança',
      body: message,
      severity: 'low',
      metadata: { type: 'daily-report' },
    });
    logger.info('Daily security report sent');
  }

  private static appendSnapshotLines(lines: string[], snapshot: ReturnType<typeof HostSecurityService.getSnapshot> extends Promise<infer T> ? T : never): void {
    lines.push(`🖥️ <b>${snapshot.serverName}</b>`);

    if (!snapshot.available) {
      lines.push(`   ⚠️ SSH indisponível`);
      return;
    }

    if (snapshot.bannedIpsNow > 0) {
      lines.push(`   🔒 Fail2ban: ${snapshot.bannedIpsNow} IPs banidos`);
    }

    lines.push(
      `   🔑 SSH: ${snapshot.failedLoginsTotal} falhas, ${snapshot.successfulLogins} OK, ${snapshot.uniqueAttackerIps} IPs`,
    );

    if (snapshot.failedLoginsByUser.length > 0) {
      lines.push(`   👤 Top: ${snapshot.failedLoginsByUser.slice(0, 3).map(u => `${u.user}(${u.count})`).join(', ')}`);
    }

    if (snapshot.blockedByPort.length > 0) {
      lines.push(
        `   🚫 UFW: ${snapshot.blockedTotal} — ${snapshot.blockedByPort.slice(0, 3).map(p => `${p.service}(${p.count})`).join(', ')}`,
      );
    }
  }

  static async stop(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    logger.info('Daily report worker stopped');
  }
}
