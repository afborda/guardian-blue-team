import { HostSecurityService } from '../services/host-security.service.js';
import { ServerService } from '../services/server.service.js';
import { db, dbDate } from '../database/connection.js';
import { securityEvents, socIncidents, serverScores } from '../database/schema.js';
import { gte, ne, desc, count, eq, and } from 'drizzle-orm';
import { NotifierManager } from '../plugins/notifier-manager.js';
import { AnomalyDetector } from '../intelligence/anomaly-detector.js';
import { TrendPredictor } from '../intelligence/trend-predictor.js';
import { logger } from '../utils/logger.js';
import { stripHtml } from '../telegram/messaging/style.js';
import type { MessageSpec } from '../telegram/messaging/types.js';

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
      `📊 <b>Relatório diário</b>`,
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

    if (openIncidents.cnt > 0) {
      lines.push(``, `👉 <b>Precisa de você:</b> ${openIncidents.cnt} incidente(s) aberto(s). Digite /incidents para ver.`);
    }

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

    // Scores summary — batch query for latest score per server
    const scoreLines: string[] = [];
    if (servers.length > 0) {
      const latestScores = await db.select().from(serverScores)
        .orderBy(desc(serverScores.periodStart))
        .limit(servers.length * 2);

      const scoreMap = new Map<number, typeof latestScores[0]>();
      for (const score of latestScores) {
        if (!scoreMap.has(score.serverId)) scoreMap.set(score.serverId, score);
      }

      for (const server of servers) {
        const score = scoreMap.get(server.id);
        if (score) {
          const icon = score.overallScore >= 80 ? '🟢' : score.overallScore >= 60 ? '🟡' : score.overallScore >= 40 ? '🟠' : '🔴';
          scoreLines.push(`   ${icon} ${server.name}: ${score.overallScore}/100 (H:${score.healthScore} S:${score.securityScore} Q:${score.qualityScore})`);
        }
      }
    }
    if (scoreLines.length > 0) {
      lines.push(``, `📊 <b>Scores:</b>`, ...scoreLines);
    }

    // Anomalies and trends
    const anomalyLines: string[] = [];
    const trendLines: string[] = [];
    for (const server of servers) {
      const anomalies = await AnomalyDetector.detect(server.id);
      for (const a of anomalies.filter(x => x.severity === 'critical')) {
        anomalyLines.push(`   ⚠️ ${server.name}: ${a.metric} = ${a.currentValue} (${a.deviations}σ)`);
      }
      const trends = await TrendPredictor.predict(server.id);
      for (const t of trends.filter(x => x.daysUntil90 !== null && x.daysUntil90 < 14)) {
        const resource = t.metric === 'disk' ? `disco ${t.mountpoint}` : 'memória';
        trendLines.push(`   📈 ${server.name}: ${resource} atinge 90% em ~${t.daysUntil90}d`);
      }
    }
    if (anomalyLines.length > 0) {
      lines.push(``, `🔍 <b>Anomalias:</b>`, ...anomalyLines);
    }
    if (trendLines.length > 0) {
      lines.push(``, `📈 <b>Tendências:</b>`, ...trendLines);
    }

    for (const server of servers) {
      const target = ServerService.toSSHTarget(server);
      const snapshot = await HostSecurityService.getSnapshot(target, 24);
      lines.push(``, `━━━━━━━━━━━━━━━━━━━━━━`);
      this.appendSnapshotLines(lines, snapshot);
    }

    const details = lines
      .slice(3)
      .filter(line => !line.includes('Precisa de você'))
      .map(stripHtml);

    const open = openIncidents.cnt;
    const spec: MessageSpec = {
      kind: 'report',
      severity: open > 0 ? 'high' : 'low',
      title: 'Relatório diário de segurança',
      lead: `Nas últimas 24h: ${totalEvents.cnt} eventos, ${totalIncidents.cnt} novos incidentes e ${open} em aberto, em ${servers.length} servidores.`,
      facts: [
        { label: 'Eventos', value: String(totalEvents.cnt) },
        { label: 'Novos incidentes', value: String(totalIncidents.cnt) },
        { label: 'Em aberto', value: String(open) },
        { label: 'Servidores', value: String(servers.length) },
      ],
      action: open > 0
        ? {
            required: true,
            title: 'Precisa de você',
            steps: [`Digite /incidents para revisar os ${open} incidente(s) aberto(s).`],
            fallbackCommand: '/incidents',
          }
        : {
            required: false,
            title: 'Precisa de você',
            steps: ['Nada crítico nas últimas 24h.'],
          },
      sections: details.length > 0 ? [{ title: 'Detalhes das últimas 24h', lines: details }] : undefined,
    };

    await NotifierManager.notifySpec(spec);
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
