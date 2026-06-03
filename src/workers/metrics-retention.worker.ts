import { db, dbDate } from '../database/connection.js';
import { serverMetrics, securityEvents } from '../database/schema.js';
import { lte, and, inArray } from 'drizzle-orm';
import { logger } from '../utils/logger.js';

// Retention policy for security_events by event type.
// High-signal events (brute force, lateral movement, etc.) are kept indefinitely.
// Telemetry that floods the table but has no investigative value is pruned aggressively.
const SECURITY_EVENT_RETENTION: Array<{ types: string[]; days: number; label: string }> = [
  {
    label: 'high-volume telemetry (connection, process, config)',
    days: 7,
    types: [
      'container_connection',
      'container_config_ok',
      'container_process',
      'container_insecure_config',
      'docker_top',
      'docker_connect',
      'docker_disconnect',
      'docker_mount',
      'docker_unmount',
      'kernel_error',
    ],
  },
  {
    label: 'auth telemetry (successful logins, sessions)',
    days: 30,
    types: [
      'ssh_login_success',
      'session_opened',
      'interactive_session_active',
      'interactive_session_history',
    ],
  },
  {
    label: 'container filesystem diffs',
    days: 14,
    types: [
      'container_file_added',
      'container_file_changed',
    ],
  },
  {
    label: 'docker lifecycle events',
    days: 30,
    types: [
      'docker_start', 'docker_stop', 'docker_die', 'docker_kill',
      'docker_create', 'docker_destroy', 'docker_restart',
      'docker_rename', 'docker_prune', 'docker_tag', 'docker_untag',
      'docker_save', 'docker_pull', 'docker_import', 'docker_attach',
    ],
  },
  {
    label: 'firewall blocks (keep 90d for trend analysis)',
    days: 90,
    types: ['firewall_block'],
  },
  {
    label: 'systemd noise',
    days: 30,
    types: ['systemd_unit_failed', 'systemd_restart_loop', 'journal_error'],
  },
];

export class MetricsRetentionWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static readonly INTERVAL_MS = 24 * 60 * 60 * 1000;
  private static readonly METRICS_RETENTION_DAYS = 30;

  static start(): void {
    if (this.intervalId) return;

    setTimeout(() => {
      this.cleanup().catch(err => logger.error({ err }, 'Metrics retention cleanup error'));
    }, 60 * 60 * 1000);

    this.intervalId = setInterval(() => {
      this.cleanup().catch(err => logger.error({ err }, 'Metrics retention cleanup error'));
    }, this.INTERVAL_MS);

    logger.info(`Metrics retention worker started (deletes >=${this.METRICS_RETENTION_DAYS}d)`);
  }

  static async cleanup(): Promise<void> {
    const metricsCutoff = new Date(Date.now() - this.METRICS_RETENTION_DAYS * 24 * 60 * 60 * 1000);

    try {
      await db.delete(serverMetrics).where(
        lte(serverMetrics.collectedAt, dbDate(metricsCutoff))
      );
      logger.info({ cutoffDate: metricsCutoff.toISOString() }, 'Old server metrics purged');
    } catch (err) {
      logger.error({ err }, 'Server metrics retention failed');
    }

    let totalDeleted = 0;
    for (const policy of SECURITY_EVENT_RETENTION) {
      const cutoff = new Date(Date.now() - policy.days * 24 * 60 * 60 * 1000);
      try {
        const result = await db.delete(securityEvents).where(
          and(
            inArray(securityEvents.eventType, policy.types),
            lte(securityEvents.timestamp, dbDate(cutoff))
          )
        );
        const deleted = (result as unknown as { rowCount?: number }).rowCount ?? 0;
        if (deleted > 0) {
          logger.info({ label: policy.label, days: policy.days, deleted }, 'Security events purged');
          totalDeleted += deleted;
        }
      } catch (err) {
        logger.error({ err, label: policy.label }, 'Security event retention failed');
      }
    }

    if (totalDeleted > 0) {
      logger.info({ totalDeleted }, 'Security events retention complete');
    }
  }

  static async stop(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    logger.info('Metrics retention worker stopped');
  }
}
