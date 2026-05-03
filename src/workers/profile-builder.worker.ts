import { db } from '../database/connection.js';
import { instances } from '../database/schema.js';
import { eq } from 'drizzle-orm';
import { InstanceProfileService } from '../services/instance-profile.service.js';
import { logger } from '../utils/logger.js';

export class ProfileBuilderWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static readonly INTERVAL_MS = 6 * 60 * 60 * 1000; // 6 hours

  static start(): void {
    if (this.intervalId) return;

    setTimeout(() => {
      this.rebuildAll().catch(err => logger.error({ err }, 'Initial profile build error'));
    }, 5 * 60 * 1000);

    this.intervalId = setInterval(() => {
      this.rebuildAll().catch(err => logger.error({ err }, 'Profile rebuild error'));
    }, this.INTERVAL_MS);

    logger.info('Profile builder worker started (every 6h)');
  }

  private static async rebuildAll(): Promise<void> {
    const activeInstances = await db
      .select({ clientId: instances.clientId })
      .from(instances)
      .where(eq(instances.status, 'active'));

    if (activeInstances.length === 0) return;

    logger.info(`Rebuilding profiles for ${activeInstances.length} instances`);

    for (const instance of activeInstances) {
      try {
        await InstanceProfileService.buildProfile(instance.clientId);
      } catch (error) {
        logger.error({ err: error }, `Profile build failed for ${instance.clientId}`);
      }
    }

    logger.info('Profile rebuild completed');
  }

  static async stop(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    logger.info('Profile builder worker stopped');
  }
}
