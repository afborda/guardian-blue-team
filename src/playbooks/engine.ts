import { db, dbNow } from '../database/connection.js';
import { playbookExecutions } from '../database/schema.js';
import { eq } from 'drizzle-orm';
import { logger } from '../utils/logger.js';

export interface PlaybookStep {
  action: string;
  params?: Record<string, unknown>;
  condition?: string;
}

export interface PlaybookDefinition {
  name: string;
  description: string;
  trigger: {
    eventType: string;
    threshold?: number;
    window?: string;
  };
  steps: PlaybookStep[];
  requiresApproval: boolean;
}

export interface PlaybookContext {
  serverId: number;
  serverName: string;
  incidentId?: number;
  sourceIp?: string;
  triggeredBy: string;
  variables: Record<string, unknown>;
}

export type ActionFn = (ctx: PlaybookContext, params?: Record<string, unknown>) => Promise<{ success: boolean; message: string }>;

export class PlaybookEngine {
  private static actions = new Map<string, ActionFn>();

  static registerAction(name: string, fn: ActionFn): void {
    this.actions.set(name, fn);
  }

  static async execute(playbook: PlaybookDefinition, ctx: PlaybookContext): Promise<{ success: boolean; executionId: number }> {
    const [execution] = await db.insert(playbookExecutions).values({
      playbookName: playbook.name,
      incidentId: ctx.incidentId ?? null,
      serverId: ctx.serverId,
      triggerType: ctx.triggeredBy === 'auto' ? 'auto' : 'manual',
      triggeredBy: ctx.triggeredBy,
    }).returning();

    const stepsCompleted: string[] = [];
    const stepsFailed: string[] = [];

    logger.info({ playbook: playbook.name, executionId: execution.id, server: ctx.serverName }, 'Playbook started');

    for (const step of playbook.steps) {
      if (step.condition && !this.evaluateCondition(step.condition, ctx)) {
        logger.debug({ step: step.action, playbook: playbook.name }, 'Step skipped (condition not met)');
        continue;
      }

      const actionFn = this.actions.get(step.action);
      if (!actionFn) {
        stepsFailed.push(`${step.action}: action not registered`);
        logger.error({ action: step.action }, 'Unknown playbook action');
        break;
      }

      try {
        const result = await actionFn(ctx, step.params);
        if (result.success) {
          stepsCompleted.push(`${step.action}: ${result.message}`);
        } else {
          stepsFailed.push(`${step.action}: ${result.message}`);
          break;
        }
      } catch (error) {
        stepsFailed.push(`${step.action}: ${(error as Error).message}`);
        logger.error({ err: error, action: step.action }, 'Playbook step failed');
        break;
      }
    }

    const success = stepsFailed.length === 0;

    await db.update(playbookExecutions)
      .set({
        status: success ? 'completed' : 'failed',
        stepsCompleted,
        stepsFailed,
        completedAt: dbNow(),
      })
      .where(eq(playbookExecutions.id, execution.id));

    logger.info({
      playbook: playbook.name,
      executionId: execution.id,
      success,
      stepsCompleted: stepsCompleted.length,
      stepsFailed: stepsFailed.length,
    }, 'Playbook finished');

    if (success) {
      // notifyCompletion removed: the `notify` action already sends the alert
      // body and feedback buttons. A third "✅ Playbook Executed" recap was
      // pure noise.
      //
      // autoLearn(stepsCompleted) was also removed — it stored an
      // `outcome='resolved'` row in incident_memory for every successful
      // execution, which polluted FalsePositiveFilter's signal: the human
      // marking an incident as "false positive" got drowned in auto-resolved
      // execution logs. Real learning only fires from explicit human
      // feedback via the Telegram inline buttons.
    }

    return { success, executionId: execution.id };
  }

  private static evaluateCondition(condition: string, ctx: PlaybookContext): boolean {
    // Support OR conditions: "score > 70 OR repeatCount > 2"
    if (condition.includes(' OR ')) {
      return condition.split(' OR ').some(part => this.evaluateSingle(part.trim(), ctx));
    }
    // Support AND conditions: "score > 30 AND repeatCount > 0"
    if (condition.includes(' AND ')) {
      return condition.split(' AND ').every(part => this.evaluateSingle(part.trim(), ctx));
    }
    return this.evaluateSingle(condition, ctx);
  }

  private static evaluateSingle(condition: string, ctx: PlaybookContext): boolean {
    const match = condition.match(/^(\w+)\s*(>|<|>=|<=|==|!=)\s*(\d+)$/);
    if (!match) return true;

    const [, key, op, valueStr] = match;
    const actual = ctx.variables[key] as number | undefined;
    if (actual === undefined) return false;

    const value = parseInt(valueStr);
    switch (op) {
      case '>': return actual > value;
      case '<': return actual < value;
      case '>=': return actual >= value;
      case '<=': return actual <= value;
      case '==': return actual === value;
      case '!=': return actual !== value;
      default: return false;
    }
  }
}
