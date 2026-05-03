import { describe, it, expect, beforeEach } from 'vitest';
import { PlaybookEngine, type PlaybookDefinition, type PlaybookContext } from '../src/playbooks/engine.js';

describe('PlaybookEngine - Condition Evaluator', () => {
  beforeEach(() => {
    PlaybookEngine.registerAction('test-action', async () => ({ success: true, message: 'ok' }));
  });

  function makeCtx(variables: Record<string, unknown> = {}): PlaybookContext {
    return {
      serverId: 1,
      serverName: 'test-server',
      incidentId: 1,
      sourceIp: '1.2.3.4',
      triggeredBy: 'test',
      variables,
    };
  }

  function makePlaybook(condition: string): PlaybookDefinition {
    return {
      name: 'test-playbook',
      description: 'test',
      trigger: { eventType: 'test' },
      steps: [{ action: 'test-action', condition }],
      requiresApproval: false,
    };
  }

  it('evaluates simple > condition', async () => {
    const ctx = makeCtx({ score: 80 });
    const result = await PlaybookEngine.execute(makePlaybook('score > 70'), ctx);
    expect(result.success).toBe(true);
  });

  it('skips step when condition not met', async () => {
    const ctx = makeCtx({ score: 30 });
    const result = await PlaybookEngine.execute(makePlaybook('score > 70'), ctx);
    expect(result.success).toBe(true);
  });

  it('evaluates OR condition — first true', async () => {
    const ctx = makeCtx({ score: 80, repeatCount: 0 });
    const result = await PlaybookEngine.execute(makePlaybook('score > 70 OR repeatCount > 2'), ctx);
    expect(result.success).toBe(true);
  });

  it('evaluates OR condition — second true', async () => {
    const ctx = makeCtx({ score: 10, repeatCount: 5 });
    const result = await PlaybookEngine.execute(makePlaybook('score > 70 OR repeatCount > 2'), ctx);
    expect(result.success).toBe(true);
  });

  it('evaluates OR condition — both false skips step', async () => {
    const ctx = makeCtx({ score: 10, repeatCount: 1 });
    const result = await PlaybookEngine.execute(makePlaybook('score > 70 OR repeatCount > 2'), ctx);
    expect(result.success).toBe(true);
  });

  it('evaluates AND condition — both true', async () => {
    const ctx = makeCtx({ score: 60, repeatCount: 3 });
    const result = await PlaybookEngine.execute(makePlaybook('score > 30 AND repeatCount > 0'), ctx);
    expect(result.success).toBe(true);
  });

  it('evaluates AND condition — one false skips step', async () => {
    const ctx = makeCtx({ score: 60, repeatCount: 0 });
    const result = await PlaybookEngine.execute(makePlaybook('score > 30 AND repeatCount > 0'), ctx);
    expect(result.success).toBe(true);
  });

  it('evaluates != operator', async () => {
    const ctx = makeCtx({ authMethod: 1 });
    const result = await PlaybookEngine.execute(makePlaybook('authMethod != 0'), ctx);
    expect(result.success).toBe(true);
  });

  it('handles missing variable as false (step skipped)', async () => {
    const ctx = makeCtx({});
    const result = await PlaybookEngine.execute(makePlaybook('score > 70'), ctx);
    expect(result.success).toBe(true);
  });

  it('fails when action is not registered', async () => {
    const playbook: PlaybookDefinition = {
      name: 'test-unknown',
      description: 'test',
      trigger: { eventType: 'test' },
      steps: [{ action: 'unknown-action' }],
      requiresApproval: false,
    };
    const result = await PlaybookEngine.execute(playbook, makeCtx());
    expect(result.success).toBe(false);
  });
});
