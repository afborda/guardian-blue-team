import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { PlaybookContext } from '../src/playbooks/engine.js';

// Mock dependencies BEFORE importing the service under test. Each mock is a
// fresh `vi.fn()` so individual tests can drive them per-scenario.
const lookupIPMock = vi.fn();
const aiIsAvailableMock = vi.fn();
const aiChatMock = vi.fn();
const buildContextForAIMock = vi.fn(async () => '');

vi.mock('../src/threat-intel/manager.js', () => ({
  ThreatIntelManager: { lookupIP: lookupIPMock },
}));
vi.mock('../src/services/ai-provider.js', () => ({
  AIProvider: {
    isAvailable: aiIsAvailableMock,
    chat: aiChatMock,
  },
}));
vi.mock('../src/services/incident-memory.service.js', () => ({
  IncidentMemoryService: { buildContextForAI: buildContextForAIMock },
}));

const { AIBlockAdvisor } = await import('../src/services/ai-block-advisor.service.js');

const baseCtx: PlaybookContext = {
  serverId: 1,
  serverName: 'web-01',
  sourceIp: '203.0.113.50',
  triggeredBy: 'detector',
  variables: {},
};

const baseEvent = {
  eventType: 'ssh_brute_force',
  severity: 'high',
  eventCount: 12,
  sourceIp: '203.0.113.50',
};

function aiResponse(action: string, confidence: number, reasoning = 'r'): { text: string } {
  return { text: JSON.stringify({ action, confidence, reasoning }) };
}

beforeEach(() => {
  lookupIPMock.mockReset();
  aiIsAvailableMock.mockReset();
  aiChatMock.mockReset();
  buildContextForAIMock.mockReset();
  buildContextForAIMock.mockResolvedValue('');
});

describe('AIBlockAdvisor — TI+AI consensus gate', () => {
  it('TI high (≥75): auto-blocks without consulting AI', async () => {
    lookupIPMock.mockResolvedValueOnce({ score: 88, source: 'abuseipdb' });
    aiIsAvailableMock.mockReturnValue(true);

    const rec = await AIBlockAdvisor.getRecommendation(baseCtx, baseEvent);

    expect(rec.action).toBe('block_permanent');
    expect(rec.source).toBe('ti_high');
    expect(rec.tiScore).toBe(88);
    // AI was NOT called — that's the whole point of the short-circuit.
    expect(aiChatMock).not.toHaveBeenCalled();
  });

  it('TI mid (30-74) + AI confident block ≥70: ti_ai_consensus', async () => {
    lookupIPMock.mockResolvedValueOnce({ score: 50, source: 'abuseipdb' });
    aiIsAvailableMock.mockReturnValue(true);
    aiChatMock.mockResolvedValueOnce(aiResponse('block_permanent', 80));

    const rec = await AIBlockAdvisor.getRecommendation(baseCtx, baseEvent);

    expect(rec.action).toBe('block_permanent');
    expect(rec.source).toBe('ti_ai_consensus');
    expect(rec.confidence).toBe(80);
    expect(rec.tiScore).toBe(50);
  });

  it('TI mid + AI block but only 60 conf: trusts AI soft call (ai_only, no consensus)', async () => {
    lookupIPMock.mockResolvedValueOnce({ score: 50, source: 'abuseipdb' });
    aiIsAvailableMock.mockReturnValue(true);
    aiChatMock.mockResolvedValueOnce(aiResponse('block_permanent', 60));

    const rec = await AIBlockAdvisor.getRecommendation(baseCtx, baseEvent);

    expect(rec.source).toBe('ai_only');
    // Action is whatever AI said (block_permanent) but the source flag
    // tells the caller TI consensus did not validate it.
    expect(rec.action).toBe('block_permanent');
    expect(rec.confidence).toBe(60);
  });

  it('No TI signal + AI block at <85 conf: downgrades to monitor', async () => {
    lookupIPMock.mockResolvedValueOnce(null);
    aiIsAvailableMock.mockReturnValue(true);
    aiChatMock.mockResolvedValueOnce(aiResponse('block_permanent', 75, 'looks bad'));

    const rec = await AIBlockAdvisor.getRecommendation(baseCtx, baseEvent);

    expect(rec.action).toBe('monitor');
    expect(rec.source).toBe('no_ti_low_conf');
    expect(rec.reasoning).toMatch(/no TI signal/);
    expect(rec.reasoning).toMatch(/looks bad/); // preserves AI's original reasoning
  });

  it('No TI signal + AI block at ≥85 conf: AI flies solo', async () => {
    lookupIPMock.mockResolvedValueOnce(null);
    aiIsAvailableMock.mockReturnValue(true);
    aiChatMock.mockResolvedValueOnce(aiResponse('block_permanent', 92));

    const rec = await AIBlockAdvisor.getRecommendation(baseCtx, baseEvent);

    expect(rec.action).toBe('block_permanent');
    expect(rec.source).toBe('ai_only');
    expect(rec.confidence).toBe(92);
  });

  it('TI clean (<30) + AI suggests monitor: passes through as ai_only', async () => {
    lookupIPMock.mockResolvedValueOnce({ score: 10, source: 'abuseipdb' });
    aiIsAvailableMock.mockReturnValue(true);
    aiChatMock.mockResolvedValueOnce(aiResponse('monitor', 70));

    const rec = await AIBlockAdvisor.getRecommendation(baseCtx, baseEvent);

    expect(rec.action).toBe('monitor');
    expect(rec.source).toBe('ai_only');
    expect(rec.tiScore).toBe(10);
  });

  it('AI unavailable: falls back to rule-based block_permanent', async () => {
    lookupIPMock.mockResolvedValueOnce(null);
    aiIsAvailableMock.mockReturnValue(false);

    const rec = await AIBlockAdvisor.getRecommendation(baseCtx, baseEvent);

    expect(rec.action).toBe('block_permanent');
    expect(rec.source).toBe('ai_unavailable');
    expect(aiChatMock).not.toHaveBeenCalled();
  });

  it('AI returns malformed JSON: errors as ai_error with fallback block', async () => {
    lookupIPMock.mockResolvedValueOnce(null);
    aiIsAvailableMock.mockReturnValue(true);
    aiChatMock.mockResolvedValueOnce({ text: 'not json at all' });

    const rec = await AIBlockAdvisor.getRecommendation(baseCtx, baseEvent);

    expect(rec.source).toBe('ai_error');
    expect(rec.action).toBe('block_permanent');
  });

  it('AI returns empty: errors as ai_empty with fallback block', async () => {
    lookupIPMock.mockResolvedValueOnce(null);
    aiIsAvailableMock.mockReturnValue(true);
    aiChatMock.mockResolvedValueOnce(null);

    const rec = await AIBlockAdvisor.getRecommendation(baseCtx, baseEvent);

    expect(rec.source).toBe('ai_empty');
    expect(rec.action).toBe('block_permanent');
  });

  it('AI throws: caught and reported as ai_error (never bubbles up)', async () => {
    lookupIPMock.mockResolvedValueOnce(null);
    aiIsAvailableMock.mockReturnValue(true);
    aiChatMock.mockRejectedValueOnce(new Error('upstream timeout'));

    const rec = await AIBlockAdvisor.getRecommendation(baseCtx, baseEvent);

    expect(rec.source).toBe('ai_error');
    expect(rec.action).toBe('block_permanent');
  });

  it('TI lookup fails: proceeds without TI signal (no crash)', async () => {
    lookupIPMock.mockRejectedValueOnce(new Error('TI provider down'));
    aiIsAvailableMock.mockReturnValue(true);
    aiChatMock.mockResolvedValueOnce(aiResponse('block_permanent', 90));

    const rec = await AIBlockAdvisor.getRecommendation(baseCtx, baseEvent);

    // No TI score → solo gate applies (≥85 needed). 90 passes.
    expect(rec.action).toBe('block_permanent');
    expect(rec.source).toBe('ai_only');
    expect(rec.tiScore).toBeUndefined();
  });

  it('clamps AI confidence into 0-100 range (defensive against bad model output)', async () => {
    lookupIPMock.mockResolvedValueOnce({ score: 50, source: 'abuseipdb' });
    aiIsAvailableMock.mockReturnValue(true);
    aiChatMock.mockResolvedValueOnce({
      text: JSON.stringify({ action: 'block_permanent', confidence: 250, reasoning: 'r' }),
    });

    const rec = await AIBlockAdvisor.getRecommendation(baseCtx, baseEvent);
    expect(rec.confidence).toBe(100); // clamped
  });

  it('coerces unknown AI action to block_permanent (fail-secure)', async () => {
    lookupIPMock.mockResolvedValueOnce({ score: 50, source: 'abuseipdb' });
    aiIsAvailableMock.mockReturnValue(true);
    aiChatMock.mockResolvedValueOnce({
      text: JSON.stringify({ action: 'nuke_from_orbit', confidence: 90, reasoning: 'oops' }),
    });

    const rec = await AIBlockAdvisor.getRecommendation(baseCtx, baseEvent);
    expect(rec.action).toBe('block_permanent');
  });
});

describe('AIBlockAdvisor.logTiHint', () => {
  it('does not throw when ip is missing', async () => {
    await expect(AIBlockAdvisor.logTiHint({ ...baseCtx, sourceIp: undefined }, { eventType: 'x' })).resolves.toBeUndefined();
    expect(lookupIPMock).not.toHaveBeenCalled();
  });

  it('queries TI when ip is present and silently returns when score is high', async () => {
    lookupIPMock.mockResolvedValueOnce({ score: 80, source: 'abuseipdb' });
    await AIBlockAdvisor.logTiHint(baseCtx, { eventType: 'ssh_brute_force', sourceIp: baseCtx.sourceIp });
    expect(lookupIPMock).toHaveBeenCalledWith(baseCtx.sourceIp);
  });

  it('does not throw when TI returns null', async () => {
    lookupIPMock.mockResolvedValueOnce(null);
    await expect(AIBlockAdvisor.logTiHint(baseCtx, { eventType: 'ssh_brute_force', sourceIp: baseCtx.sourceIp })).resolves.toBeUndefined();
  });
});
