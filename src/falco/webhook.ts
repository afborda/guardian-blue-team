/**
 * Falco webhook receiver.
 *
 * Falco's `http_output` POSTs one JSON payload per alert. We validate the
 * shared token (constant-time), resolve the host name to a serverId, map
 * rule → NormalizedEvent, then re-use the existing pipeline:
 *
 *     correlate → persist → triggerPlaybooks
 *
 * That last step is what makes Falco "feel" like the rest of Guardian: a
 * `Mining cryptocurrency` alert flows straight into `crypto-mining-response`
 * (kill → block → notify) without any new playbook code.
 *
 * Failure modes:
 *   - 503 if FALCO_WEBHOOK_TOKEN is unset (fail-closed: don't accept
 *     un-authenticated runtime alerts)
 *   - 401 token mismatch
 *   - 404 X-Guardian-Host doesn't map to a registered server
 *   - 400 malformed payload (missing rule/priority/output)
 *   - 204 success (Falco ignores response body, only cares about status)
 */
import type { Request, Response } from 'express';
import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';
import { safeCompare } from '../utils/sanitize.js';
import { ServerService } from '../services/server.service.js';
import { EventCorrelator } from '../pipeline/correlator.js';
import { EventIngestor } from '../pipeline/ingestor.js';
import { EventCollectorWorker } from '../workers/event-collector.worker.js';
import { FalcoMapper, type FalcoEvent } from './mapper.js';

function isValidPayload(body: unknown): body is FalcoEvent {
  if (!body || typeof body !== 'object') return false;
  const b = body as Record<string, unknown>;
  return (
    typeof b.rule === 'string' &&
    typeof b.priority === 'string' &&
    typeof b.output === 'string'
  );
}

export async function falcoWebhookHandler(req: Request, res: Response): Promise<void> {
  const expected = config.falco.webhookToken;
  if (!expected) {
    res.status(503).json({ error: 'Falco webhook disabled' });
    return;
  }

  const presented = req.headers['x-falco-token'];
  if (typeof presented !== 'string' || !safeCompare(presented, expected)) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }

  const hostHeader = req.headers['x-guardian-host'];
  if (typeof hostHeader !== 'string' || hostHeader.length === 0) {
    res.status(400).json({ error: 'missing X-Guardian-Host header' });
    return;
  }

  const server = await ServerService.getByName(hostHeader);
  if (!server) {
    logger.warn({ host: hostHeader }, 'Falco event from unknown host');
    res.status(404).json({ error: 'unknown host' });
    return;
  }

  if (!isValidPayload(req.body)) {
    res.status(400).json({ error: 'invalid payload' });
    return;
  }

  try {
    const normalized = FalcoMapper.toNormalizedEvent(req.body, server.id);
    const correlated = await EventCorrelator.correlate([normalized]);
    await EventIngestor.persist(correlated);
    await EventCollectorWorker.triggerPlaybooks(correlated);

    logger.info({
      host: hostHeader,
      rule: req.body.rule,
      eventType: normalized.eventType,
      severity: normalized.severity,
    }, 'Falco event ingested');

    res.status(204).end();
  } catch (err) {
    logger.error({ err, host: hostHeader, rule: req.body.rule }, 'Falco webhook handler failed');
    res.status(500).json({ error: 'internal error' });
  }
}
