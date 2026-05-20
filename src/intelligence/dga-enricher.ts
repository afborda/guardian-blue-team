/**
 * Pre-classify DNS query events with DGA model scores before they reach the
 * synchronous detector rules.
 *
 * The detector rules can't `await`, so the classifier output must be attached
 * to events ahead of time. This module is the seam between async ML inference
 * and the synchronous rule pipeline.
 */

import type { NormalizedEvent } from '../pipeline/normalizer.js';
import { DgaClassifier } from './dga-classifier.js';

/**
 * Mutate-in-place: for every dns_query event, attach a dgaScore and dgaSource
 * to its metadata. Non-DNS events are left untouched. Returns the same array
 * for ergonomic chaining.
 */
export async function enrichWithDgaScore(events: NormalizedEvent[]): Promise<NormalizedEvent[]> {
  // Filter once to avoid awaiting on every iteration of the main loop.
  const dnsEvents = events.filter(e => e.eventType === 'dns_query' && e.metadata?.domain);
  if (dnsEvents.length === 0) return events;

  // Run classifier in parallel — ONNX inference releases the loop between
  // tensor ops, so concurrent calls overlap I/O and don't serialize.
  await Promise.all(dnsEvents.map(async event => {
    const domain = event.metadata!.domain as string;
    const result = await DgaClassifier.classify(domain);
    event.metadata = {
      ...event.metadata,
      dgaScore: result.score,
      dgaIsDga: result.isDga,
      dgaSource: result.source,
    };
  }));

  return events;
}
