import { describe, expect, it } from 'vitest';
import { shouldAutoEnforceIncident } from '../src/services/incident-policy.js';

describe('incident auto-enforce policy', () => {
  it('never auto-blocks the destination of an egress incident', () => {
    expect(shouldAutoEnforceIncident('egress')).toBe(false);
  });

  it('keeps auto-block for inbound attack categories', () => {
    expect(shouldAutoEnforceIncident('brute_force')).toBe(true);
    expect(shouldAutoEnforceIncident('port_scan')).toBe(true);
    expect(shouldAutoEnforceIncident('ddos')).toBe(true);
    expect(shouldAutoEnforceIncident(undefined)).toBe(true);
  });
});
