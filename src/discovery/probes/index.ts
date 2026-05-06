import type { Executor } from '../executor.js';
import type { ServerSnapshot } from '../types.js';
import { probeNetwork } from './network.js';
import { probeProxy } from './proxy.js';
import { probeDocker } from './docker.js';
import { probeSecurity } from './security.js';
import { probeSystem } from './system.js';

const TOTAL_TIMEOUT_MS = 120_000;

export async function runAllProbes(
  exec: Executor,
  target: { host: string; port: number; user: string },
  transport: 'local' | 'ssh',
): Promise<ServerSnapshot> {
  const start = Date.now();

  const timeout = new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error('Total scan timeout')), TOTAL_TIMEOUT_MS)
  );

  const probes = Promise.all([
    probeNetwork(exec),
    probeProxy(exec),
    probeDocker(exec),
    probeSecurity(exec),
    probeSystem(exec),
  ]);

  const results = await Promise.race([probes, timeout]);

  return {
    timestamp: new Date().toISOString(),
    scanDurationMs: Date.now() - start,
    transport,
    target,
    probes: {
      network: results[0],
      proxy: results[1],
      docker: results[2],
      security: results[3],
      system: results[4],
    },
  };
}
