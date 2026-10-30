import type { ServerSnapshot } from './types.js';

const PUBLIC_ADDR = new Set(['0.0.0.0', '::', '*', '']);

export interface DiscoveryFingerprint {
  services: string[];
  ports: number[];
  architecture: string;
}

/**
 * Container names and public ports come from the probes, not from the model.
 * The model renames the same host ("sshd apareceu", "guardian-api parou") between runs.
 */
export function fingerprintFromSnapshot(snapshot: ServerSnapshot, architecture: string): DiscoveryFingerprint {
  const docker = snapshot.probes.docker;
  const network = snapshot.probes.network;
  const services = docker.success
    ? [...new Set(docker.data.containers.map((c) => c.name))].sort()
    : [];
  const ports = network.success
    ? [...new Set(
      network.data.listeningPorts
        .filter((p) => p.port > 0 && p.port < 10000 && PUBLIC_ADDR.has(p.address))
        .map((p) => p.port),
    )].sort((a, b) => a - b)
    : [];
  return { services, ports, architecture };
}

/**
 * Old baselines stored the model's service labels. Those names barely overlap
 * real container names, so the first run after this change must save quietly.
 */
export function isLabelMigration(previousServices: string[], nextServices: string[]): boolean {
  if (previousServices.length === 0 || nextServices.length === 0) return false;
  const next = new Set(nextServices);
  const overlap = previousServices.filter((s) => next.has(s)).length;
  return overlap / previousServices.length < 0.5;
}

export function describeDiscoveryChanges(
  previous: { services: string[]; ports: number[] },
  next: { services: string[]; ports: number[] },
): string[] {
  const lines: string[] = [];
  const newPorts = next.ports.filter((p) => !previous.ports.includes(p));
  const closedPorts = previous.ports.filter((p) => !next.ports.includes(p));
  const newContainers = next.services.filter((s) => !previous.services.includes(s));
  const stopped = previous.services.filter((s) => !next.services.includes(s));

  if (newPorts.length > 0) lines.push(`Portas novas abertas para a internet: ${newPorts.join(', ')}`);
  if (closedPorts.length > 0) lines.push(`Portas que fecharam: ${closedPorts.join(', ')}`);
  if (newContainers.length > 0) lines.push(`Containers novos: ${newContainers.join(', ')}`);
  if (stopped.length > 0) lines.push(`Containers que pararam: ${stopped.join(', ')}`);
  return lines;
}
