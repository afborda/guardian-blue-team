import type { Executor } from '../executor.js';
import type { ProbeResult, DockerData } from '../types.js';

export async function probeDocker(exec: Executor): Promise<ProbeResult<DockerData>> {
  const start = Date.now();
  try {
    const versionResult = await exec.run('docker version --format "{{.Server.Version}}" 2>/dev/null');
    const podmanResult = !versionResult.success
      ? await exec.run('podman version --format "{{.Version}}" 2>/dev/null')
      : { stdout: '', success: false };

    const installed = versionResult.success || podmanResult.success;
    const runtime: DockerData['runtime'] = versionResult.success ? 'docker' : podmanResult.success ? 'podman' : null;
    const version = versionResult.stdout.trim() || podmanResult.stdout.trim() || null;

    if (!installed) {
      return {
        name: 'docker',
        success: true,
        data: { installed: false, runtime: null, version: null, containers: [], networks: [], volumes: [], composeFiles: [] },
        durationMs: Date.now() - start,
      };
    }

    const cmd = runtime === 'podman' ? 'podman' : 'docker';
    const [containersResult, networksResult, volumesResult, composeResult] = await Promise.all([
      exec.run(`${cmd} ps --format '{{.Names}}|{{.Image}}|{{.State}}|{{.Ports}}' 2>/dev/null`),
      exec.run(`${cmd} network ls --format '{{.Name}}' 2>/dev/null`),
      exec.run(`${cmd} volume ls --format '{{.Name}}' 2>/dev/null`),
      exec.run('find / -maxdepth 4 -name "docker-compose.yml" -o -name "docker-compose.yaml" -o -name "compose.yml" -o -name "compose.yaml" 2>/dev/null | head -20'),
    ]);

    const containers = containersResult.stdout.trim().split('\n').filter(Boolean).map(line => {
      const [name, image, state, ports] = line.split('|');
      return { name: name || '', image: image || '', state: state || '', ports: ports || '' };
    });

    const networks = networksResult.stdout.trim().split('\n').filter(Boolean);
    const volumes = volumesResult.stdout.trim().split('\n').filter(Boolean);
    const composeFiles = composeResult.stdout.trim().split('\n').filter(Boolean);

    return {
      name: 'docker',
      success: true,
      data: { installed, runtime, version, containers, networks, volumes, composeFiles },
      durationMs: Date.now() - start,
    };
  } catch (error) {
    return {
      name: 'docker',
      success: false,
      data: { installed: false, runtime: null, version: null, containers: [], networks: [], volumes: [], composeFiles: [] },
      error: String(error),
      durationMs: Date.now() - start,
    };
  }
}
