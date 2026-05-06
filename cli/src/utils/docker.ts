import { execa } from 'execa';

export async function isDockerRunning(): Promise<boolean> {
  try {
    await execa('docker', ['info'], { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

export async function pullImage(image: string): Promise<void> {
  await execa('docker', ['pull', image], { stdio: 'pipe' });
}

export async function composeUp(dir: string): Promise<void> {
  await execa('docker', ['compose', 'up', '-d'], { cwd: dir, stdio: 'pipe' });
}

export async function composeDown(dir: string): Promise<void> {
  await execa('docker', ['compose', 'down', '-v'], { cwd: dir, stdio: 'pipe' });
}

export async function waitForHealthy(containerName: string, timeoutMs = 30_000): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const { stdout } = await execa('docker', ['inspect', '--format', '{{.State.Health.Status}}', containerName]);
      if (stdout.trim() === 'healthy') return true;
    } catch { /* container may not exist yet */ }
    await new Promise(r => setTimeout(r, 2000));
  }
  return false;
}
