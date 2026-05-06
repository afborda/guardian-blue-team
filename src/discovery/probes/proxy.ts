import type { Executor } from '../executor.js';
import type { ProbeResult, ProxyData } from '../types.js';

export async function probeProxy(exec: Executor): Promise<ProbeResult<ProxyData>> {
  const start = Date.now();
  try {
    const [traefikResult, nginxResult, caddyResult, haproxyResult, certsResult] = await Promise.all([
      detectTraefik(exec),
      detectNginx(exec),
      detectCaddy(exec),
      detectHAProxy(exec),
      detectCerts(exec),
    ]);

    const detected = traefikResult.found ? 'traefik'
      : nginxResult.found ? 'nginx'
      : caddyResult.found ? 'caddy'
      : haproxyResult.found ? 'haproxy'
      : 'none';

    const version = traefikResult.version ?? nginxResult.version ?? caddyResult.version ?? haproxyResult.version ?? null;
    const config = nginxResult.config ?? caddyResult.config ?? haproxyResult.config ?? null;
    const domains = [...new Set([...traefikResult.domains, ...nginxResult.domains, ...caddyResult.domains])];

    return {
      name: 'proxy',
      success: true,
      data: { detected, version, config, domains, sslCerts: certsResult, traefikLabels: traefikResult.labels },
      durationMs: Date.now() - start,
    };
  } catch (error) {
    return {
      name: 'proxy',
      success: false,
      data: { detected: 'none', version: null, config: null, domains: [], sslCerts: [], traefikLabels: [] },
      error: String(error),
      durationMs: Date.now() - start,
    };
  }
}

interface ProxyDetection {
  found: boolean;
  version: string | null;
  config: string | null;
  domains: string[];
  labels: Record<string, string>[];
}

async function detectTraefik(exec: Executor): Promise<ProxyDetection> {
  const result = await exec.run(
    'docker ps --format "{{.Names}}|{{.Image}}|{{.Labels}}" 2>/dev/null | grep -i traefik'
  );
  if (!result.success || !result.stdout.trim()) {
    return { found: false, version: null, config: null, domains: [], labels: [] };
  }

  const versionResult = await exec.run(
    'docker exec $(docker ps -q --filter "ancestor=traefik" | head -1) traefik version 2>/dev/null | head -1'
  );
  const version = versionResult.stdout.match(/Version:\s*(\S+)/)?.[1] ?? null;

  const domains: string[] = [];
  const labels: Record<string, string>[] = [];
  const containerLabelsResult = await exec.run(
    'docker ps --format "{{.Labels}}" 2>/dev/null'
  );

  for (const line of containerLabelsResult.stdout.split('\n')) {
    const hostMatch = line.match(/traefik\.http\.routers\.\w+\.rule=Host\(`([^`]+)`\)/);
    if (hostMatch) domains.push(hostMatch[1]);
  }

  return { found: true, version, config: null, domains, labels };
}

async function detectNginx(exec: Executor): Promise<ProxyDetection> {
  const testResult = await exec.run('nginx -v 2>&1');
  if (!testResult.success && !testResult.stdout.includes('nginx')) {
    const dockerNginx = await exec.run('docker ps --format "{{.Image}}" 2>/dev/null | grep nginx');
    if (!dockerNginx.stdout.trim()) {
      return { found: false, version: null, config: null, domains: [], labels: [] };
    }
  }

  const version = testResult.stdout.match(/nginx\/([\d.]+)/)?.[1] ?? null;
  const configResult = await exec.run(
    'cat /etc/nginx/sites-enabled/* 2>/dev/null || cat /etc/nginx/conf.d/*.conf 2>/dev/null'
  );
  const domains = [...configResult.stdout.matchAll(/server_name\s+([^;]+)/g)]
    .flatMap(m => m[1].split(/\s+/).filter(d => d !== '_' && d.includes('.')));

  return { found: true, version, config: configResult.stdout.slice(0, 2000), domains, labels: [] };
}

async function detectCaddy(exec: Executor): Promise<ProxyDetection> {
  const result = await exec.run('caddy version 2>&1');
  if (!result.success || !result.stdout.includes('v')) {
    return { found: false, version: null, config: null, domains: [], labels: [] };
  }

  const version = result.stdout.match(/v([\d.]+)/)?.[1] ?? null;
  const configResult = await exec.run('cat /etc/caddy/Caddyfile 2>/dev/null || cat ~/Caddyfile 2>/dev/null');
  const domains = [...configResult.stdout.matchAll(/^([\w.-]+\.[\w]+)\s*\{/gm)].map(m => m[1]);

  return { found: true, version, config: configResult.stdout.slice(0, 2000), domains, labels: [] };
}

async function detectHAProxy(exec: Executor): Promise<ProxyDetection> {
  const result = await exec.run('haproxy -v 2>&1');
  if (!result.success || !result.stdout.includes('HAProxy')) {
    return { found: false, version: null, config: null, domains: [], labels: [] };
  }

  const version = result.stdout.match(/version\s+([\d.]+)/)?.[1] ?? null;
  const configResult = await exec.run('cat /etc/haproxy/haproxy.cfg 2>/dev/null');

  return { found: true, version, config: configResult.stdout.slice(0, 2000), domains: [], labels: [] };
}

async function detectCerts(exec: Executor): Promise<ProxyData['sslCerts']> {
  const result = await exec.run(
    'find /etc/letsencrypt/live -name "cert.pem" 2>/dev/null | head -10'
  );
  if (!result.stdout.trim()) return [];

  const certs: ProxyData['sslCerts'] = [];
  for (const certPath of result.stdout.trim().split('\n')) {
    const domain = certPath.match(/live\/([^/]+)/)?.[1] ?? 'unknown';
    const expiryResult = await exec.run(
      `openssl x509 -enddate -noout -in "${certPath}" 2>/dev/null`
    );
    const expiresAt = expiryResult.stdout.match(/notAfter=(.+)/)?.[1] ?? null;
    certs.push({ domain, expiresAt });
  }
  return certs;
}
