import type { DiscoveryResult, ServerSnapshot } from './types.js';

export function generateFallbackConfig(snapshot: ServerSnapshot): DiscoveryResult {
  const proxy = snapshot.probes.proxy.data;
  const docker = snapshot.probes.docker.data;
  const network = snapshot.probes.network.data;
  const security = snapshot.probes.security.data;
  const system = snapshot.probes.system.data;

  const architecture = detectArchitecture(proxy, docker);
  const sshPort = security.sshConfig.port || network.sshPort || 22;

  const env: Record<string, string> = {
    PORT: '3334',
    NODE_ENV: 'production',
    HOST_SSH_HOST: '127.0.0.1',
    HOST_SSH_PORT: String(sshPort),
    HOST_SSH_USER: 'root',
    AI_PROVIDER: 'auto',
    DATABASE_URL: 'postgres://guardian:guardian_secret@guardian-db:5432/guardian',
  };

  let dockerCompose: string | undefined;
  let systemdUnit: string | undefined;

  if (docker.installed) {
    dockerCompose = getDockerComposeTemplate(architecture);
  } else {
    systemdUnit = SYSTEMD_TEMPLATE;
  }

  const warnings: string[] = [];
  if (security.sshConfig.passwordAuth === 'yes') {
    warnings.push('PasswordAuthentication enabled — consider disabling for SSH key-only access');
  }
  if (security.sshConfig.permitRoot === 'yes') {
    warnings.push('PermitRootLogin enabled — consider restricting to prohibit-password or no');
  }
  if (security.firewall.tool === 'none') {
    warnings.push('No firewall detected — strongly recommend enabling ufw or iptables');
  }
  if (!security.fail2ban.active) {
    warnings.push('fail2ban not active — SSH brute-force protection missing');
  }

  const recommendations: string[] = [];
  if (!security.fail2ban.active) recommendations.push('Install and enable fail2ban for SSH protection');
  if (security.firewall.tool === 'none') recommendations.push('Enable ufw: ufw default deny incoming && ufw allow ssh && ufw enable');

  return {
    summary: `${system.os.name} with ${architecture} architecture. SSH on port ${sshPort}.`,
    architecture,
    confidence: 60,
    env,
    dockerCompose,
    systemdUnit,
    warnings,
    recommendations,
    monitoringProfile: {
      services: docker.containers.map(c => c.name).slice(0, 10),
      logPaths: ['/var/log/auth.log', '/var/log/syslog'],
      criticalPorts: network.listeningPorts.filter(p => p.port < 10000).map(p => p.port),
      customChecks: [],
    },
  };
}

function detectArchitecture(proxy: { detected: string }, docker: { installed: boolean }): DiscoveryResult['architecture'] {
  if (proxy.detected === 'traefik' && docker.installed) return 'traefik-docker';
  if (proxy.detected === 'nginx' && docker.installed) return 'nginx-docker';
  if (proxy.detected === 'nginx') return 'nginx-standalone';
  if (proxy.detected === 'caddy') return 'caddy';
  if (proxy.detected === 'haproxy') return 'haproxy';
  if (docker.installed) return 'traefik-docker';
  return 'bare-metal';
}

function getDockerComposeTemplate(arch: string): string {
  if (arch === 'traefik-docker') return TRAEFIK_COMPOSE;
  if (arch.includes('nginx')) return NGINX_COMPOSE;
  return BARE_COMPOSE;
}

const TRAEFIK_COMPOSE = `services:
  guardian:
    build: .
    container_name: guardian
    restart: unless-stopped
    env_file: .env
    depends_on:
      guardian-db:
        condition: service_healthy
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - \${SSH_KEY_DIR:-~/.ssh}:/home/node/.ssh:ro
    networks:
      - guardian-internal
      - traefik-public
    labels:
      - "traefik.enable=true"
      - "traefik.docker.network=traefik-public"
      - "traefik.http.routers.guardian.rule=Host(\\\`\${GUARDIAN_DOMAIN:-guardian.localhost}\\\`)"
      - "traefik.http.routers.guardian.entrypoints=websecure"
      - "traefik.http.routers.guardian.tls.certresolver=letsencrypt"
      - "traefik.http.services.guardian.loadbalancer.server.port=3334"

  guardian-db:
    image: postgres:16-alpine
    container_name: guardian-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: guardian
      POSTGRES_USER: guardian
      POSTGRES_PASSWORD: \${GUARDIAN_DB_PASSWORD:-guardian_secret}
    volumes:
      - guardian_pgdata:/var/lib/postgresql/data
    networks:
      - guardian-internal
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U guardian -d guardian"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s

volumes:
  guardian_pgdata:

networks:
  guardian-internal:
    driver: bridge
  traefik-public:
    external: true
`;

const NGINX_COMPOSE = `services:
  guardian:
    build: .
    container_name: guardian
    restart: unless-stopped
    env_file: .env
    depends_on:
      guardian-db:
        condition: service_healthy
    ports:
      - "127.0.0.1:3334:3334"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - \${SSH_KEY_DIR:-~/.ssh}:/home/node/.ssh:ro
    networks:
      - guardian-internal

  guardian-db:
    image: postgres:16-alpine
    container_name: guardian-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: guardian
      POSTGRES_USER: guardian
      POSTGRES_PASSWORD: \${GUARDIAN_DB_PASSWORD:-guardian_secret}
    volumes:
      - guardian_pgdata:/var/lib/postgresql/data
    networks:
      - guardian-internal
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U guardian -d guardian"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s

volumes:
  guardian_pgdata:

networks:
  guardian-internal:
    driver: bridge
`;

const BARE_COMPOSE = `services:
  guardian:
    build: .
    container_name: guardian
    restart: unless-stopped
    env_file: .env
    depends_on:
      guardian-db:
        condition: service_healthy
    ports:
      - "3334:3334"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - \${SSH_KEY_DIR:-~/.ssh}:/home/node/.ssh:ro
    networks:
      - guardian-internal

  guardian-db:
    image: postgres:16-alpine
    container_name: guardian-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: guardian
      POSTGRES_USER: guardian
      POSTGRES_PASSWORD: \${GUARDIAN_DB_PASSWORD:-guardian_secret}
    volumes:
      - guardian_pgdata:/var/lib/postgresql/data
    networks:
      - guardian-internal
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U guardian -d guardian"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s

volumes:
  guardian_pgdata:

networks:
  guardian-internal:
    driver: bridge
`;

const SYSTEMD_TEMPLATE = `[Unit]
Description=Guardian Blue Team SIEM
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=guardian
WorkingDirectory=/opt/guardian
ExecStart=/usr/bin/node dist/index.js
Restart=on-failure
RestartSec=10
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
`;
