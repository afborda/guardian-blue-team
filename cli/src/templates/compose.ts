export interface ComposeConfig {
  domain: string;
  traefikNetwork: string | null;
  dbPassword: string;
}

export function generateComposeFile(cfg: ComposeConfig): string {
  const traefikLabels = cfg.traefikNetwork ? `
      labels:
        - "traefik.enable=true"
        - "traefik.http.routers.guardian.rule=Host(\`${cfg.domain}\`)"
        - "traefik.http.routers.guardian.entrypoints=websecure"
        - "traefik.http.routers.guardian.tls.certresolver=letsencrypt"
        - "traefik.http.services.guardian.loadbalancer.server.port=3334"` : '';

  const traefikNetworkDef = cfg.traefikNetwork ? `
    ${cfg.traefikNetwork}:
      external: true` : '';

  const traefikNetworks = cfg.traefikNetwork ? `
      - ${cfg.traefikNetwork}` : '';

  return `services:
  guardian:
    image: ghcr.io/afborda/guardian-blue-team:latest
    container_name: guardian
    restart: unless-stopped
    env_file: .env
    ports:
      - "3334:3334"
    volumes:
      - ./data:/data
      - ./data/ssh:/home/node/.ssh:ro
    depends_on:
      guardian-db:
        condition: service_healthy
    networks:
      - guardian-net${traefikNetworks}${traefikLabels}
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:3334/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 15s
    deploy:
      resources:
        limits:
          cpus: "2"
          memory: 512M
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

  guardian-db:
    image: postgres:16-alpine
    container_name: guardian-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: guardian
      POSTGRES_USER: guardian
      POSTGRES_PASSWORD: ${cfg.dbPassword}
    volumes:
      - guardian-pgdata:/var/lib/postgresql/data
    networks:
      - guardian-net
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U guardian"]
      interval: 10s
      timeout: 3s
      retries: 5
    deploy:
      resources:
        limits:
          cpus: "1"
          memory: 256M
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  guardian-pgdata:

networks:
  guardian-net:
    driver: bridge${traefikNetworkDef}
`;
}
