FROM node:20-slim AS builder

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci && npm cache clean --force
COPY tsconfig.json tsup.config.ts ./
COPY src/ ./src/
RUN npm run build

FROM node:20-slim

LABEL org.opencontainers.image.source="https://github.com/afborda/guardian-blue-team"
LABEL org.opencontainers.image.description="Lightweight SOAR for the rest of us"
LABEL org.opencontainers.image.licenses="AGPL-3.0"

RUN apt-get update && apt-get install -y --no-install-recommends openssh-client curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=builder /app/dist ./dist/

RUN mkdir -p /data /home/node/.ssh && chown -R node:node /data /home/node/.ssh
VOLUME /data

USER node
EXPOSE 3334

ENV NODE_ENV=production

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=15s \
  CMD curl -sf http://localhost:3334/health || exit 1

CMD ["node", "dist/index.js"]
