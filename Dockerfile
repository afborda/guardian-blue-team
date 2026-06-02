FROM node:20-slim AS builder

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci && npm cache clean --force
COPY tsconfig.json tsup.config.ts ./
COPY src/ ./src/
COPY scripts/ ./scripts/
RUN npm run build

FROM node:20-slim

LABEL org.opencontainers.image.source="https://github.com/afborda/guardian-blue-team"
LABEL org.opencontainers.image.description="Lightweight SOAR for the rest of us"
LABEL org.opencontainers.image.licenses="AGPL-3.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-client curl \
      python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Instala dependências Python de ML num venv isolado (não polui o sistema)
RUN python3 -m venv /app/ml-venv && \
    /app/ml-venv/bin/pip install --no-cache-dir \
      scikit-learn skl2onnx onnxruntime numpy requests psycopg2-binary

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=builder /app/dist ./dist/
COPY scripts/ ./scripts/

RUN mkdir -p /data /home/node/.ssh /app/models && \
    chown -R node:node /data /home/node/.ssh /app/models /app/scripts /app/ml-venv
VOLUME /data

USER node
EXPOSE 3334

ENV NODE_ENV=production
ENV ML_PYTHON=/app/ml-venv/bin/python3

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=15s \
  CMD curl -sf http://localhost:3334/health || exit 1

CMD ["node", "dist/index.js"]
