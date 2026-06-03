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

# ── System deps + Docker CLI + Trivy (cached until apt lists change) ──────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-client curl wget gnupg ca-certificates \
      python3 python3-pip python3-venv \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" \
       > /etc/apt/sources.list.d/docker.list \
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - \
    && echo "deb https://aquasecurity.github.io/trivy-repo/deb bookworm main" \
       > /etc/apt/sources.list.d/trivy.list \
    && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli trivy \
    && rm -rf /var/lib/apt/lists/*

# ── Python ML venv (cached until this RUN line changes) ───────────────────────
RUN python3 -m venv /app/ml-venv && \
    /app/ml-venv/bin/pip install --no-cache-dir \
      scikit-learn skl2onnx onnxruntime numpy requests psycopg2-binary \
      pandas pyarrow

# ── Node prod deps (cached until package.json/lock changes) ───────────────────
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev && npm cache clean --force

# ── App code (invalidates only when src/scripts change — layers above stay) ───
COPY --from=builder /app/dist ./dist/
COPY scripts/ ./scripts/

RUN mkdir -p /data /home/node/.ssh /app/models && \
    groupadd -g 988 docker-host && \
    usermod -aG docker-host node && \
    chown -R node:node /data /home/node/.ssh /app/models /app/scripts /app/ml-venv
VOLUME /data

USER node
EXPOSE 3334

ENV NODE_ENV=production
ENV ML_PYTHON=/app/ml-venv/bin/python3

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=15s \
  CMD curl -sf http://localhost:3334/health || exit 1

CMD ["node", "dist/index.js"]
