FROM node:22-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

FROM node:22-alpine

RUN apk add --no-cache curl docker-cli openssh-client

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev --ignore-scripts
COPY --from=builder /app/dist ./dist/

RUN mkdir -p /home/node/.ssh && chown -R node:node /home/node/.ssh

USER node
EXPOSE 3334

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:3334/health || exit 1

CMD ["node", "dist/index.js"]
