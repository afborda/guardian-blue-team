#!/usr/bin/env bash
# Deploy Guardian to Hetzner
# Usage: ./scripts/deploy.sh [--no-cache]
set -euo pipefail

REMOTE="hetzner"
REMOTE_DIR="/root/guardian"
NO_CACHE="${1:-}"

echo "→ Building locally..."
npm run build

echo "→ Rsyncing to $REMOTE (excluding .env and models)..."
rsync -az --delete \
  --exclude='.git' \
  --exclude='node_modules' \
  --exclude='data' \
  --exclude='models' \
  --exclude='.env' \
  --exclude='.env.local' \
  /Users/I776289/Documents/study/guardian/ \
  "$REMOTE:$REMOTE_DIR/"

echo "→ Building Docker image on server${NO_CACHE:+ (--no-cache)}..."
ssh "$REMOTE" "cd $REMOTE_DIR && docker compose build $NO_CACHE guardian"

echo "→ Deploying..."
ssh "$REMOTE" "cd $REMOTE_DIR && docker compose up -d guardian"

echo "→ Waiting for health check..."
sleep 8
ssh "$REMOTE" "docker logs guardian --tail 5 2>&1"

echo "✓ Deploy complete"
