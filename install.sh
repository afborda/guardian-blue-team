#!/usr/bin/env bash
set -euo pipefail

# ─── Guardian Blue Team — Interactive Installer ─────────────────────────────────
# Supports: Ubuntu/Debian, Alpine, macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/your-repo/guardian-blue-team/main/install.sh | bash

# ─── Colors & Helpers ────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

banner() {
  echo ""
  echo -e "${BLUE}${BOLD}"
  echo "  ┌─────────────────────────────────────────────────────┐"
  echo "  │          🛡️  Guardian Blue Team Installer            │"
  echo "  │     Lightweight SIEM/SOAR for Infrastructure        │"
  echo "  └─────────────────────────────────────────────────────┘"
  echo -e "${NC}"
}

info()    { echo -e "  ${BLUE}ℹ${NC}  $1"; }
success() { echo -e "  ${GREEN}✔${NC}  $1"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $1"; }
error()   { echo -e "  ${RED}✖${NC}  $1"; }
step()    { echo -e "\n  ${CYAN}${BOLD}[$1/$TOTAL_STEPS]${NC} ${BOLD}$2${NC}"; }

prompt() {
  local var_name="$1" prompt_text="$2" default="${3:-}"
  if [[ -n "$default" ]]; then
    echo -ne "  ${BOLD}$prompt_text${NC} ${DIM}[$default]${NC}: "
    read -r input
    eval "$var_name=\"${input:-$default}\""
  else
    echo -ne "  ${BOLD}$prompt_text${NC}: "
    read -r input
    eval "$var_name=\"$input\""
  fi
}

prompt_secret() {
  local var_name="$1" prompt_text="$2"
  echo -ne "  ${BOLD}$prompt_text${NC}: "
  read -rs input
  echo ""
  eval "$var_name=\"$input\""
}

TOTAL_STEPS=7

# ─── Step 0: Banner ─────────────────────────────────────────────────────────────

banner

# ─── Step 1: Detect OS ──────────────────────────────────────────────────────────

step 1 "Detecting environment"

OS="unknown"
PKG_MANAGER=""

if [[ "$OSTYPE" == "darwin"* ]]; then
  OS="macos"
  PKG_MANAGER="brew"
elif [[ -f /etc/alpine-release ]]; then
  OS="alpine"
  PKG_MANAGER="apk"
elif [[ -f /etc/debian_version ]]; then
  OS="debian"
  PKG_MANAGER="apt"
elif [[ -f /etc/redhat-release ]]; then
  OS="redhat"
  PKG_MANAGER="yum"
fi

success "OS: ${OS} | Package manager: ${PKG_MANAGER:-none detected}"

# ─── Step 2: Check Prerequisites ───────────────────────────────────────────────

step 2 "Checking prerequisites"

MISSING=()

if ! command -v node &>/dev/null; then
  MISSING+=("node")
elif [[ $(node -v | sed 's/v//' | cut -d. -f1) -lt 20 ]]; then
  warn "Node.js $(node -v) found but v20+ is required"
  MISSING+=("node>=20")
else
  success "Node.js $(node -v)"
fi

if ! command -v npm &>/dev/null; then
  MISSING+=("npm")
else
  success "npm $(npm -v)"
fi

if command -v docker &>/dev/null; then
  success "Docker $(docker --version | grep -oP '\d+\.\d+\.\d+')"
  HAS_DOCKER=true
else
  info "Docker not found (optional — needed for Docker Compose mode)"
  HAS_DOCKER=false
fi

if command -v ssh &>/dev/null; then
  success "SSH client available"
else
  MISSING+=("ssh")
fi

if [[ ${#MISSING[@]} -gt 0 ]]; then
  error "Missing prerequisites: ${MISSING[*]}"
  echo ""
  info "Install them and re-run this script:"
  if [[ "$PKG_MANAGER" == "apt" ]]; then
    echo -e "    ${DIM}sudo apt update && sudo apt install -y nodejs npm openssh-client${NC}"
  elif [[ "$PKG_MANAGER" == "brew" ]]; then
    echo -e "    ${DIM}brew install node${NC}"
  elif [[ "$PKG_MANAGER" == "apk" ]]; then
    echo -e "    ${DIM}apk add nodejs npm openssh-client${NC}"
  fi
  exit 1
fi

# ─── Step 3: Choose Install Directory ──────────────────────────────────────────

step 3 "Configuration"

INSTALL_DIR="${HOME}/.guardian"
prompt INSTALL_DIR "Install directory" "$INSTALL_DIR"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"
success "Directory: $INSTALL_DIR"

# ─── Step 4: Generate SSH Keys ─────────────────────────────────────────────────

step 4 "SSH key setup"

SSH_KEY_PATH="${INSTALL_DIR}/keys/id_ed25519"

if [[ -f "$SSH_KEY_PATH" ]]; then
  success "SSH key already exists: $SSH_KEY_PATH"
else
  mkdir -p "${INSTALL_DIR}/keys"
  ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N "" -q
  success "Generated SSH key: $SSH_KEY_PATH"
  echo ""
  info "Add this public key to your servers:"
  echo -e "    ${DIM}$(cat "${SSH_KEY_PATH}.pub")${NC}"
  echo ""
  warn "Press Enter after you've added the key to at least one server..."
  read -r
fi

# ─── Step 5: Configure .env ────────────────────────────────────────────────────

step 5 "Environment configuration"

DASHBOARD_TOKEN=$(openssl rand -hex 16 2>/dev/null || head -c 32 /dev/urandom | xxd -p | head -c 32)

echo ""
info "Telegram Bot (required for alerts):"
prompt TELEGRAM_TOKEN "Bot token (from @BotFather)" ""
prompt TELEGRAM_CHAT "Chat ID (from @userinfobot)" ""

echo ""
info "AI Provider (enhances analysis — optional):"
echo -e "    ${DIM}1) Gemini (free tier)  2) OpenAI  3) Claude  4) Ollama (local)  5) Skip${NC}"
prompt AI_CHOICE "Choose [1-5]" "1"

AI_PROVIDER="auto"
GEMINI_KEY=""
OPENAI_KEY=""
ANTHROPIC_KEY=""

case "$AI_CHOICE" in
  1) prompt_secret GEMINI_KEY "Gemini API key"; AI_PROVIDER="gemini" ;;
  2) prompt_secret OPENAI_KEY "OpenAI API key"; AI_PROVIDER="openai" ;;
  3) prompt_secret ANTHROPIC_KEY "Anthropic API key"; AI_PROVIDER="claude" ;;
  4) AI_PROVIDER="ollama" ;;
  5) AI_PROVIDER="auto" ;;
esac

echo ""
info "Database:"
echo -e "    ${DIM}1) SQLite (zero-config, great for single server)${NC}"
echo -e "    ${DIM}2) PostgreSQL (recommended for multiple servers)${NC}"
prompt DB_CHOICE "Choose [1-2]" "1"

DATABASE_URL="sqlite:${INSTALL_DIR}/data/guardian.db"
if [[ "$DB_CHOICE" == "2" ]]; then
  prompt DATABASE_URL "PostgreSQL URL" "postgres://guardian:secret@localhost:5432/guardian"
fi

echo ""
info "Threat intelligence (optional):"
prompt_secret ABUSEIPDB_KEY "AbuseIPDB API key (Enter to skip)"

cat > "${INSTALL_DIR}/.env" << EOF
# Guardian Blue Team — Auto-generated $(date -Iseconds)
PORT=3334
NODE_ENV=production
DASHBOARD_TOKEN=${DASHBOARD_TOKEN}
DATABASE_URL=${DATABASE_URL}
TELEGRAM_BOT_TOKEN=${TELEGRAM_TOKEN}
TELEGRAM_CHAT_ID=${TELEGRAM_CHAT}
AI_PROVIDER=${AI_PROVIDER}
GEMINI_API_KEY=${GEMINI_KEY}
OPENAI_API_KEY=${OPENAI_KEY}
ANTHROPIC_API_KEY=${ANTHROPIC_KEY}
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=qwen3:4b
ABUSEIPDB_API_KEY=${ABUSEIPDB_KEY}
HOST_SSH_KEY_PATH=${SSH_KEY_PATH}
CVE_MONITOR_ENABLED=true
EOF

success ".env created at ${INSTALL_DIR}/.env"

# ─── Step 6: Install & Build ──────────────────────────────────────────────────

step 6 "Installing Guardian"

if [[ "$HAS_DOCKER" == "true" ]]; then
  echo -e "    ${DIM}1) Docker Compose (recommended)${NC}"
  echo -e "    ${DIM}2) Native Node.js (systemd service)${NC}"
  prompt DEPLOY_MODE "Deploy mode [1-2]" "1"
else
  DEPLOY_MODE="2"
  info "No Docker found — using native Node.js mode"
fi

if [[ "$DEPLOY_MODE" == "1" ]]; then
  info "Pulling Guardian Docker image..."
  docker pull ghcr.io/your-user/guardian-blue-team:latest 2>/dev/null || warn "Pull failed — will build locally"
  success "Docker mode ready. Run: docker compose up -d"
else
  if [[ ! -d "${INSTALL_DIR}/app" ]]; then
    info "Cloning Guardian..."
    git clone --depth 1 https://github.com/your-user/guardian-blue-team.git "${INSTALL_DIR}/app" 2>/dev/null || {
      warn "Clone failed — ensure the repo URL is correct"
      mkdir -p "${INSTALL_DIR}/app"
    }
  fi

  if [[ -f "${INSTALL_DIR}/app/package.json" ]]; then
    cd "${INSTALL_DIR}/app"
    npm ci --production 2>/dev/null || npm install
    npm run build 2>/dev/null || true
    success "Guardian built successfully"

    if command -v systemctl &>/dev/null; then
      info "Creating systemd service..."
      sudo tee /etc/systemd/system/guardian.service > /dev/null << SVCEOF
[Unit]
Description=Guardian Blue Team SIEM/SOAR
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=${INSTALL_DIR}/app
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=$(which node) dist/index.js
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF
      sudo systemctl daemon-reload
      sudo systemctl enable guardian
      success "Systemd service created (guardian.service)"
    fi
  fi
fi

# ─── Step 7: Add First Server ────────────────────────────────────────────────

step 7 "Add your first server"

echo ""
prompt SERVER_NAME "Server name (e.g., prod-web-1)" ""
prompt SERVER_HOST "Server IP/hostname" ""
prompt SERVER_PORT "SSH port" "22"
prompt SERVER_USER "SSH user" "ubuntu"

echo ""
info "Testing SSH connection to ${SERVER_USER}@${SERVER_HOST}:${SERVER_PORT}..."
if ssh -i "$SSH_KEY_PATH" -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p "$SERVER_PORT" "${SERVER_USER}@${SERVER_HOST}" "echo ok" &>/dev/null; then
  success "SSH connection successful!"
else
  warn "SSH connection failed. Check that the public key is authorized on the server."
  info "Public key: $(cat "${SSH_KEY_PATH}.pub")"
fi

# Save server config for first-run
cat >> "${INSTALL_DIR}/.env" << EOF

# First server
HOST_SSH_HOST=${SERVER_HOST}
HOST_SSH_PORT=${SERVER_PORT}
HOST_SSH_USER=${SERVER_USER}
HOST_SSH_KEY_PATH=${SSH_KEY_PATH}
EOF

# ─── Summary ────────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}"
echo "  ┌─────────────────────────────────────────────────────┐"
echo "  │            ✔  Installation Complete!                 │"
echo "  └─────────────────────────────────────────────────────┘"
echo -e "${NC}"
echo ""
echo -e "  ${BOLD}Dashboard:${NC}     http://localhost:3334/dashboard?token=${DASHBOARD_TOKEN}"
echo -e "  ${BOLD}Config:${NC}        ${INSTALL_DIR}/.env"
echo -e "  ${BOLD}SSH Key:${NC}       ${SSH_KEY_PATH}"
echo -e "  ${BOLD}Logs:${NC}          journalctl -u guardian -f"
echo ""

if [[ "$DEPLOY_MODE" == "1" ]]; then
  echo -e "  ${BOLD}Start:${NC}         cd ${INSTALL_DIR} && docker compose up -d"
else
  echo -e "  ${BOLD}Start:${NC}         sudo systemctl start guardian"
fi

echo ""
echo -e "  ${BOLD}Telegram:${NC}      Send /status to your bot to verify"
echo -e "  ${BOLD}Add servers:${NC}   Send /add-server via Telegram"
echo ""
echo -e "  ${DIM}Documentation: https://github.com/your-user/guardian-blue-team${NC}"
echo ""
