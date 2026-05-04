#!/usr/bin/env bash
set -e

INSTALLER_VERSION="1.0.5"

# ─── Guardian Blue Team — Interactive Installer ─────────────────────────────────
# Supports: Ubuntu/Debian, Alpine, macOS
# Usage:
#   bash <(curl -fsSL https://raw.githubusercontent.com/afborda/guardian-blue-team/main/install.sh)
#   OR: curl -fsSL ... -o install.sh && bash install.sh
#
# Flags:
#   --uninstall   Remove Guardian and all data

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
  echo "  │                  v${INSTALLER_VERSION}                             │"
  echo "  └─────────────────────────────────────────────────────┘"
  echo -e "${NC}"
}

info()    { echo -e "  ${BLUE}ℹ${NC}  $1"; }
success() { echo -e "  ${GREEN}✔${NC}  $1"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $1"; }
error()   { echo -e "  ${RED}✖${NC}  $1"; }
step()    { echo -e "\n  ${CYAN}${BOLD}[$1/$TOTAL_STEPS]${NC} ${BOLD}$2${NC}"; }

# Read from /dev/tty so it works even when script is piped via curl
prompt() {
  local var_name="$1" prompt_text="$2" default="${3:-}"
  local input=""
  if [[ -n "$default" ]]; then
    echo -ne "  ${BOLD}$prompt_text${NC} ${DIM}[$default]${NC}: "
    read -r input </dev/tty 2>/dev/null || input=""
    printf -v "$var_name" '%s' "${input:-$default}"
  else
    echo -ne "  ${BOLD}$prompt_text${NC}: "
    read -r input </dev/tty 2>/dev/null || input=""
    printf -v "$var_name" '%s' "$input"
  fi
}

prompt_secret() {
  local var_name="$1" prompt_text="$2"
  local input=""
  echo -ne "  ${BOLD}$prompt_text${NC}: "
  # Try silent read from tty, fall back to visible read
  if read -rs input </dev/tty 2>/dev/null; then
    echo ""
  else
    read -r input 2>/dev/null || input=""
  fi
  printf -v "$var_name" '%s' "$input"
}

prompt_yn() {
  local prompt_text="$1" default="${2:-y}"
  local input=""
  echo -ne "  ${BOLD}$prompt_text${NC} ${DIM}[${default}]${NC}: "
  read -r input </dev/tty 2>/dev/null || input=""
  input="${input:-$default}"
  [[ "$input" =~ ^[Yy] ]]
}

TOTAL_STEPS=7

# ─── Handle --uninstall ────────────────────────────────────────────────────────

if [[ "${1:-}" == "--uninstall" ]]; then
  banner
  echo ""
  INSTALL_DIR="${HOME}/.guardian"
  if [[ ! -d "$INSTALL_DIR" ]]; then
    error "Guardian not found at $INSTALL_DIR — nothing to remove."
    exit 1
  fi

  echo -e "  ${RED}${BOLD}This will remove:${NC}"
  echo -e "    ${RED}•${NC} $INSTALL_DIR (config, keys, data)"
  [[ -f /etc/systemd/system/guardian.service ]] && echo -e "    ${RED}•${NC} systemd service (guardian.service)"
  docker image inspect ghcr.io/afborda/guardian-blue-team:latest &>/dev/null 2>&1 && echo -e "    ${RED}•${NC} Docker image (ghcr.io/afborda/guardian-blue-team)"
  echo ""

  if prompt_yn "Are you sure? (y/N)" "n"; then
    # Stop service
    if systemctl is-active guardian &>/dev/null 2>&1; then
      sudo systemctl stop guardian
      info "Stopped guardian service"
    fi
    if [[ -f /etc/systemd/system/guardian.service ]]; then
      sudo systemctl disable guardian 2>/dev/null || true
      sudo rm -f /etc/systemd/system/guardian.service
      sudo systemctl daemon-reload
      info "Removed systemd service"
    fi
    # Stop docker container
    if docker ps -q --filter name=guardian &>/dev/null 2>&1; then
      docker stop guardian 2>/dev/null || true
      docker rm guardian 2>/dev/null || true
      info "Stopped Docker container"
    fi
    # Remove docker image
    if docker image inspect ghcr.io/afborda/guardian-blue-team:latest &>/dev/null 2>&1; then
      docker rmi ghcr.io/afborda/guardian-blue-team:latest 2>/dev/null || true
      info "Removed Docker image"
    fi
    # Remove install directory
    rm -rf "$INSTALL_DIR"
    success "Guardian completely removed from $INSTALL_DIR"
    echo ""
    info "To reinstall: bash <(curl -fsSL https://raw.githubusercontent.com/afborda/guardian-blue-team/main/install.sh)"
    echo ""
  else
    info "Uninstall cancelled."
  fi
  exit 0
fi

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
WARNINGS=()
HAS_DOCKER=false

# ─── Node.js ────────────────────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  MISSING+=("Node.js (v20+)")
  error "Node.js not found"
else
  NODE_VERSION=$(node -v | sed 's/v//')
  NODE_MAJOR=$(echo "$NODE_VERSION" | cut -d. -f1)
  if [[ $NODE_MAJOR -lt 20 ]]; then
    MISSING+=("Node.js >= 20 (current: v${NODE_VERSION})")
    error "Node.js v${NODE_VERSION} found but v20+ is required"
  else
    success "Node.js v${NODE_VERSION}"
  fi
fi

# ─── npm ────────────────────────────────────────────────────────────────────────
if ! command -v npm &>/dev/null; then
  MISSING+=("npm")
  error "npm not found"
else
  success "npm $(npm -v)"
fi

# ─── Git ────────────────────────────────────────────────────────────────────────
if ! command -v git &>/dev/null; then
  MISSING+=("git")
  error "git not found (needed to clone the repository)"
else
  success "git $(git --version | awk '{print $3}')"
fi

# ─── SSH client ─────────────────────────────────────────────────────────────────
if ! command -v ssh &>/dev/null; then
  MISSING+=("ssh client")
  error "SSH client not found (required for agentless monitoring)"
else
  success "SSH client available"
fi

# ─── ssh-keygen ─────────────────────────────────────────────────────────────────
if ! command -v ssh-keygen &>/dev/null; then
  MISSING+=("ssh-keygen")
  error "ssh-keygen not found (needed for key generation)"
else
  success "ssh-keygen available"
fi

# ─── openssl or /dev/urandom (for token generation) ─────────────────────────────
if command -v openssl &>/dev/null; then
  success "openssl available (token generation)"
elif [[ -r /dev/urandom ]]; then
  success "/dev/urandom readable (token generation)"
else
  WARNINGS+=("Neither openssl nor /dev/urandom available — dashboard token may need manual setting")
  warn "No secure random source found"
fi

# ─── Docker (optional) ──────────────────────────────────────────────────────────
if command -v docker &>/dev/null; then
  DOCKER_VERSION=$(docker --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  if docker info &>/dev/null 2>&1; then
    success "Docker ${DOCKER_VERSION} (daemon running)"
    HAS_DOCKER=true
  else
    warn "Docker ${DOCKER_VERSION} installed but daemon not running"
    info "  Start it with: sudo systemctl start docker"
    HAS_DOCKER=false
  fi
else
  info "Docker not found (optional — needed for Docker Compose mode)"
  HAS_DOCKER=false
fi

# ─── curl or wget (needed for Telegram, threat intel APIs) ──────────────────────
if command -v curl &>/dev/null; then
  success "curl available"
elif command -v wget &>/dev/null; then
  success "wget available"
else
  WARNINGS+=("Neither curl nor wget found — Telegram notifications may fail")
  warn "No HTTP client (curl/wget) found"
fi

# ─── Disk space (minimum 500MB free) ────────────────────────────────────────────
INSTALL_PARENT=$(dirname "${INSTALL_DIR:-$HOME/.guardian}")
if command -v df &>/dev/null; then
  FREE_MB=$(df -m "$INSTALL_PARENT" 2>/dev/null | awk 'NR==2{print $4}')
  if [[ -n "$FREE_MB" && "$FREE_MB" -lt 500 ]]; then
    MISSING+=("Disk space: only ${FREE_MB}MB free (need 500MB+)")
    error "Insufficient disk space: ${FREE_MB}MB free in ${INSTALL_PARENT}"
  elif [[ -n "$FREE_MB" ]]; then
    success "Disk space: ${FREE_MB}MB free"
  fi
fi

# ─── RAM (minimum 256MB available) ──────────────────────────────────────────────
if [[ "$OS" == "macos" ]]; then
  TOTAL_RAM_MB=$(sysctl -n hw.memsize 2>/dev/null | awk '{print int($1/1048576)}')
  if [[ -n "$TOTAL_RAM_MB" && "$TOTAL_RAM_MB" -gt 0 ]]; then
    success "RAM: ${TOTAL_RAM_MB}MB total"
  fi
elif [[ -f /proc/meminfo ]]; then
  AVAIL_RAM_MB=$(grep MemAvailable /proc/meminfo 2>/dev/null | awk '{print int($2/1024)}')
  if [[ -n "$AVAIL_RAM_MB" && "$AVAIL_RAM_MB" -lt 256 ]]; then
    WARNINGS+=("Low RAM: only ${AVAIL_RAM_MB}MB available (Guardian uses ~50MB but Node.js build needs more)")
    warn "Low available RAM: ${AVAIL_RAM_MB}MB (recommended: 512MB+)"
  elif [[ -n "$AVAIL_RAM_MB" ]]; then
    success "RAM: ${AVAIL_RAM_MB}MB available"
  fi
fi

# ─── Write permissions ──────────────────────────────────────────────────────────
INSTALL_PARENT_DIR=$(dirname "${INSTALL_DIR:-$HOME/.guardian}")
if [[ -w "$INSTALL_PARENT_DIR" ]]; then
  success "Write permission: $INSTALL_PARENT_DIR"
else
  MISSING+=("Write permission to ${INSTALL_PARENT_DIR}")
  error "Cannot write to ${INSTALL_PARENT_DIR} — run as a user with write access"
fi

# ─── Network connectivity (check github.com + npm registry) ─────────────────────
if command -v curl &>/dev/null; then
  if curl -sf --max-time 5 "https://registry.npmjs.org/" &>/dev/null; then
    success "Network: npm registry reachable"
  else
    WARNINGS+=("Cannot reach npm registry — install may fail if dependencies aren't cached")
    warn "Cannot reach registry.npmjs.org (offline install may fail)"
  fi
  if curl -sf --max-time 5 "https://github.com" &>/dev/null; then
    success "Network: github.com reachable"
  else
    WARNINGS+=("Cannot reach github.com — git clone will fail")
    warn "Cannot reach github.com"
  fi
elif command -v wget &>/dev/null; then
  if wget -q --timeout=5 --spider "https://registry.npmjs.org/" 2>/dev/null; then
    success "Network: npm registry reachable"
  else
    WARNINGS+=("Cannot reach npm registry")
    warn "Cannot reach registry.npmjs.org"
  fi
fi

# ─── systemd (for native service mode) ──────────────────────────────────────────
if command -v systemctl &>/dev/null; then
  success "systemd available (for service management)"
  HAS_SYSTEMD=true
else
  info "systemd not available (you'll need to manage the process manually)"
  HAS_SYSTEMD=false
fi

# ─── Summary ────────────────────────────────────────────────────────────────────
echo ""

if [[ ${#WARNINGS[@]} -gt 0 ]]; then
  echo -e "  ${YELLOW}${BOLD}Warnings (non-blocking):${NC}"
  for w in "${WARNINGS[@]}"; do
    echo -e "    ${YELLOW}•${NC} $w"
  done
  echo ""
fi

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo -e "  ${RED}${BOLD}Missing requirements:${NC}"
  for m in "${MISSING[@]}"; do
    echo -e "    ${RED}✖${NC} $m"
  done
  echo ""
  echo -e "  ${BOLD}How to fix:${NC}"
  echo ""
  if [[ "$PKG_MANAGER" == "apt" ]]; then
    echo -e "    ${DIM}# Install Node.js 20+ (via NodeSource):${NC}"
    echo -e "    ${DIM}curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -${NC}"
    echo -e "    ${DIM}sudo apt install -y nodejs git openssh-client${NC}"
  elif [[ "$PKG_MANAGER" == "brew" ]]; then
    echo -e "    ${DIM}brew install node git openssh${NC}"
  elif [[ "$PKG_MANAGER" == "apk" ]]; then
    echo -e "    ${DIM}apk add nodejs npm git openssh-client${NC}"
  elif [[ "$PKG_MANAGER" == "yum" ]]; then
    echo -e "    ${DIM}# Install Node.js 20+ (via NodeSource):${NC}"
    echo -e "    ${DIM}curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -${NC}"
    echo -e "    ${DIM}sudo yum install -y nodejs git openssh-clients${NC}"
  else
    echo -e "    ${DIM}Install Node.js 20+, npm, git, and an SSH client for your OS${NC}"
  fi
  echo ""
  error "Fix the issues above and re-run this script."
  exit 1
fi

success "All prerequisites met!"

# ─── Step 3: Choose Install Directory ──────────────────────────────────────────

step 3 "Configuration"

INSTALL_DIR="${HOME}/.guardian"
prompt INSTALL_DIR "Install directory" "$INSTALL_DIR"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"
success "Directory: $INSTALL_DIR"

# ─── Step 4: Generate SSH Keys ─────────────────────────────────────────────────

step 4 "SSH key setup"

mkdir -p "${INSTALL_DIR}/keys"

# Check if any guardian key already exists
SSH_KEY_PATH=""
for f in "${INSTALL_DIR}/keys"/guardian-*_ed25519 "${INSTALL_DIR}/keys/id_ed25519"; do
  if [[ -f "$f" ]]; then
    SSH_KEY_PATH="$f"
    break
  fi
done

if [[ -n "$SSH_KEY_PATH" ]]; then
  success "SSH key already exists: $SSH_KEY_PATH"
else
  # Generate unique key name
  KEY_ID=$(openssl rand -hex 3 2>/dev/null || echo "$RANDOM")
  KEY_ID="${KEY_ID:0:5}"
  SSH_KEY_PATH="${INSTALL_DIR}/keys/guardian-${KEY_ID}_ed25519"
  ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N "" -q -C "guardian-${KEY_ID}@$(hostname)"
  success "Generated SSH key: $SSH_KEY_PATH"
  echo ""
  info "Add this public key to your servers:"
  echo -e "    ${DIM}$(cat "${SSH_KEY_PATH}.pub")${NC}"
  echo ""
  info "You can add this key to servers later via:"
  echo -e "    ${DIM}ssh-copy-id -i ${SSH_KEY_PATH}.pub user@your-server${NC}"
fi

# ─── Step 5: Configure .env ────────────────────────────────────────────────────

step 5 "Environment configuration"

DASHBOARD_TOKEN=$(openssl rand -hex 16 2>/dev/null || head -c 32 /dev/urandom | xxd -p | head -c 32)

echo ""
info "Telegram Bot (required for alerts):"
prompt TELEGRAM_TOKEN "Bot token (from @BotFather)" ""
prompt TELEGRAM_CHAT "Chat ID (from @userinfobot)" ""

if [[ -z "$TELEGRAM_TOKEN" || -z "$TELEGRAM_CHAT" ]]; then
  warn "Telegram not configured — you can set it later in ${INSTALL_DIR}/.env"
fi

echo ""
info "AI Provider (enhances analysis — optional):"
echo -e "    ${DIM}1) Gemini (free tier)  2) OpenAI  3) Claude  4) Ollama (local)  5) Skip${NC}"
prompt AI_CHOICE "Choose [1-5]" "5"

AI_PROVIDER="auto"
GEMINI_KEY=""
OPENAI_KEY=""
ANTHROPIC_KEY=""

case "$AI_CHOICE" in
  1) prompt GEMINI_KEY "Gemini API key (paste here, Enter to skip)" ""; AI_PROVIDER="gemini" ;;
  2) prompt OPENAI_KEY "OpenAI API key (paste here, Enter to skip)" ""; AI_PROVIDER="openai" ;;
  3) prompt ANTHROPIC_KEY "Anthropic API key (paste here, Enter to skip)" ""; AI_PROVIDER="claude" ;;
  4) AI_PROVIDER="ollama" ;;
  *) AI_PROVIDER="auto" ;;
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
prompt ABUSEIPDB_KEY "AbuseIPDB API key (Enter to skip)" ""

echo ""
info "Security — Trusted entities (optional):"
info "These prevent false alerts for known-good connections."
echo -e "    ${DIM}Comma-separated IPs. Example: 203.0.113.10,198.51.100.5${NC}"
prompt TRUSTED_IPS_VAL "Your admin/home IPs (Enter to skip)" ""
echo -e "    ${DIM}Comma-separated SHA256 fingerprints. Get yours with: ssh-keygen -lf ~/.ssh/id_ed25519.pub${NC}"
prompt TRUSTED_FP_VAL "Your SSH key fingerprints (Enter to skip)" ""

mkdir -p "${INSTALL_DIR}/data"

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
TRUSTED_IPS=${TRUSTED_IPS_VAL}
TRUSTED_FINGERPRINTS=${TRUSTED_FP_VAL}
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
  docker pull ghcr.io/afborda/guardian-blue-team:latest || warn "Pull failed — will build locally"
  success "Docker mode ready"

  # Create docker-compose.yml if not exists
  if [[ ! -f "${INSTALL_DIR}/docker-compose.yml" ]]; then
    cat > "${INSTALL_DIR}/docker-compose.yml" << 'DCEOF'
services:
  guardian:
    image: ghcr.io/afborda/guardian-blue-team:latest
    container_name: guardian
    env_file: .env
    ports:
      - "3334:3334"
    volumes:
      - ./data:/data
      - ./keys:/home/node/.ssh:ro
    restart: unless-stopped
DCEOF
    success "Created docker-compose.yml"
  fi
else
  if [[ ! -d "${INSTALL_DIR}/app" ]]; then
    info "Cloning Guardian..."
    git clone --depth 1 https://github.com/afborda/guardian-blue-team.git "${INSTALL_DIR}/app" 2>/dev/null || {
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
info "Configure the first server to monitor (you can add more later via Telegram)."
prompt SERVER_NAME "Server name (e.g., prod-web-1)" "$(hostname)"
prompt SERVER_HOST "Server IP/hostname" "127.0.0.1"
prompt SERVER_PORT "SSH port" "22"
prompt SERVER_USER "SSH user" "$(whoami)"

# Only test SSH if host is not empty/localhost
if [[ -n "$SERVER_HOST" && "$SERVER_HOST" != "127.0.0.1" ]]; then
  echo ""
  info "Testing SSH connection to ${SERVER_USER}@${SERVER_HOST}:${SERVER_PORT}..."
  if ssh -i "$SSH_KEY_PATH" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p "$SERVER_PORT" "${SERVER_USER}@${SERVER_HOST}" "echo ok" &>/dev/null; then
    success "SSH connection successful!"
  else
    warn "SSH connection failed. Add the public key to the server:"
    echo -e "    ${DIM}ssh-copy-id -i ${SSH_KEY_PATH}.pub ${SERVER_USER}@${SERVER_HOST}${NC}"
  fi
fi

# Save server config
cat >> "${INSTALL_DIR}/.env" << EOF

# First server
HOST_SSH_HOST=${SERVER_HOST}
HOST_SSH_PORT=${SERVER_PORT}
HOST_SSH_USER=${SERVER_USER}
EOF

# ─── Summary ────────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}"
echo "  ┌─────────────────────────────────────────────────────┐"
echo "  │            ✔  Installation Complete!                 │"
echo "  └─────────────────────────────────────────────────────┘"
echo -e "${NC}"
echo ""
echo -e "  ${BOLD}Dashboard:${NC}     http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):3334/dashboard?token=${DASHBOARD_TOKEN}"
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
echo -e "  ${BOLD}Uninstall:${NC}     bash <(curl -fsSL https://raw.githubusercontent.com/afborda/guardian-blue-team/main/install.sh) --uninstall"
echo ""
echo -e "  ${DIM}Documentation: https://github.com/afborda/guardian-blue-team${NC}"
echo ""
