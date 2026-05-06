#!/usr/bin/env bash
# No set -e: we handle errors explicitly to avoid silent crashes

INSTALLER_VERSION="1.3.0"

# ─── Guardian Blue Team — Interactive Installer ─────────────────────────────────
# Supports: Ubuntu/Debian, Alpine, macOS
# Usage:
#   bash <(curl -fsSL https://raw.githubusercontent.com/afborda/guardian-blue-team/main/install.sh)
#   OR: curl -fsSL ... -o install.sh && bash install.sh
#
# Flags:
#   --uninstall   Remove Guardian and all data
#
# Non-interactive (env vars):
#   GUARDIAN_TELEGRAM_TOKEN=xxx GUARDIAN_TELEGRAM_CHAT=xxx \
#   GUARDIAN_DOMAIN=guardian.example.com \
#   bash <(curl -fsSL .../install.sh)

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
    # Stop docker compose
    if [[ -f "${INSTALL_DIR}/docker-compose.yml" ]]; then
      cd "$INSTALL_DIR"
      docker compose down 2>/dev/null || true
      info "Stopped Docker containers"
    fi
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
    # Remove docker image
    if docker image inspect ghcr.io/afborda/guardian-blue-team:latest &>/dev/null 2>&1; then
      docker rmi ghcr.io/afborda/guardian-blue-team:latest 2>/dev/null || true
      info "Removed Docker image"
    fi
    # Remove guardian SSH key from authorized_keys
    if [[ -f "${HOME}/.ssh/authorized_keys" ]]; then
      grep -v "guardian@" "${HOME}/.ssh/authorized_keys" > "${HOME}/.ssh/authorized_keys.tmp" 2>/dev/null || true
      mv "${HOME}/.ssh/authorized_keys.tmp" "${HOME}/.ssh/authorized_keys" 2>/dev/null || true
      chmod 600 "${HOME}/.ssh/authorized_keys" 2>/dev/null || true
      info "Removed guardian SSH key from authorized_keys"
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

# ─── Handle --upgrade ──────────────────────────────────────────────────────────

if [[ "${1:-}" == "--upgrade" ]]; then
  banner
  INSTALL_DIR="${HOME}/.guardian"
  if [[ ! -d "$INSTALL_DIR" ]]; then
    error "Guardian not found at $INSTALL_DIR — install first."
    exit 1
  fi

  info "Upgrading Guardian..."
  cd "$INSTALL_DIR"

  # Pull latest image or code
  if docker compose pull 2>/dev/null; then
    success "Latest image pulled"
  else
    if [[ -d .git ]]; then
      git pull --ff-only 2>/dev/null && success "Code updated" || warn "Git pull failed"
    fi
  fi

  # Rebuild and restart
  docker compose up -d --build 2>/dev/null || docker compose up -d

  # Wait for health
  info "Waiting for Guardian to start..."
  ATTEMPTS=0
  while [[ $ATTEMPTS -lt 12 ]]; do
    if wget -qO- http://localhost:3334/health 2>/dev/null | grep -q '"status":"ok"'; then
      success "Guardian upgraded and healthy!"
      exit 0
    fi
    ATTEMPTS=$((ATTEMPTS + 1))
    sleep 5
  done

  warn "Guardian may still be starting. Check: docker compose logs -f"
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

# ─── Step 2: Check & Fix Prerequisites ────────────────────────────────────────

step 2 "Checking prerequisites"

MISSING=()
WARNINGS=()
HAS_DOCKER=false

# ─── Node.js (auto-install if missing or outdated) ─────────────────────────────
NODE_OK=false
if command -v node &>/dev/null; then
  NODE_VERSION=$(node -v | sed 's/v//')
  NODE_MAJOR=$(echo "$NODE_VERSION" | cut -d. -f1)
  if [[ $NODE_MAJOR -ge 20 ]]; then
    success "Node.js v${NODE_VERSION}"
    NODE_OK=true
  else
    warn "Node.js v${NODE_VERSION} found but v20+ is required"
  fi
fi

if [[ "$NODE_OK" == "false" ]]; then
  info "Node.js 20+ not found — attempting to install..."
  if [[ "$PKG_MANAGER" == "apt" ]]; then
    curl -fsSL https://deb.nodesource.com/setup_20.x 2>/dev/null | bash - >/dev/null 2>&1
    apt-get install -y nodejs >/dev/null 2>&1
  elif [[ "$PKG_MANAGER" == "brew" ]]; then
    brew install node >/dev/null 2>&1
  elif [[ "$PKG_MANAGER" == "apk" ]]; then
    apk add --no-cache nodejs npm >/dev/null 2>&1
  elif [[ "$PKG_MANAGER" == "yum" ]]; then
    curl -fsSL https://rpm.nodesource.com/setup_20.x 2>/dev/null | bash - >/dev/null 2>&1
    yum install -y nodejs >/dev/null 2>&1
  fi

  # Verify install worked
  if command -v node &>/dev/null; then
    NODE_VERSION=$(node -v | sed 's/v//')
    NODE_MAJOR=$(echo "$NODE_VERSION" | cut -d. -f1)
    if [[ $NODE_MAJOR -ge 20 ]]; then
      success "Node.js v${NODE_VERSION} (auto-installed)"
      NODE_OK=true
    else
      MISSING+=("Node.js >= 20 (installed v${NODE_VERSION} but need 20+)")
      error "Auto-install got wrong version"
    fi
  else
    MISSING+=("Node.js (v20+) — auto-install failed")
    error "Could not install Node.js automatically"
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
  info "git not found — installing..."
  if [[ "$PKG_MANAGER" == "apt" ]]; then
    apt-get install -y git >/dev/null 2>&1
  elif [[ "$PKG_MANAGER" == "brew" ]]; then
    brew install git >/dev/null 2>&1
  elif [[ "$PKG_MANAGER" == "apk" ]]; then
    apk add --no-cache git >/dev/null 2>&1
  elif [[ "$PKG_MANAGER" == "yum" ]]; then
    yum install -y git >/dev/null 2>&1
  fi
  if command -v git &>/dev/null; then
    success "git $(git --version | awk '{print $3}') (auto-installed)"
  else
    MISSING+=("git")
    error "git not found and auto-install failed"
  fi
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

# ─── openssl ───────────────────────────────────────────────────────────────────
if command -v openssl &>/dev/null; then
  success "openssl available"
elif [[ -r /dev/urandom ]]; then
  success "/dev/urandom readable"
else
  WARNINGS+=("No secure random source — dashboard token may need manual setting")
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

# ─── curl ───────────────────────────────────────────────────────────────────────
if command -v curl &>/dev/null; then
  success "curl available"
elif command -v wget &>/dev/null; then
  success "wget available"
else
  WARNINGS+=("Neither curl nor wget found — Telegram notifications may fail")
  warn "No HTTP client (curl/wget) found"
fi

# ─── Disk space ─────────────────────────────────────────────────────────────────
INSTALL_PARENT=$(dirname "${INSTALL_DIR:-$HOME/.guardian}")
if command -v df &>/dev/null; then
  FREE_MB=$(df -m "$INSTALL_PARENT" 2>/dev/null | awk 'NR==2{print $4}')
  if [[ -n "$FREE_MB" && "$FREE_MB" -lt 500 ]]; then
    MISSING+=("Disk space: only ${FREE_MB}MB free (need 500MB+)")
    error "Insufficient disk space: ${FREE_MB}MB free"
  elif [[ -n "$FREE_MB" ]]; then
    success "Disk space: ${FREE_MB}MB free"
  fi
fi

# ─── RAM ────────────────────────────────────────────────────────────────────────
if [[ "$OS" == "macos" ]]; then
  TOTAL_RAM_MB=$(sysctl -n hw.memsize 2>/dev/null | awk '{print int($1/1048576)}')
  if [[ -n "$TOTAL_RAM_MB" && "$TOTAL_RAM_MB" -gt 0 ]]; then
    success "RAM: ${TOTAL_RAM_MB}MB total"
  fi
elif [[ -f /proc/meminfo ]]; then
  AVAIL_RAM_MB=$(grep MemAvailable /proc/meminfo 2>/dev/null | awk '{print int($2/1024)}')
  if [[ -n "$AVAIL_RAM_MB" && "$AVAIL_RAM_MB" -lt 256 ]]; then
    WARNINGS+=("Low RAM: ${AVAIL_RAM_MB}MB available")
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
  error "Cannot write to ${INSTALL_PARENT_DIR}"
fi

# ─── Network ───────────────────────────────────────────────────────────────────
if command -v curl &>/dev/null; then
  if curl -sf --max-time 5 "https://registry.npmjs.org/" &>/dev/null; then
    success "Network: npm registry reachable"
  else
    WARNINGS+=("Cannot reach npm registry")
    warn "Cannot reach registry.npmjs.org"
  fi
  if curl -sf --max-time 5 "https://github.com" &>/dev/null; then
    success "Network: github.com reachable"
  else
    WARNINGS+=("Cannot reach github.com")
    warn "Cannot reach github.com"
  fi
fi

# ─── systemd ───────────────────────────────────────────────────────────────────
if command -v systemctl &>/dev/null; then
  success "systemd available"
  HAS_SYSTEMD=true
else
  info "systemd not available"
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

# Check if any key already exists in our keys directory
SSH_KEY_PATH=""
if ls "${INSTALL_DIR}/keys/"*ed25519 1>/dev/null 2>&1; then
  SSH_KEY_PATH=$(ls "${INSTALL_DIR}/keys/"*ed25519 2>/dev/null | grep -v '.pub' | head -1)
fi

if [[ -n "$SSH_KEY_PATH" && -f "$SSH_KEY_PATH" ]]; then
  success "SSH key already exists: $SSH_KEY_PATH"
else
  # Generate unique key name
  KEY_ID=$(openssl rand -hex 3 2>/dev/null)
  KEY_ID="${KEY_ID:-$(date +%s | tail -c 6)}"
  KEY_ID="${KEY_ID:0:5}"
  SSH_KEY_PATH="${INSTALL_DIR}/keys/guardian-${KEY_ID}_ed25519"
  yes n 2>/dev/null | ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N "" -q -C "guardian@$(hostname)" 2>/dev/null || true
  if [[ -f "$SSH_KEY_PATH" ]]; then
    success "Generated SSH key: $SSH_KEY_PATH"
    echo ""
    info "Add this public key to your servers:"
    echo -e "    ${DIM}$(cat "${SSH_KEY_PATH}.pub")${NC}"
    echo ""
    info "You can add this key later via:"
    echo -e "    ${DIM}ssh-copy-id -i ${SSH_KEY_PATH}.pub user@your-server${NC}"
  else
    warn "Could not generate SSH key — you can create one manually later"
    SSH_KEY_PATH="${INSTALL_DIR}/keys/id_ed25519"
  fi
fi

# ─── Step 5: Configure .env ────────────────────────────────────────────────────

step 5 "Environment configuration"

DASHBOARD_TOKEN=$(openssl rand -hex 16 2>/dev/null || head -c 32 /dev/urandom | xxd -p | head -c 32)

# Accept env vars for non-interactive mode
TELEGRAM_TOKEN="${GUARDIAN_TELEGRAM_TOKEN:-}"
TELEGRAM_CHAT="${GUARDIAN_TELEGRAM_CHAT:-}"

echo ""
info "Telegram Bot (required for alerts):"
if [[ -z "$TELEGRAM_TOKEN" ]]; then
  prompt TELEGRAM_TOKEN "Bot token (from @BotFather)" ""
else
  success "Bot token: (from environment)"
fi
if [[ -z "$TELEGRAM_CHAT" ]]; then
  prompt TELEGRAM_CHAT "Chat ID (from @userinfobot)" ""
else
  success "Chat ID: (from environment)"
fi

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
  1) prompt GEMINI_KEY "Gemini API key (paste, Enter to skip)" ""; AI_PROVIDER="gemini" ;;
  2) prompt OPENAI_KEY "OpenAI API key (paste, Enter to skip)" ""; AI_PROVIDER="openai" ;;
  3) prompt ANTHROPIC_KEY "Anthropic API key (paste, Enter to skip)" ""; AI_PROVIDER="claude" ;;
  4) AI_PROVIDER="ollama" ;;
  *) AI_PROVIDER="auto" ;;
esac

echo ""
info "Database:"
echo -e "    ${DIM}1) SQLite (zero-config, great for single server)${NC}"
echo -e "    ${DIM}2) PostgreSQL (recommended for multiple servers — auto-configured)${NC}"
prompt DB_CHOICE "Choose [1-2]" "1"

DATABASE_URL="sqlite:/data/guardian.db"
USE_POSTGRES=false
if [[ "$DB_CHOICE" == "2" ]]; then
  USE_POSTGRES=true
  # Generate postgres password
  PG_PASSWORD=$(openssl rand -hex 12 2>/dev/null || echo "guardian_$(date +%s)")
  DATABASE_URL="postgres://guardian:${PG_PASSWORD}@localhost:5432/guardian"
  success "PostgreSQL will be auto-configured in Docker Compose"
fi

echo ""
info "Threat intelligence (optional):"
prompt ABUSEIPDB_KEY "AbuseIPDB API key (Enter to skip)" ""

echo ""
info "Security — Trusted entities (optional):"
info "These prevent false alerts for YOUR OWN logins."

# Detect current SSH client IP
CURRENT_CLIENT_IP=$(echo "${SSH_CLIENT:-}" | awk '{print $1}')
if [[ -z "$CURRENT_CLIENT_IP" ]]; then
  CURRENT_CLIENT_IP=$(who am i 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi

if [[ -n "$CURRENT_CLIENT_IP" ]]; then
  info "Your current IP: ${BOLD}${CURRENT_CLIENT_IP}${NC} (detected from SSH session)"
  prompt TRUSTED_IPS_VAL "Trusted IPs (comma-separated, Enter to accept)" "$CURRENT_CLIENT_IP"
else
  echo -e "    ${DIM}Comma-separated IPs. Tip: run 'curl ifconfig.me' to find yours${NC}"
  prompt TRUSTED_IPS_VAL "Your admin/home IPs (Enter to skip)" ""
fi

# Detect current SSH key fingerprint
CURRENT_FP=""
if [[ -n "${SSH_CLIENT:-}" && -f /var/log/auth.log ]]; then
  CURRENT_FP=$(grep "Accepted publickey" /var/log/auth.log 2>/dev/null | grep "${CURRENT_CLIENT_IP:-x}" | tail -1 | grep -oE 'SHA256:[A-Za-z0-9+/=]+' | tail -1)
fi

if [[ -n "$CURRENT_FP" ]]; then
  info "Your SSH key fingerprint: ${BOLD}${CURRENT_FP}${NC}"
  prompt TRUSTED_FP_VAL "Trusted fingerprints (Enter to accept)" "$CURRENT_FP"
else
  echo -e "    ${DIM}Get yours: ssh-keygen -lf ~/.ssh/id_ed25519.pub${NC}"
  prompt TRUSTED_FP_VAL "Trusted fingerprints (Enter to skip)" ""
fi

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
HOST_SSH_KEY_PATH=/home/node/.ssh/$(basename "$SSH_KEY_PATH")
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
  success "Image pulled"

  # ─── Fix SSH key permissions for container (node uid=1000) ───────────────────
  # The container runs as 'node' (uid 1000), so keys must be owned by that uid.
  # Root (the typical installer user) can still read these for SSH testing in Step 7.
  info "Setting SSH key permissions for container..."
  chown -R 1000:1000 "${INSTALL_DIR}/keys" 2>/dev/null || sudo chown -R 1000:1000 "${INSTALL_DIR}/keys" 2>/dev/null || true
  chmod 700 "${INSTALL_DIR}/keys" 2>/dev/null || true
  chmod 600 "${INSTALL_DIR}/keys/"* 2>/dev/null || true
  success "SSH key permissions fixed (uid=1000)"

  # ─── Auto-add guardian public key to host authorized_keys ────────────────────
  if [[ -f "${SSH_KEY_PATH}.pub" ]]; then
    GUARDIAN_PUBKEY=$(cat "${SSH_KEY_PATH}.pub")
    AUTHORIZED_KEYS="${HOME}/.ssh/authorized_keys"
    mkdir -p "${HOME}/.ssh"
    chmod 700 "${HOME}/.ssh"
    if ! grep -qF "$GUARDIAN_PUBKEY" "$AUTHORIZED_KEYS" 2>/dev/null; then
      echo "$GUARDIAN_PUBKEY" >> "$AUTHORIZED_KEYS"
      chmod 600 "$AUTHORIZED_KEYS"
      success "Guardian SSH key added to ${AUTHORIZED_KEYS}"
    else
      success "Guardian SSH key already in authorized_keys"
    fi
  fi

  # ─── Detect SSH port ──────────────────────────────────────────────────────────
  HOST_SSH_PORT=$(grep -E '^\s*Port\s+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
  HOST_SSH_PORT="${HOST_SSH_PORT:-22}"

  # Detect Traefik
  TRAEFIK_NETWORK=""
  GUARDIAN_DOMAIN="${GUARDIAN_DOMAIN:-}"

  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qi traefik; then
    TRAEFIK_CONTAINER=$(docker ps --format '{{.Names}}' | grep -i traefik | head -1)
    TRAEFIK_NETWORK=$(docker inspect "$TRAEFIK_CONTAINER" 2>/dev/null | grep -oP '"Name":\s*"\K[^"]+' | grep -iE 'traefik|proxy|public' | head -1)
    if [[ -z "$TRAEFIK_NETWORK" ]]; then
      TRAEFIK_NETWORK=$(docker network ls --format '{{.Name}}' | grep -iE 'traefik|proxy' | head -1)
    fi
  fi

  if [[ -n "$TRAEFIK_NETWORK" ]]; then
    info "Traefik detected (network: ${TRAEFIK_NETWORK})"
    if [[ -z "$GUARDIAN_DOMAIN" ]]; then
      prompt GUARDIAN_DOMAIN "Domain for Guardian dashboard" "guardian.$(hostname -d 2>/dev/null || echo 'example.com')"
    else
      success "Domain: ${GUARDIAN_DOMAIN} (from environment)"
    fi

    # Guardian uses host network (SSH to 127.0.0.1 works directly)
    # A proxy sidecar joins the Traefik network for HTTPS routing
    cat > "${INSTALL_DIR}/docker-compose.yml" << DCEOF
services:
  guardian:
    image: ghcr.io/afborda/guardian-blue-team:latest
    container_name: guardian
    network_mode: host
    env_file: .env
    volumes:
      - ./data:/data
      - ./keys:/home/node/.ssh
    restart: unless-stopped
DCEOF

    # Add postgres if selected (also host network for localhost access)
    if [[ "$USE_POSTGRES" == "true" ]]; then
      cat >> "${INSTALL_DIR}/docker-compose.yml" << DCEOF
    depends_on:
      guardian-db:
        condition: service_healthy

  guardian-db:
    image: postgres:16-alpine
    container_name: guardian-db
    network_mode: host
    environment:
      POSTGRES_DB: guardian
      POSTGRES_USER: guardian
      POSTGRES_PASSWORD: ${PG_PASSWORD}
    volumes:
      - pg_data:/var/lib/postgresql/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "guardian"]
      interval: 5s
      timeout: 3s
      retries: 5

DCEOF
    fi

    # Add Traefik proxy sidecar — bridges host network to Traefik's Docker network
    cat >> "${INSTALL_DIR}/docker-compose.yml" << DCEOF
  guardian-proxy:
    image: nginx:alpine
    container_name: guardian-proxy
    restart: unless-stopped
    networks:
      - ${TRAEFIK_NETWORK}
    extra_hosts:
      - "host.docker.internal:host-gateway"
    volumes:
      - ./nginx-proxy.conf:/etc/nginx/conf.d/default.conf:ro
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.guardian.rule=Host(\`${GUARDIAN_DOMAIN}\`)"
      - "traefik.http.routers.guardian.entrypoints=websecure"
      - "traefik.http.routers.guardian.tls.certresolver=letsencrypt"
      - "traefik.http.services.guardian.loadbalancer.server.port=80"
      - "traefik.docker.network=${TRAEFIK_NETWORK}"

DCEOF

    # Add volumes and networks
    if [[ "$USE_POSTGRES" == "true" ]]; then
      cat >> "${INSTALL_DIR}/docker-compose.yml" << DCEOF
volumes:
  pg_data:

DCEOF
    fi

    cat >> "${INSTALL_DIR}/docker-compose.yml" << DCEOF
networks:
  ${TRAEFIK_NETWORK}:
    external: true
DCEOF

    # Create nginx proxy config
    cat > "${INSTALL_DIR}/nginx-proxy.conf" << 'NGEOF'
server {
    listen 80;
    location / {
        proxy_pass http://host.docker.internal:3334;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGEOF

    success "Created docker-compose.yml (host network + Traefik proxy)"

  else
    # No Traefik — Guardian with host network, direct port access
    cat > "${INSTALL_DIR}/docker-compose.yml" << 'DCEOF'
services:
  guardian:
    image: ghcr.io/afborda/guardian-blue-team:latest
    container_name: guardian
    network_mode: host
    env_file: .env
    volumes:
      - ./data:/data
      - ./keys:/home/node/.ssh
    restart: unless-stopped
DCEOF

    if [[ "$USE_POSTGRES" == "true" ]]; then
      cat >> "${INSTALL_DIR}/docker-compose.yml" << DCEOF
    depends_on:
      guardian-db:
        condition: service_healthy

  guardian-db:
    image: postgres:16-alpine
    container_name: guardian-db
    network_mode: host
    environment:
      POSTGRES_DB: guardian
      POSTGRES_USER: guardian
      POSTGRES_PASSWORD: ${PG_PASSWORD}
    volumes:
      - pg_data:/var/lib/postgresql/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "guardian"]
      interval: 5s
      timeout: 3s
      retries: 5

volumes:
  pg_data:
DCEOF
    fi
    success "Created docker-compose.yml (host network)"
  fi

  # Start Guardian automatically
  info "Starting Guardian..."
  cd "${INSTALL_DIR}"
  docker compose up -d

  # ─── Post-install validation ──────────────────────────────────────────────────
  echo ""
  info "Validating installation..."

  ATTEMPTS=0
  MAX_ATTEMPTS=12
  while [[ $ATTEMPTS -lt $MAX_ATTEMPTS ]]; do
    if wget -qO- http://localhost:3334/health 2>/dev/null | grep -q '"status":"ok"'; then
      success "Guardian is healthy!"
      break
    fi
    ATTEMPTS=$((ATTEMPTS + 1))
    sleep 5
  done

  if [[ $ATTEMPTS -ge $MAX_ATTEMPTS ]]; then
    warn "Guardian is still starting. Check logs: docker compose logs -f"
  fi

  info "Tip: Run auto-discovery for advanced config: docker exec guardian npx tsx src/discovery/cli.ts"

  # Test Telegram
  if [[ -n "${TELEGRAM_TOKEN:-}" ]]; then
    info "Testing Telegram bot..."
    TELEGRAM_RESP=$(wget -qO- --post-data="chat_id=${TELEGRAM_CHAT_ID}&text=%F0%9F%9B%A1%EF%B8%8F+Guardian+installed+on+$(hostname)%21&parse_mode=HTML" \
      "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" 2>/dev/null || echo "")
    if echo "$TELEGRAM_RESP" | grep -q '"ok":true'; then
      success "Telegram notification sent! Check your chat."
    else
      warn "Could not send Telegram test message. Verify your token and chat ID."
    fi
  fi

else
  # Native Node.js mode
  if [[ ! -d "${INSTALL_DIR}/app" ]]; then
    info "Cloning Guardian..."
    git clone --depth 1 https://github.com/afborda/guardian-blue-team.git "${INSTALL_DIR}/app" 2>/dev/null || {
      warn "Clone failed — ensure the repo URL is correct"
      mkdir -p "${INSTALL_DIR}/app"
    }
  fi

  if [[ -f "${INSTALL_DIR}/app/package.json" ]]; then
    cd "${INSTALL_DIR}/app"
    info "Installing dependencies..."
    npm ci --production 2>/dev/null || npm install
    npm run build 2>/dev/null || true
    success "Guardian built successfully"

    # ─── Auto-Discovery ────────────────────────────────────────────────
    echo -e "\n  ${CYAN}${BOLD}[Auto-Discovery]${NC} ${BOLD}Running auto-discovery...${NC}"

    DISCOVERY_ARGS="--dir ${INSTALL_DIR}"
    [[ -n "${GEMINI_KEY:-}" ]] && DISCOVERY_ARGS="${DISCOVERY_ARGS} --api-key ${GEMINI_KEY}"
    [[ -n "${TELEGRAM_TOKEN:-}" ]] && DISCOVERY_ARGS="${DISCOVERY_ARGS} --telegram-token ${TELEGRAM_TOKEN}"
    [[ -n "${TELEGRAM_CHAT:-}" ]] && DISCOVERY_ARGS="${DISCOVERY_ARGS} --telegram-chat-id ${TELEGRAM_CHAT}"
    [[ -n "${GUARDIAN_DOMAIN:-}" ]] && DISCOVERY_ARGS="${DISCOVERY_ARGS} --domain ${GUARDIAN_DOMAIN}"

    if [[ -n "${GEMINI_KEY:-}" ]]; then
      info "AI auto-discovery will configure Guardian for this server..."
      npx tsx src/discovery/cli.ts ${DISCOVERY_ARGS} </dev/tty || {
        warn "Auto-discovery exited non-zero. Using manual configuration."
      }
    else
      info "No Gemini API key — skipping auto-discovery."
      info "Run later: cd ${INSTALL_DIR}/app && npx tsx src/discovery/cli.ts --api-key YOUR_KEY --dir ${INSTALL_DIR}"
    fi

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
      sudo systemctl start guardian
      success "Guardian service created and started!"
    fi
  fi
fi

# ─── Step 7: Add First Server ────────────────────────────────────────────────

step 7 "Add your first server"

echo ""
info "Configure the first server to monitor (add more later via Telegram /add-server)."
info "Since Guardian runs with host networking, 127.0.0.1 monitors THIS machine."
prompt SERVER_NAME "Server name (e.g., prod-web-1)" "$(hostname)"
prompt SERVER_HOST "Server IP/hostname" "127.0.0.1"

# Detect SSH port from sshd_config
DETECTED_SSH_PORT=$(grep -E '^\s*Port\s+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
DETECTED_SSH_PORT="${DETECTED_SSH_PORT:-22}"
prompt SERVER_PORT "SSH port" "$DETECTED_SSH_PORT"
prompt SERVER_USER "SSH user" "$(whoami)"

# Test SSH connection (works for both localhost and remote)
echo ""
info "Testing SSH connection to ${SERVER_USER}@${SERVER_HOST}:${SERVER_PORT}..."
if ssh -i "$SSH_KEY_PATH" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p "$SERVER_PORT" "${SERVER_USER}@${SERVER_HOST}" "echo ok" &>/dev/null; then
  success "SSH connection successful! Guardian can collect data from this server."
else
  warn "SSH connection failed."
  if [[ "$SERVER_HOST" == "127.0.0.1" || "$SERVER_HOST" == "localhost" ]]; then
    info "The guardian SSH key should already be in authorized_keys."
    info "If it's not working, check that sshd allows publickey auth."
  else
    echo -e "    ${DIM}Add the key: ssh-copy-id -i ${SSH_KEY_PATH}.pub -p ${SERVER_PORT} ${SERVER_USER}@${SERVER_HOST}${NC}"
  fi
fi

# Save server config
cat >> "${INSTALL_DIR}/.env" << EOF

# First server
HOST_SSH_HOST=${SERVER_HOST}
HOST_SSH_PORT=${SERVER_PORT}
HOST_SSH_USER=${SERVER_USER}
EOF

# Restart to pick up server config
if [[ "$DEPLOY_MODE" == "1" ]]; then
  cd "${INSTALL_DIR}"
  docker compose restart guardian >/dev/null 2>&1 || true
fi

# ─── Summary ────────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}"
echo "  ┌─────────────────────────────────────────────────────┐"
echo "  │        ✔  Guardian is installed and running!         │"
echo "  └─────────────────────────────────────────────────────┘"
echo -e "${NC}"
echo ""

# Show the right dashboard URL
if [[ -n "${GUARDIAN_DOMAIN:-}" ]]; then
  echo -e "  ${BOLD}Dashboard:${NC}     https://${GUARDIAN_DOMAIN}/dashboard?token=${DASHBOARD_TOKEN}"
else
  SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo -e "  ${BOLD}Dashboard:${NC}     http://${SERVER_IP:-localhost}:3334/dashboard?token=${DASHBOARD_TOKEN}"
fi
echo -e "  ${BOLD}Config:${NC}        ${INSTALL_DIR}/.env"
echo -e "  ${BOLD}SSH Key:${NC}       ${SSH_KEY_PATH}"
echo ""

if [[ "$DEPLOY_MODE" == "1" ]]; then
  echo -e "  ${BOLD}Logs:${NC}          cd ${INSTALL_DIR} && docker compose logs -f"
  echo -e "  ${BOLD}Restart:${NC}       cd ${INSTALL_DIR} && docker compose restart"
  echo -e "  ${BOLD}Stop:${NC}          cd ${INSTALL_DIR} && docker compose down"
else
  echo -e "  ${BOLD}Logs:${NC}          journalctl -u guardian -f"
  echo -e "  ${BOLD}Restart:${NC}       sudo systemctl restart guardian"
  echo -e "  ${BOLD}Stop:${NC}          sudo systemctl stop guardian"
fi

echo ""
echo -e "  ${BOLD}Telegram:${NC}      Send /status to your bot to verify"
echo -e "  ${BOLD}Add servers:${NC}   Send /add-server via Telegram"
echo -e "  ${BOLD}Uninstall:${NC}     bash <(curl -fsSL https://raw.githubusercontent.com/afborda/guardian-blue-team/main/install.sh) --uninstall"
echo ""
echo -e "  ${DIM}Documentation: https://github.com/afborda/guardian-blue-team${NC}"
echo ""
