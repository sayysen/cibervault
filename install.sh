#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# Cibervault EDR/SIEM Platform — Server Installer
# 
# One-command installation on Ubuntu 22.04/24.04
#
# Usage:
#   git clone https://github.com/sayysen/cibervault.git
#   cd cibervault
#   sudo bash install.sh
#
# What it installs:
#   - Python 3, pip, required packages
#   - FastAPI server + SQLite database
#   - Ollama AI (phi3:mini + qwen2.5-coder:7b)
#   - Nginx reverse proxy + optional Let's Encrypt TLS
#   - Cibervault Linux Agent (local telemetry)
#   - Systemd services (auto-start on boot)
#   - .NET 8 SDK (for building Windows agent)
#   - fail2ban (SSH protection)
# ═══════════════════════════════════════════════════════════════════════════
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "  ${GREEN}[OK]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }
err()  { echo -e "  ${RED}[ERROR]${NC} $1"; }
step() { echo -e "\n${CYAN}  [$1/$TOTAL_STEPS]${NC} ${BOLD}$2${NC}"; }

TOTAL_STEPS=12
INSTALL_DIR="/opt/cibervault"
SERVER_PORT=8081
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo -e "${CYAN}  ╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}  ║                                                        ║${NC}"
echo -e "${CYAN}  ║${NC}   ${BOLD}Cibervault EDR/SIEM Platform — Installer${NC}            ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   AI-Powered Endpoint Detection & Response            ${CYAN}║${NC}"
echo -e "${CYAN}  ║                                                        ║${NC}"
echo -e "${CYAN}  ╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Root check ────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    err "Run as root: sudo bash install.sh"
    exit 1
fi

# ── Interactive config ────────────────────────────────────────────────
echo -e "  ${BOLD}Configuration${NC}"
echo ""

# Domain
read -p "  Domain name (leave blank for IP-only): " CV_DOMAIN
CV_DOMAIN=$(echo "$CV_DOMAIN" | xargs)

# Admin password
while true; do
    read -sp "  Admin password (min 8 chars): " CV_ADMIN_PASS
    echo ""
    if [ ${#CV_ADMIN_PASS} -ge 8 ]; then break; fi
    warn "Password must be at least 8 characters"
done

# TLS
CV_TLS="n"
if [ -n "$CV_DOMAIN" ]; then
    read -p "  Enable Let's Encrypt TLS for $CV_DOMAIN? (Y/n): " CV_TLS
    CV_TLS=${CV_TLS:-Y}
fi

# Ollama
read -p "  Install Ollama AI? (Y/n): " CV_OLLAMA
CV_OLLAMA=${CV_OLLAMA:-Y}

# .NET SDK
read -p "  Install .NET 8 SDK (for building Windows agent)? (Y/n): " CV_DOTNET
CV_DOTNET=${CV_DOTNET:-Y}

echo ""
echo -e "  ${BOLD}Installing with:${NC}"
echo "    Domain:    ${CV_DOMAIN:-none (IP only)}"
echo "    TLS:       ${CV_TLS}"
echo "    Ollama AI: ${CV_OLLAMA}"
echo "    .NET SDK:  ${CV_DOTNET}"
echo ""
read -p "  Continue? (Y/n): " CONFIRM
if [ "$CONFIRM" = "n" ] || [ "$CONFIRM" = "N" ]; then
    echo "  Cancelled."
    exit 0
fi

# ══════════════════════════════════════════════════════════════════════
step 1 "System dependencies"
# ══════════════════════════════════════════════════════════════════════

apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv sqlite3 \
    nginx certbot python3-certbot-nginx \
    curl wget zip unzip jq fail2ban \
    iptables-persistent net-tools > /dev/null 2>&1

log "System packages installed"

# ══════════════════════════════════════════════════════════════════════
step 2 "Create Cibervault user and directories"
# ══════════════════════════════════════════════════════════════════════

# Create system user
if ! id -u cibervault > /dev/null 2>&1; then
    useradd -r -m -s /bin/false cibervault
    log "Created cibervault user"
else
    log "cibervault user exists"
fi

# Create directories
mkdir -p "$INSTALL_DIR"/{data,logs,backups,agent-binaries}
mkdir -p "$INSTALL_DIR"/server/static/{js,css,downloads}

log "Directories created"

# ══════════════════════════════════════════════════════════════════════
step 3 "Copy server files"
# ══════════════════════════════════════════════════════════════════════

# Copy server files from repo
if [ -d "$SCRIPT_DIR/server" ]; then
    cp -r "$SCRIPT_DIR/server/"* "$INSTALL_DIR/server/"
    log "Server files copied"
else
    err "Server directory not found. Run from the git repo root."
    exit 1
fi

# Copy agent source
if [ -d "$SCRIPT_DIR/agent-source" ]; then
    cp -r "$SCRIPT_DIR/agent-source" "$INSTALL_DIR/agent-source"
    log "Agent source copied"
fi

# Copy Linux agent
if [ -f "$SCRIPT_DIR/linux-agent-installer/cibervault-linux-agent.py" ]; then
    cp "$SCRIPT_DIR/linux-agent-installer/cibervault-linux-agent.py" "$INSTALL_DIR/cibervault-linux-agent.py"
    cp "$SCRIPT_DIR/linux-agent-installer/install.sh" "$INSTALL_DIR/linux-agent-install.sh" 2>/dev/null
    log "Linux agent copied"
fi

# ══════════════════════════════════════════════════════════════════════
step 4 "Python dependencies"
# ══════════════════════════════════════════════════════════════════════

pip3 install --break-system-packages -q \
    fastapi uvicorn[standard] aiosqlite aiohttp \
    python-multipart python-jose passlib bcrypt \
    httpx pydantic jinja2 2>/dev/null || \
pip3 install -q \
    fastapi uvicorn[standard] aiosqlite aiohttp \
    python-multipart python-jose passlib bcrypt \
    httpx pydantic jinja2

log "Python packages installed"

# ══════════════════════════════════════════════════════════════════════
step 5 "Generate secrets and config"
# ══════════════════════════════════════════════════════════════════════

JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
AGENT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
SESSION_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Get server IP
SERVER_IP=$(hostname -I | awk '{print $1}')

# Create server.env
cat > "$INSTALL_DIR/server.env" << ENVEOF
JWT_SECRET=${JWT_SECRET}
AGENT_SECRET=${AGENT_SECRET}
SESSION_SECRET=${SESSION_SECRET}
DB_PATH=${INSTALL_DIR}/data/cibervault.db
SERVER_PORT=${SERVER_PORT}
SERVER_IP=${SERVER_IP}
DOMAIN=${CV_DOMAIN}
OLLAMA_URL=http://127.0.0.1:11434
AI_PROVIDER=ollama
ENVEOF

chmod 600 "$INSTALL_DIR/server.env"
log "Secrets generated and saved to server.env"

# Create agent config for local agent
cat > "$INSTALL_DIR/agent.conf" << AGENTEOF
CV_SERVER=http://127.0.0.1:${SERVER_PORT}
CV_SECRET=${AGENT_SECRET}
AGENTEOF

chmod 600 "$INSTALL_DIR/agent.conf"
log "Agent config created"

# ══════════════════════════════════════════════════════════════════════
step 6 "Initialize database"
# ══════════════════════════════════════════════════════════════════════

# Create admin user hash
ADMIN_HASH=$(python3 -c "
from passlib.hash import bcrypt
print(bcrypt.hash('${CV_ADMIN_PASS}'))
" 2>/dev/null || python3 -c "
import hashlib
print(hashlib.sha256('${CV_ADMIN_PASS}'.encode()).hexdigest())
")

# Initialize DB — the server creates tables on startup, but we pre-create admin
sqlite3 "$INSTALL_DIR/data/cibervault.db" << SQLEOF
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT DEFAULT '',
    email TEXT DEFAULT '',
    role TEXT DEFAULT 'analyst',
    active INTEGER DEFAULT 1,
    last_login TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO users (username, password_hash, full_name, role)
VALUES ('admin', '${ADMIN_HASH}', 'System Administrator', 'admin');

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TEXT DEFAULT (datetime('now'))
);

INSERT OR REPLACE INTO settings (key, value) VALUES ('agent_secret', '${AGENT_SECRET}');
INSERT OR REPLACE INTO settings (key, value) VALUES ('server_url', 'https://${CV_DOMAIN:-$SERVER_IP}');
SQLEOF

log "Database initialized with admin user"

# ══════════════════════════════════════════════════════════════════════
step 7 "Set permissions"
# ══════════════════════════════════════════════════════════════════════

chown -R cibervault:cibervault "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR/server"
chmod 700 "$INSTALL_DIR/data"
chmod 600 "$INSTALL_DIR/server.env" "$INSTALL_DIR/agent.conf"

log "Permissions set"

# ══════════════════════════════════════════════════════════════════════
step 8 "Create systemd services"
# ══════════════════════════════════════════════════════════════════════

# Cibervault Server
cat > /etc/systemd/system/cibervault-server.service << 'SVCEOF'
[Unit]
Description=Cibervault EDR/SIEM Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cibervault
Group=cibervault
WorkingDirectory=/opt/cibervault/server
EnvironmentFile=/opt/cibervault/server.env
ExecStart=/usr/bin/python3 -m uvicorn main:app --host 0.0.0.0 --port 8081 --workers 1
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

# Cibervault Linux Agent
cat > /etc/systemd/system/cibervault-agent.service << 'AGENTEOF'
[Unit]
Description=Cibervault Linux Agent — Security Telemetry Collector
After=network-online.target cibervault-server.service
Wants=cibervault-server.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/cibervault/cibervault-linux-agent.py
WorkingDirectory=/opt/cibervault
Restart=always
RestartSec=10
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
AGENTEOF

systemctl daemon-reload
systemctl enable cibervault-server cibervault-agent

log "Systemd services created and enabled"

# ══════════════════════════════════════════════════════════════════════
step 9 "Configure Nginx"
# ══════════════════════════════════════════════════════════════════════

NGINX_DOMAIN="${CV_DOMAIN:-$SERVER_IP}"

cat > /etc/nginx/sites-available/cibervault << NGXEOF
server {
    listen 80;
    server_name ${NGINX_DOMAIN};

    location / {
        proxy_pass http://127.0.0.1:${SERVER_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /ws {
        proxy_pass http://127.0.0.1:${SERVER_PORT}/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }

    client_max_body_size 100M;
}
NGXEOF

ln -sf /etc/nginx/sites-available/cibervault /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t 2>/dev/null && systemctl reload nginx

log "Nginx configured for ${NGINX_DOMAIN}"

# TLS with Let's Encrypt
if [[ "$CV_TLS" =~ ^[Yy] ]] && [ -n "$CV_DOMAIN" ]; then
    echo ""
    echo "  Setting up TLS certificate..."
    certbot --nginx -d "$CV_DOMAIN" --non-interactive --agree-tos \
        --register-unsafely-without-email 2>/dev/null && \
        log "TLS certificate installed for $CV_DOMAIN" || \
        warn "TLS setup failed — run manually: certbot --nginx -d $CV_DOMAIN"
fi

# ══════════════════════════════════════════════════════════════════════
step 10 "Install Ollama AI (optional)"
# ══════════════════════════════════════════════════════════════════════

if [[ "$CV_OLLAMA" =~ ^[Yy] ]]; then
    if ! command -v ollama &>/dev/null; then
        echo "  Downloading Ollama..."
        curl -fsSL https://ollama.ai/install.sh | sh 2>/dev/null
        log "Ollama installed"
    else
        log "Ollama already installed"
    fi

    # Start Ollama
    systemctl enable ollama 2>/dev/null
    systemctl start ollama 2>/dev/null
    sleep 3

    # Pull models
    echo "  Pulling AI models (this may take a few minutes)..."
    ollama pull phi3:mini 2>/dev/null && log "phi3:mini model ready" || warn "phi3:mini pull failed — run manually: ollama pull phi3:mini"
    ollama pull qwen2.5-coder:7b 2>/dev/null && log "qwen2.5-coder:7b ready" || warn "qwen2.5-coder pull failed — run manually: ollama pull qwen2.5-coder:7b"
else
    warn "Ollama skipped — AI features will need an API key configured in dashboard"
fi

# ══════════════════════════════════════════════════════════════════════
step 11 "Install .NET 8 SDK (optional)"
# ══════════════════════════════════════════════════════════════════════

if [[ "$CV_DOTNET" =~ ^[Yy] ]]; then
    if ! command -v dotnet &>/dev/null; then
        echo "  Installing .NET 8 SDK..."
        # Ubuntu/Debian
        apt-get install -y -qq dotnet-sdk-8.0 2>/dev/null || {
            # Fallback: Microsoft packages
            wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb
            dpkg -i /tmp/packages-microsoft-prod.deb 2>/dev/null
            apt-get update -qq
            apt-get install -y -qq dotnet-sdk-8.0 2>/dev/null
        }
        log ".NET 8 SDK installed"
    else
        log ".NET SDK already installed: $(dotnet --version)"
    fi

    # Build Windows agent if source exists
    if [ -d "$INSTALL_DIR/agent-source/CibervaultAgent" ]; then
        echo "  Building Windows agent..."
        cd "$INSTALL_DIR/agent-source/CibervaultAgent"
        dotnet publish -c Release -r win-x64 --self-contained -o "$INSTALL_DIR/agent-installer" 2>/dev/null && {
            # Copy installer scripts
            cp "$INSTALL_DIR/agent-source/INSTALL.bat" "$INSTALL_DIR/agent-installer/" 2>/dev/null
            cp "$INSTALL_DIR/agent-source/UNINSTALL.bat" "$INSTALL_DIR/agent-installer/" 2>/dev/null
            # Create download zip
            cd "$INSTALL_DIR/agent-installer"
            zip -r "$INSTALL_DIR/server/static/downloads/CibervaultAgent-installer.zip" \
                CibervaultAgent.exe INSTALL.bat UNINSTALL.bat 2>/dev/null
            cp CibervaultAgent.exe "$INSTALL_DIR/server/static/downloads/" 2>/dev/null
            chown -R cibervault:cibervault "$INSTALL_DIR/server/static/downloads" "$INSTALL_DIR/agent-installer"
            log "Windows agent built and ready for download"
        } || warn "Windows agent build failed — run manually: bash /opt/cibervault/agent-source/build-agent.sh"
    fi
else
    warn ".NET SDK skipped — Windows agent must be built separately"
fi

# ══════════════════════════════════════════════════════════════════════
step 12 "Start services"
# ══════════════════════════════════════════════════════════════════════

# Configure fail2ban
systemctl enable fail2ban
systemctl start fail2ban
log "fail2ban started"

# Start Cibervault
systemctl start cibervault-server
sleep 3

if systemctl is-active --quiet cibervault-server; then
    log "Cibervault server RUNNING"
else
    err "Server failed to start — check: journalctl -u cibervault-server -n 30"
fi

# Start Linux agent
systemctl start cibervault-agent
sleep 3

if systemctl is-active --quiet cibervault-agent; then
    log "Linux agent RUNNING"
else
    warn "Linux agent not running — check: journalctl -u cibervault-agent -n 20"
fi

# ══════════════════════════════════════════════════════════════════════
#  DONE
# ══════════════════════════════════════════════════════════════════════

# Determine access URL
if [ -n "$CV_DOMAIN" ]; then
    ACCESS_URL="https://${CV_DOMAIN}"
else
    ACCESS_URL="http://${SERVER_IP}"
fi

echo ""
echo -e "${CYAN}  ╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}  ║${NC}                                                        ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   ${GREEN}${BOLD}✅ INSTALLATION COMPLETE${NC}                              ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}                                                        ${CYAN}║${NC}"
echo -e "${CYAN}  ╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}  ║${NC}                                                        ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   ${BOLD}Dashboard:${NC}  ${ACCESS_URL}                 ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   ${BOLD}Username:${NC}   admin                                    ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   ${BOLD}Password:${NC}   (the one you entered)                    ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}                                                        ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   ${BOLD}Services:${NC}                                            ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   • cibervault-server  (port ${SERVER_PORT})                    ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   • cibervault-agent   (local telemetry)               ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   • nginx              (reverse proxy)                 ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   • fail2ban           (SSH protection)                ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}                                                        ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   ${BOLD}Agent Secret:${NC}                                        ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   ${AGENT_SECRET:0:32}...  ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   (also in Dashboard → Settings)                       ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}                                                        ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   ${BOLD}Windows Agent:${NC}                                       ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   Download: ${ACCESS_URL}/static/downloads/             ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}                                                        ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   ${BOLD}Linux Agent (other servers):${NC}                          ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   cd linux-agent-installer && sudo bash install.sh      ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}                                                        ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   ${BOLD}Wazuh Integration:${NC}                                   ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   Add to /var/ossec/etc/ossec.conf:                     ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   hook_url: http://SERVER:${SERVER_PORT}/api/v1/wazuh/alert    ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}                                                        ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   ${BOLD}Management:${NC}                                          ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   Status:  systemctl status cibervault-server           ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   Logs:    journalctl -u cibervault-server -f           ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}   Agent:   systemctl status cibervault-agent            ${CYAN}║${NC}"
echo -e "${CYAN}  ║${NC}                                                        ${CYAN}║${NC}"
echo -e "${CYAN}  ╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
