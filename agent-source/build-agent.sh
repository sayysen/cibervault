#!/bin/bash
# ================================================================
# Cibervault Agent - Build, Register & Serve
# Usage: sudo bash /opt/cibervault/agent-source/build-agent.sh
#
# This script:
#   1. Builds the C# agent from source
#   2. Prepares the installer folder (exe + bat files)
#   3. Creates a downloadable zip
#   4. Auto-registers the binary in the Cibervault database
#   5. Makes it available in Dashboard > Settings > Agent Binaries
# ================================================================
set -e

GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log() { echo -e "${GREEN}[OK]${NC} $1"; }

SRC="/opt/cibervault/agent-source/CibervaultAgent"
INSTALLER="/opt/cibervault/agent-installer"
BINARIES="/opt/cibervault/agent-binaries"
DB="/opt/cibervault/data/cibervault.db"
DOWNLOADS="/opt/cibervault/server/static/downloads"

echo ""
echo -e "${CYAN}  ================================================${NC}"
echo -e "${CYAN}    Cibervault Agent - Build & Register${NC}"
echo -e "${CYAN}  ================================================${NC}"
echo ""

# ── Step 1: Build ──────────────────────────────────────────────
echo "  [1/5] Building agent..."
cd "$SRC"
dotnet publish -c Release -r win-x64 --self-contained -o "$INSTALLER" 2>&1 | tail -3
log "Build complete"

# ── Step 2: Copy installer scripts ────────────────────────────
echo "  [2/5] Preparing installer..."
cp /opt/cibervault/agent-source/INSTALL.bat "$INSTALLER/" 2>/dev/null || true
cp /opt/cibervault/agent-source/UNINSTALL.bat "$INSTALLER/" 2>/dev/null || true
log "Installer prepared at $INSTALLER/"

# ── Step 3: Get version and hash ──────────────────────────────
echo "  [3/5] Computing metadata..."
VERSION=$(grep -oP 'VERSION\s*=\s*"[^"]+"' "$SRC/Program.cs" | grep -oP '"[^"]+"' | tr -d '"' | head -1)
if [ -z "$VERSION" ]; then VERSION="3.0.0"; fi
SHA256=$(sha256sum "$INSTALLER/CibervaultAgent.exe" | cut -d' ' -f1)
FILESIZE=$(stat -c%s "$INSTALLER/CibervaultAgent.exe")
FILESIZE_MB=$(echo "scale=1; $FILESIZE / 1048576" | bc)
BINARY_ID="bin-$(date +%Y%m%d%H%M%S)"
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

log "Version: $VERSION | Size: ${FILESIZE_MB}MB | SHA256: ${SHA256:0:16}..."

# ── Step 4: Create downloadable zip ───────────────────────────
echo "  [4/5] Creating download packages..."
mkdir -p "$DOWNLOADS" "$BINARIES"

# Copy exe to binaries dir
cp "$INSTALLER/CibervaultAgent.exe" "$BINARIES/CibervaultAgent-${VERSION}.exe"

# Create installer zip
cd "$INSTALLER"
zip -r "$DOWNLOADS/CibervaultAgent-installer.zip" CibervaultAgent.exe INSTALL.bat UNINSTALL.bat 2>/dev/null | tail -1

# Also copy standalone exe to downloads
cp "$INSTALLER/CibervaultAgent.exe" "$DOWNLOADS/CibervaultAgent.exe"

chown -R cibervault:cibervault "$DOWNLOADS" "$BINARIES" "$INSTALLER"
log "Downloads ready at /static/downloads/"

# ── Step 5: Register in database ──────────────────────────────
echo "  [5/5] Registering in dashboard..."

# Deactivate previous active binary
sqlite3 "$DB" "UPDATE agent_binaries SET is_active=0 WHERE is_active=1;" 2>/dev/null || true

# Insert new binary record
sqlite3 "$DB" "INSERT OR REPLACE INTO agent_binaries
    (binary_id, filename, version, platform, file_size, sha256, uploaded_by, uploaded_at, notes, is_active)
    VALUES
    ('${BINARY_ID}', 'CibervaultAgent.exe', '${VERSION}', 'win-x64', ${FILESIZE}, '${SHA256}', 'build-script', '${NOW}', 'Auto-built from source', 1);" 2>/dev/null

if [ $? -eq 0 ]; then
    log "Registered as ACTIVE binary in dashboard"
else
    echo "  [!!] Could not register in DB (table may not exist yet)"
    echo "       Run: sudo bash /opt/cibervault/agent-source/deploy-agent-updates.sh first"
fi

# ── Done ──────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}  ================================================${NC}"
echo -e "${GREEN}    BUILD COMPLETE${NC}"
echo -e "${CYAN}  ================================================${NC}"
echo ""
echo "  Version:       $VERSION"
echo "  SHA256:        ${SHA256:0:32}..."
echo "  Size:          ${FILESIZE_MB} MB"
echo ""
echo "  Files:"
echo "    EXE:         $INSTALLER/CibervaultAgent.exe"
echo "    Installer:   $DOWNLOADS/CibervaultAgent-installer.zip"
echo "    Binary:      $BINARIES/CibervaultAgent-${VERSION}.exe"
echo ""
echo "  Download from dashboard:"
echo "    https://edr.cibervault.com/static/downloads/CibervaultAgent-installer.zip"
echo "    https://edr.cibervault.com/static/downloads/CibervaultAgent.exe"
echo ""
echo "  Or push from: Dashboard > Settings > Agent Binaries > Push Updates"
echo ""
