#!/usr/bin/env bash
# install.sh — pulld installer
# Run as root: sudo bash install.sh
set -euo pipefail

# ──────────────────────────────────────────────────────────────────
# Terminal helpers
# ──────────────────────────────────────────────────────────────────
BOLD="\033[1m"; RESET="\033[0m"
GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"; CYAN="\033[96m"; DIM="\033[2m"

ok()   { echo -e "${GREEN}✓${RESET}  $*"; }
fail() { echo -e "${RED}✗${RESET}  $*" >&2; exit 1; }
warn() { echo -e "${YELLOW}!${RESET}  $*"; }
info() { echo -e "\033[94m→${RESET}  $*"; }
step() { echo -e "\n${BOLD}${CYAN}── $* ${RESET}"; }

# ──────────────────────────────────────────────────────────────────
# Pre-flight checks
# ──────────────────────────────────────────────────────────────────
step "Pre-flight checks"

[[ "$EUID" -eq 0 ]] || fail "Please run as root: sudo bash install.sh"

python3 --version &>/dev/null || fail "python3 is required but not found"
git --version     &>/dev/null || fail "git is required but not found"
ok "python3 found: $(python3 --version)"
ok "git found: $(git --version)"

# Verify Python 3.7+ for ThreadingHTTPServer
PY_VER=$(python3 -c "import sys; print(sys.version_info >= (3,7))")
[[ "$PY_VER" == "True" ]] || fail "Python 3.7 or newer is required"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ──────────────────────────────────────────────────────────────────
# Directories
# ──────────────────────────────────────────────────────────────────
step "Creating directories"

install -d -m 755 /etc/pulld
install -d -m 755 /etc/pulld/deploy
install -d -m 755 /var/log/pulld
install -d -m 755 /run/pulld
install -d -m 755 /usr/share/pulld/templates

ok "Directories created"

# ──────────────────────────────────────────────────────────────────
# Install files
# ──────────────────────────────────────────────────────────────────
step "Installing files"

install -m 755 "$SCRIPT_DIR/pulld.py"  /usr/local/bin/pulld
install -m 755 "$SCRIPT_DIR/pullctl"   /usr/local/bin/pullctl
ok "pulld   → /usr/local/bin/pulld"
ok "pullctl → /usr/local/bin/pullctl"

# Install deploy script templates
if [[ -d "$SCRIPT_DIR/templates" ]]; then
    cp "$SCRIPT_DIR"/templates/*.sh /usr/share/pulld/templates/
    chmod 644 /usr/share/pulld/templates/*.sh
    ok "Templates  → /usr/share/pulld/templates/"
fi

# Install systemd service
install -m 644 "$SCRIPT_DIR/pulld.service" /etc/systemd/system/pulld.service
ok "Service    → /etc/systemd/system/pulld.service"

# ──────────────────────────────────────────────────────────────────
# Initial config (only if it doesn't exist — preserve existing config)
# ──────────────────────────────────────────────────────────────────
step "Configuration"

if [[ ! -f /etc/pulld/config.json ]]; then
    cat > /etc/pulld/config.json <<'EOF'
{
  "_host": "0.0.0.0",
  "_port": 9000
}
EOF
    chmod 600 /etc/pulld/config.json
    ok "Created default config: /etc/pulld/config.json"
else
    warn "Config already exists — keeping it unchanged: /etc/pulld/config.json"
fi

# ──────────────────────────────────────────────────────────────────
# Firewall hint (ufw)
# ──────────────────────────────────────────────────────────────────
if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    echo ""
    warn "ufw is active. Incoming webhook traffic needs port 9000 open."
    read -rp "    Allow port 9000 through ufw now? [y/N] " UFW_ANSWER
    if [[ "${UFW_ANSWER,,}" == "y" ]]; then
        ufw allow 9000/tcp comment "pulld"
        ok "ufw: port 9000 allowed"
    else
        warn "Skipped. Run manually if needed: sudo ufw allow 9000/tcp"
    fi
fi

# ──────────────────────────────────────────────────────────────────
# Enable and start service
# ──────────────────────────────────────────────────────────────────
step "Enabling service"

systemctl daemon-reload
systemctl enable pulld
systemctl restart pulld

# ── Wait for the daemon to actually come up ───────────────────────
# systemctl restart returns immediately — we need to poll the /health
# endpoint to confirm the process has bound its port and is responding.
PORT=$(python3 -c "
import json
try:
    cfg = json.load(open('/etc/pulld/config.json'))
    print(cfg.get('_port', 9000))
except: print(9000)
")

info "Waiting for pulld to come up on port ${PORT}..."

ATTEMPTS=8
HEALTHY=0
for i in $(seq 1 $ATTEMPTS); do
    sleep 1
    RESPONSE=$(curl -sf "http://127.0.0.1:${PORT}/health" 2>/dev/null || true)
    if echo "$RESPONSE" | grep -q "pulld"; then
        HEALTHY=1
        break
    fi
done

if [[ "$HEALTHY" -eq 1 ]]; then
    ok "pulld is running and healthy"
else
    echo ""
    echo -e "${RED}✗${RESET}  pulld did not respond after ${ATTEMPTS}s — something went wrong." >&2
    echo ""
    echo -e "  ${BOLD}Last log entries:${RESET}"
    echo -e "  ${DIM}─────────────────────────────────────────────────${RESET}"
    journalctl -u pulld -n 15 --no-pager 2>/dev/null | sed 's/^/  /' || true
    echo ""
    warn "Fix the issue above, then run: sudo systemctl restart pulld"
    warn "To change the port:            sudo pullctl config --port <PORT>"
    # Don't exit — files are installed correctly, only startup failed
fi

# ──────────────────────────────────────────────────────────────────
# Done
# ──────────────────────────────────────────────────────────────────
SERVER_IP=$(python3 -c "
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    print(s.getsockname()[0])
    s.close()
except: print('YOUR_SERVER_IP')
")

echo ""
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  pulld installed successfully!${RESET}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "  Health check:  ${BOLD}curl http://${SERVER_IP}:9000/health${RESET}"
echo ""
echo -e "  Register your first project:"
echo -e "  ${BOLD}pullctl add my-app --path /srv/my-app${RESET}"
echo ""
echo -e "  ${DIM}Logs:    journalctl -u pulld -f${RESET}"
echo -e "  ${DIM}Status:  pullctl status${RESET}"
echo ""
