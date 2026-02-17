#!/usr/bin/env bash
# uninstall.sh — remove pulld from the system
set -euo pipefail

GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"; BOLD="\033[1m"; RESET="\033[0m"
ok()   { echo -e "${GREEN}✓${RESET}  $*"; }
warn() { echo -e "${YELLOW}!${RESET}  $*"; }
fail() { echo -e "${RED}✗${RESET}  $*" >&2; exit 1; }

[[ "$EUID" -eq 0 ]] || fail "Please run as root: sudo bash uninstall.sh"

echo -e "\n${BOLD}Uninstalling pulld...${RESET}\n"

# Stop and disable service
if systemctl is-active --quiet pulld 2>/dev/null; then
    systemctl stop pulld
    ok "Service stopped"
fi
if systemctl is-enabled --quiet pulld 2>/dev/null; then
    systemctl disable pulld
    ok "Service disabled"
fi

# Remove files
rm -f /etc/systemd/system/pulld.service
rm -f /usr/local/bin/pulld
rm -f /usr/local/bin/pullctl
ok "Binaries and service file removed"

systemctl daemon-reload

# Ask about data directories
echo ""
read -rp "  Remove config and deploy scripts? (/etc/pulld) [y/N] " REMOVE_CONF
if [[ "${REMOVE_CONF,,}" == "y" ]]; then
    rm -rf /etc/pulld
    ok "/etc/pulld removed"
fi

read -rp "  Remove deploy logs? (/var/log/pulld) [y/N] " REMOVE_LOGS
if [[ "${REMOVE_LOGS,,}" == "y" ]]; then
    rm -rf /var/log/pulld
    ok "/var/log/pulld removed"
fi

rm -rf /usr/share/pulld
rm -rf /run/pulld

echo ""
ok "pulld uninstalled."
echo ""
