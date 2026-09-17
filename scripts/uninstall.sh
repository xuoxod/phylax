#!/usr/bin/env bash
# ==============================================================================
# Phylax (φύλαξ) — Uninstaller
# ==============================================================================
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BOLD}🧹 Phylax Uninstaller${NC}"

# Stop and remove systemd service if present
if command -v systemctl &> /dev/null && systemctl is-active --quiet phylax 2>/dev/null; then
    echo "Stopping phylax systemd service..."
    sudo systemctl stop phylax
    sudo systemctl disable phylax
    sudo rm -f /etc/systemd/system/phylax.service
    sudo systemctl daemon-reload
    echo "Removed systemd service."
fi

# Remove logrotate configuration if present
if [ -f "/etc/logrotate.d/phylax" ]; then
    sudo rm -f "/etc/logrotate.d/phylax"
    echo "Removed /etc/logrotate.d/phylax"
fi

# Remove binaries
if [ -f "/usr/local/bin/phylax" ]; then
    sudo rm -f "/usr/local/bin/phylax"
    echo "Removed /usr/local/bin/phylax"
fi

if [ -f "${HOME}/.local/bin/phylax" ]; then
    rm -f "${HOME}/.local/bin/phylax"
    echo "Removed ${HOME}/.local/bin/phylax"
fi

if [ -f "${HOME}/.cargo/bin/phylax" ]; then
    rm -f "${HOME}/.cargo/bin/phylax"
    echo "Removed ${HOME}/.cargo/bin/phylax"
fi

echo -e "${GREEN}✅ Phylax binaries and services successfully removed.${NC}"
echo -e "Note: Configuration files at /etc/phylax or ~/.config/phylax were preserved."
