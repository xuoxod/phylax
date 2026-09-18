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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -x "${SCRIPT_DIR}/phylax-service.sh" ]; then
    "${SCRIPT_DIR}/phylax-service.sh" uninstall 2>/dev/null || true
elif command -v systemctl &> /dev/null; then
    sudo systemctl stop phylax 2>/dev/null || true
    sudo systemctl disable phylax 2>/dev/null || true
    sudo rm -f /etc/systemd/system/phylax.service
    sudo systemctl daemon-reload 2>/dev/null || true
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
