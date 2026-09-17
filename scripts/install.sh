#!/usr/bin/env bash
# ==============================================================================
# Phylax (φύλαξ) — Sovereign Edge Defense Automated Installer
# Supports: Linux (Ubuntu/Debian, CentOS/RHEL/Fedora, Arch, Alpine) and macOS
# ==============================================================================
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}${BOLD}"
cat << "EOF"
  ██████╗ ██╗  ██╗██╗   ██╗██╗      █████╗ ██╗  ██╗
  ██╔══██╗██║  ██║╚██╗ ██╔╝██║     ██╔══██╗╚██╗██╔╝
  ██████╔╝███████║ ╚████╔╝ ██║     ███████║ ╚███╔╝ 
  ██╔═══╝ ██╔══██║  ╚██╔╝  ██║     ██╔══██║ ██╔██╗ 
  ██║     ██║  ██║   ██║   ███████╗██║  ██║██╔╝ ██╗
  ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
  Sovereign Zero-Telemetry WAF & Edge Defense Daemon
EOF
echo -e "${NC}"

OS="$(uname -s)"
ARCH="$(uname -m)"

echo -e "🔍 Detected Environment: ${BOLD}${OS} (${ARCH})${NC}"

# Determine target binary directory
if [ "$(id -u)" -eq 0 ]; then
    BIN_DIR="/usr/local/bin"
    CONFIG_DIR="/etc/phylax"
else
    BIN_DIR="${HOME}/.local/bin"
    CONFIG_DIR="${HOME}/.config/phylax"
fi

mkdir -p "${BIN_DIR}"
mkdir -p "${CONFIG_DIR}"

# Determine installation source: local repo vs git clone
if [ -f "Cargo.toml" ] && grep -q 'name = "phylax"' Cargo.toml; then
    echo -e "📦 Building from local repository source..."
    cargo build --release --features cli
    cp -f "target/release/phylax" "${BIN_DIR}/phylax"
else
    echo -e "🌐 Installing latest release via Cargo from GitHub..."
    if ! command -v cargo &> /dev/null; then
        echo -e "${RED}❌ Rust/Cargo is required for source installation.${NC}"
        echo -e "   Please install Rust via https://rustup.rs or install a prebuilt binary."
        exit 1
    fi
    cargo install --git https://github.com/xuoxod/phylax.git --features cli --root "${BIN_DIR}/.."
    if [ -f "${BIN_DIR}/../bin/phylax" ]; then
        mv -f "${BIN_DIR}/../bin/phylax" "${BIN_DIR}/phylax"
    fi
fi

chmod +x "${BIN_DIR}/phylax"
echo -e "${GREEN}✅ Installed binary to: ${BOLD}${BIN_DIR}/phylax${NC}"

# Generate default configuration if not present
CONFIG_FILE="${CONFIG_DIR}/phylax.toml"
if [ ! -f "${CONFIG_FILE}" ]; then
    echo -e "⚙️  Generating production configuration template: ${CONFIG_FILE}"
    "${BIN_DIR}/phylax" init --output "${CONFIG_FILE}"
else
    echo -e "ℹ️  Existing configuration preserved at: ${CONFIG_FILE}"
fi

# Linux systemd integration (if root and systemd present)
if [ "${OS}" = "Linux" ] && [ "$(id -u)" -eq 0 ] && command -v systemctl &> /dev/null; then
    SERVICE_FILE="/etc/systemd/system/phylax.service"
    echo -e "⚙️  Configuring systemd service unit: ${SERVICE_FILE}"
    cat << EOF > "${SERVICE_FILE}"
[Unit]
Description=Phylax Sovereign Edge Defense & Reverse Proxy WAF
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_DIR}/phylax serve --config ${CONFIG_FILE}
Restart=always
RestartSec=3
LimitNOFILE=65536
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo -e "${GREEN}✅ systemd service registered.${NC}"
    echo -e "   To start and enable on boot:"
    echo -e "     ${BOLD}systemctl enable --now phylax${NC}"
fi

# Ensure PATH includes installation directory
if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
    echo -e "${YELLOW}⚠️  Note: ${BIN_DIR} is not currently in your \$PATH.${NC}"
    echo -e "   Add it by running:"
    echo -e "     ${BOLD}export PATH=\"${BIN_DIR}:\$PATH\"${NC}"
fi

echo -e "\n${GREEN}${BOLD}🎉 Phylax installation complete!${NC}"
echo -e "Quick Start Options:"
echo -e "  1. Test CLI operations:   ${BOLD}phylax --help${NC}"
echo -e "  2. Run microbenchmarks:    ${BOLD}phylax bench${NC}"
echo -e "  3. Start WAF reverse proxy: ${BOLD}phylax serve --upstream http://127.0.0.1:8080 --listen 0.0.0.0:3000${NC}\n"
