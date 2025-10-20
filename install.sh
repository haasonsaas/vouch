#!/bin/bash
set -e

VERSION="${VOUCH_VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="/etc/vouch"
SYSTEMD_DIR="/etc/systemd/system"

echo "Installing Vouch Agent ${VERSION}..."

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)
        OS="linux"
        ;;
    Darwin)
        OS="darwin"
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Download binary
DOWNLOAD_URL="https://github.com/haasonsaas/vouch/releases/download/${VERSION}/vouch-agent-${OS}-${ARCH}"
echo "Downloading from ${DOWNLOAD_URL}..."
curl -fsSL "$DOWNLOAD_URL" -o /tmp/vouch-agent

# Install binary
chmod +x /tmp/vouch-agent
sudo mv /tmp/vouch-agent "${INSTALL_DIR}/vouch-agent"

echo "✅ Binary installed to ${INSTALL_DIR}/vouch-agent"

# Create config directory
sudo mkdir -p "$CONFIG_DIR"

# Create config file if it doesn't exist
if [ ! -f "$CONFIG_DIR/agent.conf" ]; then
    cat <<EOF | sudo tee "$CONFIG_DIR/agent.conf" > /dev/null
# Vouch Agent Configuration
SERVER_URL=http://localhost:8080
REPORT_INTERVAL=5m
EOF
    echo "✅ Config created at ${CONFIG_DIR}/agent.conf"
fi

# Install systemd service (Linux only)
if [ "$OS" = "linux" ] && [ -d "$SYSTEMD_DIR" ]; then
    cat <<EOF | sudo tee "${SYSTEMD_DIR}/vouch-agent.service" > /dev/null
[Unit]
Description=Vouch Agent - Device Attestation
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${CONFIG_DIR}/agent.conf
ExecStart=${INSTALL_DIR}/vouch-agent --server \${SERVER_URL} --interval \${REPORT_INTERVAL}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    echo "✅ Systemd service installed"
    echo ""
    echo "To start the agent:"
    echo "  sudo systemctl enable --now vouch-agent"
    echo ""
    echo "To check status:"
    echo "  sudo systemctl status vouch-agent"
fi

echo ""
echo "Installation complete!"
echo ""
echo "Next steps:"
echo "1. Update ${CONFIG_DIR}/agent.conf with your server URL"
echo "2. Start the agent: sudo systemctl start vouch-agent"

# Auto-detect latest version from GitHub
if [ "$VERSION" = "latest" ]; then
    VERSION=$(curl -s https://api.github.com/repos/haasonsaas/vouch/releases/latest | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$VERSION" ]; then
        echo "Failed to detect latest version"
        exit 1
    fi
    echo "Latest version: $VERSION"
fi
