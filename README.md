# Vouch

**Lightweight device attestation for Tailscale networks**

Vouch adds device posture checks to your Tailscale network without requiring Enterprise. Devices continuously attest their security posture (OS patches, encryption, services) and non-compliant devices are automatically denied access.

## Why Vouch?

- 🔒 **Zero-trust enforcement** - Only healthy devices access your services
- 🎯 **Custom policies** - Define your own compliance rules
- ⚡ **Lightweight** - <10MB agents, minimal overhead
- 🔌 **Tailscale-native** - Integrates via ACL API
- 🏠 **Self-hosted** - Full control, no SaaS required

## Quick Start

### One-Line Install (Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/haasonsaas/vouch/main/install.sh | sh
```

### Or Download Binary

Download the latest release for your platform:

**Latest Release:** [Releases](https://github.com/haasonsaas/vouch/releases/latest)

```bash
# Linux AMD64
wget https://github.com/haasonsaas/vouch/releases/latest/download/vouch-agent-linux-amd64
chmod +x vouch-agent-linux-amd64
sudo mv vouch-agent-linux-amd64 /usr/local/bin/vouch-agent

# macOS ARM64 (Apple Silicon)
wget https://github.com/haasonsaas/vouch/releases/latest/download/vouch-agent-darwin-arm64
chmod +x vouch-agent-darwin-arm64
sudo mv vouch-agent-darwin-arm64 /usr/local/bin/vouch-agent
```

### Docker

```bash
# Server
docker pull ghcr.io/haasonsaas/vouch-server:latest

# Agent
docker pull ghcr.io/haasonsaas/vouch-agent:latest

# Run with docker-compose
docker-compose up -d
```

## Usage

### Start Server

```bash
vouch-server --policy policies.yaml --listen :8080
```

### Start Agent

```bash
vouch-agent --server http://vouch-server:8080 --interval 5m
```

### Check Status

```bash
vouch status          # Overall compliance
vouch devices         # List all devices
vouch device hostname # Device details
```

## Configuration

### Policy Example

```yaml
# policies.yaml
rules:
  - name: require-recent-updates
    check: update_age_days < 30
    action: deny
    
  - name: require-encryption
    check: disk_encrypted == true
    action: deny
    
  - name: block-outdated-kernel
    check: kernel_version >= "6.0"
    action: deny
```

### Enable Enforcement

```bash
vouch-server \
  --policy policies.yaml \
  --enforce \
  --tailscale-api-key $TAILSCALE_API_KEY \
  --tailnet example.com
```

## Building from Source

```bash
git clone https://github.com/haasonsaas/vouch
cd vouch
make build

# Binaries in bin/
./bin/vouch-server --help
./bin/vouch-agent --help
./bin/vouch --help
```

## Architecture

```
Device Agents → Control Plane → Enforcement
    ↓              ↓                ↓
  Posture        Policy           Tailscale ACLs
  Collection     Evaluation       Firewall Rules
                                  Service Auth
```

## Features

- ✅ OS update age tracking
- ✅ Disk encryption detection
- ✅ Kernel version enforcement
- ✅ Service monitoring
- ✅ Real-time compliance status
- ✅ Tailscale ACL integration
- ✅ REST API
- 🚧 Web UI (planned)
- 🚧 Windows agent (planned)
- 🚧 EDR integration (planned)

## API

### Report Posture

```bash
curl -X POST http://localhost:8080/v1/report \
  -H "Content-Type: application/json" \
  -d '{
    "node_id": "n123",
    "hostname": "dev-laptop",
    "os_release": "Ubuntu 24.04",
    "kernel": "6.8.0-47",
    "last_update_time": 1729123456,
    "disk_encrypted": true
  }'
```

### List Devices

```bash
curl http://localhost:8080/v1/devices
```

### Get Device Status

```bash
curl http://localhost:8080/v1/devices/dev-laptop
```

## Use Cases

- **Homelab Security** - Enforce patch levels before accessing services
- **Remote Work** - Verify device compliance for employee machines
- **IoT Fleet** - Track firmware versions across devices
- **ML Infrastructure** - Ensure GPU workstations meet baselines

## CI/CD

Vouch uses GitHub Actions for automated releases:

- **Push tag** → Automatic build for Linux/macOS (amd64/arm64)
- **Docker images** → Published to `ghcr.io/haasonsaas/vouch-{server,agent}`
- **Release notes** → Auto-generated from commits

To create a release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Contributing

Contributions welcome! Please open an issue first to discuss changes.

## License

Apache 2.0

## Status

🚧 **Early Development** - Core functionality working, not production-ready yet

---

Built for zero-trust homelabs and small teams who need BeyondCorp-style security without the enterprise price tag.
