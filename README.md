# Vouch

**Lightweight device attestation for Tailscale networks**

Vouch adds device posture checks to your Tailscale network without requiring Enterprise. Devices continuously attest their security posture (OS patches, encryption, services) and non-compliant devices are automatically denied access.

## Why Vouch?

- 🔒 **Zero-trust enforcement** - Only healthy devices access your services
- 🎯 **Custom policies** - Define your own compliance rules
- ⚡ **Lightweight** - <10MB agents, minimal overhead
- 🔌 **Tailscale-native** - Integrates via ACL API
- 🏠 **Self-hosted** - Full control, no SaaS required

## Architecture

```
Device Agents → Control Plane → Enforcement
    ↓              ↓                ↓
  Posture        Policy           Tailscale ACLs
  Collection     Evaluation       Firewall Rules
                                  Service Auth
```

## Quick Start

### 1. Deploy Control Plane

```bash
docker run -d \
  -p 8080:8080 \
  -v ./policies.yaml:/etc/vouch/policies.yaml \
  ghcr.io/haasonsaas/vouch-server:latest
```

### 2. Install Agent on Devices

```bash
curl -fsSL https://vouch.dev/install.sh | sh
vouch-agent --server https://vouch.example.com:8080
```

### 3. Define Policies

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

## Features

- ✅ OS update age tracking
- ✅ Disk encryption detection
- ✅ Kernel version enforcement
- ✅ Service allowlist/blocklist
- ✅ Real-time compliance status
- ✅ Tailscale ACL auto-update
- ✅ Webhook notifications
- 🚧 EDR integration (planned)
- 🚧 Certificate validation (planned)

## Components

### Agent (`vouch-agent`)
Runs on each device, collects posture data, reports to control plane.

**Collected Metrics:**
- OS version & patch level
- Kernel version
- Last update timestamp
- Disk encryption status
- Running services
- Tailscale node ID

### Control Plane (`vouch-server`)
Evaluates policies, maintains device state, enforces compliance.

**Capabilities:**
- Policy engine with custom rules
- Device state database
- Tailscale API integration
- REST API for queries
- Metrics & alerting

### CLI (`vouch`)
Management interface for policies and device status.

```bash
vouch status              # Show all device compliance
vouch policy add [file]   # Add policy
vouch device [hostname]   # Device details
vouch enforce             # Manually trigger enforcement
```

## Use Cases

### Homelab Security
Ensure dev machines are patched before accessing production services.

### Remote Work
Enforce company security standards on employee devices.

### IoT Fleet Management
Verify firmware versions and configurations across devices.

### ML Infrastructure
Ensure GPU workstations meet security baselines before training jobs.

## Installation

### Requirements
- Tailscale network
- Docker (for control plane) or binary deployment
- Tailscale API key with ACL write access

### From Source

```bash
git clone https://github.com/haasonsaas/vouch
cd vouch
make build
./bin/vouch-server --config config.yaml
```

## Configuration

### Control Plane

```yaml
# config.yaml
server:
  listen: "0.0.0.0:8080"
  tls:
    cert: /etc/vouch/tls.crt
    key: /etc/vouch/tls.key

tailscale:
  api_key: "tskey-api-..."
  tailnet: "example.com"
  
database:
  type: sqlite
  path: /var/lib/vouch/devices.db

policies:
  file: /etc/vouch/policies.yaml
  reload_interval: 60s
```

### Agent

```bash
# /etc/vouch/agent.conf
server_url=https://vouch.example.com:8080
report_interval=5m
node_id=$(tailscale status --json | jq -r '.Self.ID')
```

## API

### Report Device Posture
```http
POST /v1/report
Content-Type: application/json

{
  "node_id": "n1234...",
  "hostname": "dev-laptop",
  "posture": {
    "os_release": "Ubuntu 24.04",
    "kernel": "6.8.0-47",
    "last_update": 1729123456,
    "disk_encrypted": true
  }
}
```

### Query Device Status
```http
GET /v1/devices/{hostname}

Response:
{
  "hostname": "dev-laptop",
  "compliant": true,
  "last_seen": "2024-10-20T02:00:00Z",
  "violations": []
}
```

## Security Considerations

- Agent-server communication should use mTLS
- Store Tailscale API keys in secure vault
- Rotate API keys regularly
- Audit policy changes
- Monitor agent tampering

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## License

Apache 2.0 - See [LICENSE](LICENSE)

## Roadmap

- [ ] v0.1: Core agent + server + basic policies
- [ ] v0.2: Tailscale ACL integration
- [ ] v0.3: Web UI for device management
- [ ] v0.4: Windows agent support
- [ ] v0.5: EDR integration (CrowdStrike, etc.)
- [ ] v1.0: Production-ready release

## Credits

Built with ❤️ for zero-trust homelabs and small teams who need BeyondCorp-style security without the enterprise price tag.

---

**Status**: 🚧 Early development - not production ready yet
