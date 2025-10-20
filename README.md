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

### 1. Clone and Build

```bash
git clone https://github.com/haasonsaas/vouch
cd vouch
make build
```

### 2. Start Server

```bash
./bin/vouch-server --policy policies.example.yaml
```

### 3. Start Agent

```bash
./bin/vouch-agent --server http://localhost:8080 --interval 5m
```

### 4. Check Status

```bash
./bin/vouch status
./bin/vouch devices
```

## Docker Deployment

```bash
# Build images
docker build -t vouch-server -f Dockerfile.server .
docker build -t vouch-agent -f Dockerfile.agent .

# Run with docker-compose
docker-compose up -d
```

## Configuration

### Policies

Define compliance rules in YAML:

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

### Server

```bash
vouch-server \
  --listen :8080 \
  --policy policies.yaml \
  --db vouch.db \
  --enforce \
  --tailscale-api-key tskey-api-xxx \
  --tailnet example.com
```

### Agent

```bash
vouch-agent \
  --server http://vouch-server:8080 \
  --interval 5m
```

## CLI Commands

```bash
# Show overall compliance status
vouch status

# List all devices
vouch devices

# Show device details
vouch device hostname

# Manual enforcement
vouch enforce hostname
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
- 🚧 Windows agent (planned)

## Collected Metrics

- OS version & patch level
- Kernel version
- Last update timestamp
- Disk encryption status
- Running services
- Tailscale node ID

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

## Building

### Requirements
- Go 1.21+
- Docker (for container builds)
- CGO enabled for SQLite

### Local Build

```bash
make build
```

### Cross-Platform Build (Docker)

```bash
make docker
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

## Security Considerations

- Agent-server communication should use TLS
- Store Tailscale API keys in environment variables
- Rotate API keys regularly
- Audit policy changes
- Monitor for agent tampering

## Contributing

Contributions welcome! Please open an issue first to discuss changes.

## License

Apache 2.0 - See [LICENSE](LICENSE)

## Status

🚧 **Early Development** - Core functionality implemented, not production-ready yet

## Roadmap

- [ ] v0.1: Core agent + server + basic policies ✅
- [ ] v0.2: Tailscale ACL integration ✅
- [ ] v0.3: Web UI for device management
- [ ] v0.4: Windows agent support
- [ ] v0.5: EDR integration (CrowdStrike, etc.)
- [ ] v1.0: Production-ready release

---

Built for zero-trust homelabs and small teams who need BeyondCorp-style security without the enterprise price tag.
