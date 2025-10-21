# Vouch

Device posture attestation for Tailscale networks. Continuously monitors device security state and enforces compliance via ACLs.

## What it does

Agents run on each device and report security posture to a central server:
- OS update status (last update time, auto-update enabled, pending updates)
- Disk encryption (LUKS, FileVault, BitLocker)
- Firewall status (ufw, iptables, nftables, Windows Defender)
- Tailscale client health (version, auto-update, online status)
- Secure Boot and TPM presence
- System health (time sync, tailscaled running)

Server evaluates posture against policies and optionally updates Tailscale ACL tags to enforce access control.

## Installation

### Server

```bash
# Binary
wget https://github.com/haasonsaas/vouch/releases/latest/download/vouch-server-linux-amd64
chmod +x vouch-server-linux-amd64
./vouch-server-linux-amd64 -policy policies.yaml -listen :8080

# With external API for Keep integration
./vouch-server-linux-amd64 \
  -policy policies.yaml \
  -listen :8080 \
  -enable-external-query \
  -external-api-key "vouch_ak_your_api_key"

# Docker
docker run -d -p 8080:8080 \
  -v ./policies.yaml:/etc/vouch/policies.yaml \
  ghcr.io/haasonsaas/vouch-server:latest
```

### Agent

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/haasonsaas/vouch/main/install.sh | sh

# Enroll (one-time)
vouch-agent --enroll <token> --server http://vouch-server:8080

# Start
systemctl enable --now vouch-agent
```

## Configuration

### Policy Example

```yaml
# policies.yaml
rules:
  - name: require-recent-updates
    check: update_age_days < 30
    action: deny
    
  - name: require-firewall
    check: firewall_enabled == true
    action: deny
    
  - name: require-encryption
    check: disk_encrypted == true
    action: deny
```

### Agent Config

```yaml
# /etc/vouch/agent.yaml
server:
  url: http://vouch-server:8080
  request_timeout_s: 10

reporting:
  interval_s: 300
  jitter_s: 30

checks:
  tailscale:
    enable: true
  firewall:
    enable: true
  updates:
    enable: true
  disk_encryption:
    enable: true
  secure_boot_tpm:
    enable: true

logging:
  level: info
```

## API

### Enroll Agent
```http
POST /v1/enroll
{
  "token": "enrollment-token",
  "node_id": "tailscale-node-id",
  "hostname": "dev-laptop",
  "public_key": "ed25519-pubkey-base64"
}
```

### Report Posture
```http
POST /v1/report
Headers:
  X-Vouch-Agent-ID: agent-uuid
  X-Vouch-Signature: ed25519-signature
  X-Vouch-Timestamp: 2024-10-20T02:00:00Z

Body: {posture data}
```

### Query Devices
```http
GET /v1/devices
GET /v1/devices/:hostname

# External API (requires API key)
GET /v1/external/devices/:identifier?format=keep
Authorization: Bearer <api-key>
```

## CLI

```bash
vouch status              # Overall compliance
vouch devices             # List devices
vouch device hostname     # Device details
```

## Posture Checks

### Always Collected
- Hostname, OS (linux/darwin/windows), architecture
- OS name (Ubuntu 24.04, macOS 14, Windows 11)
- Kernel version
- Last update timestamp
- Auto-update enabled/disabled
- Pending updates count
- Reboot pending flag

### When Enabled
- **Disk encryption**: Per-volume encryption status (LUKS/FileVault/BitLocker)
- **Firewall**: Enabled status and type (ufw/iptables/nftables/pf/windows-defender)
- **Tailscale**: Client version, auto-update status, online status, node ID
- **Secure Boot**: UEFI Secure Boot enabled, TPM present and version
- **Services**: Critical services running (sshd, docker, tailscaled)

### Implementation Details

- Runs 8 probes in parallel with 10s total timeout
- Individual probe failures don't break collection
- Errors reported per-probe in `errors` map
- Uses `tailscale status --json` for accurate parsing
- Extracts PRETTY_NAME from `/etc/os-release` (not full file)
- Supports apt/dnf/pacman/apk for update detection
- Cross-platform (Linux/macOS/Windows)

## Security

- **Signed requests**: All agent reports use Ed25519 signatures
- **Replay protection**: 5-minute validity window with nonce
- **Identity binding**: Agent identity tied to Tailscale node ID
- **Enrollment tokens**: One-time tokens prevent unauthorized registration
- **Key storage**: Private keys stored with 0600 permissions

## Enforcement

When `--enforce` flag is set, server automatically:
1. Evaluates posture against policy
2. Updates Tailscale device tags via API (`tag:compliant` or removal)
3. ACLs can then restrict access based on tag presence

Requires Tailscale API key with device tag permissions.

## Building

```bash
git clone https://github.com/haasonsaas/vouch
cd vouch
make build

# Binaries in bin/
./bin/vouch-server
./bin/vouch-agent  
./bin/vouch
```

## Examples

- [`examples/policies/`](examples/policies/) - Policy configurations
- [`examples/docker-compose/`](examples/docker-compose/) - Deployment examples
- [`examples/systemd/`](examples/systemd/) - Service files

## Technical Details

### Collector Architecture

Uses `CollectorV2` with:
- Context-based timeouts (no hanging probes)
- Parallel execution (8 probes complete in ~2s)
- Structured error reporting
- Graceful degradation on probe failures

### Report Format

```json
{
  "hostname": "dev-laptop",
  "os": "linux",
  "arch": "amd64",
  "os_name": "Ubuntu 24.04",
  "kernel": "6.8.0-47-generic",
  "last_update_time": "2024-10-15T10:00:00Z",
  "updates_outstanding": 0,
  "auto_update_enabled": true,
  "reboot_pending": false,
  "root_volume_encrypted": true,
  "encryption_type": "luks",
  "tailscale_version": "1.56.0",
  "tailscale_online": true,
  "firewall_enabled": true,
  "firewall_type": "ufw",
  "secure_boot_enabled": true,
  "tpm_present": true,
  "tpm_version": "2.0",
  "errors": {}
}
```

## Monitoring

Prometheus metrics at `/metrics`:
- `vouch_devices_total`
- `vouch_devices_compliant`
- `vouch_policy_evaluations_total`

## Status

Alpha. Core functionality implemented. Not recommended for production use yet.

## License

Apache 2.0

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)
