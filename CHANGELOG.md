# Changelog

All notable changes to Vouch will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-10-20

### Added
- Initial release of Vouch
- Device posture collection agent
  - OS version and patch level detection
  - Kernel version tracking
  - Last update timestamp
  - Disk encryption detection
  - Running services enumeration
- Control plane server
  - Policy evaluation engine
  - Device state database (SQLite)
  - REST API for device management
  - Tailscale ACL integration hooks
- CLI management tool
  - `vouch status` - Overall compliance view
  - `vouch devices` - List all devices
  - `vouch device [hostname]` - Device details
- Policy engine with YAML configuration
  - Update age enforcement
  - Disk encryption requirements
  - Kernel version checks
- Tailscale enforcement integration
  - Automatic tag management
  - ACL updates via API
- Docker images
  - Multi-arch support (amd64, arm64)
  - Published to ghcr.io
- Installation script
  - Auto-detects latest release
  - Systemd service integration
- GitHub Actions CI/CD
  - Automated builds on tag push
  - Multi-platform binary releases
  - Docker image publishing
- Documentation
  - README with quick start
  - API documentation
  - Docker deployment guide

### Status
- Alpha release - core functionality working
- Not recommended for production use yet

[Unreleased]: https://github.com/haasonsaas/vouch/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/haasonsaas/vouch/releases/tag/v0.1.0
