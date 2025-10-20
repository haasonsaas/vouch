# Contributing to Vouch

Thanks for your interest in contributing to Vouch! This document provides guidelines for contributions.

## Getting Started

1. **Fork the repository**
2. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/vouch
   cd vouch
   ```
3. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Requirements
- Go 1.21 or higher
- Docker (for building images)
- Make

### Build
```bash
make build
```

### Run Tests
```bash
go test -v ./...
```

### Run Locally
```bash
# Terminal 1: Start server
./bin/vouch-server --policy policies.example.yaml

# Terminal 2: Start agent
./bin/vouch-agent --server http://localhost:8080 --interval 30s

# Terminal 3: Check status
./bin/vouch status
./bin/vouch devices
```

## Code Style

- Follow standard Go conventions
- Run `gofmt` before committing
- Add comments for exported functions
- Keep functions small and focused

## Pull Request Process

1. **Update documentation** if you're changing functionality
2. **Add tests** for new features
3. **Ensure all tests pass**: `make test`
4. **Update CHANGELOG.md** with your changes
5. **Submit PR** with a clear description of changes

### PR Title Format
```
<type>: <description>

Types:
- feat: New feature
- fix: Bug fix
- docs: Documentation changes
- refactor: Code refactoring
- test: Adding tests
- chore: Maintenance tasks
```

### Example
```
feat: Add Windows agent support
fix: Resolve SQLite connection leak
docs: Update installation instructions
```

## Feature Requests

Open an issue with:
- Clear description of the feature
- Use case / problem it solves
- Proposed implementation (if you have ideas)

## Bug Reports

Open an issue with:
- Steps to reproduce
- Expected behavior
- Actual behavior
- Vouch version (`vouch version`)
- OS and architecture
- Relevant logs

## Development Workflow

### Adding a New Policy Check

1. **Update posture collector** (`pkg/posture/collector.go`)
   ```go
   type Report struct {
       // ... existing fields
       NewField string `json:"new_field"`
   }
   ```

2. **Update policy engine** (`pkg/policy/engine.go`)
   ```go
   func checkRule(report *posture.Report, rule Rule) bool {
       switch rule.Check {
       case "new_check":
           return // your logic
       }
   }
   ```

3. **Add documentation** to README
4. **Add example** to `policies.example.yaml`
5. **Write tests**

### Adding a New Enforcement Method

1. **Create package** under `pkg/enforcement/`
2. **Implement interface**
   ```go
   type Enforcer interface {
       GrantAccess(nodeID string) error
       RevokeAccess(nodeID string) error
   }
   ```
3. **Update server** to support new enforcer
4. **Add configuration** options
5. **Document usage**

## Testing

### Unit Tests
```bash
go test ./pkg/...
```

### Integration Tests
```bash
# Start test server
go run ./server --policy policies.example.yaml &

# Run integration tests
go test ./tests/integration/...
```

### Manual Testing
```bash
# Build and test locally
make build
./bin/vouch-server --policy policies.example.yaml &
./bin/vouch-agent --server http://localhost:8080 --interval 10s &
sleep 15
./bin/vouch devices
```

## Release Process

Maintainers only:

1. Update version in documentation
2. Update CHANGELOG.md
3. Commit: `git commit -m "chore: Release v0.x.0"`
4. Tag: `git tag -a v0.x.0 -m "Release v0.x.0"`
5. Push: `git push origin main --tags`

GitHub Actions will automatically:
- Build binaries for all platforms
- Create GitHub release
- Publish Docker images

## Questions?

- Open an issue for questions
- Start a discussion for broader topics
- Tag maintainers with `@haasonsaas`

## Code of Conduct

Be respectful, constructive, and professional. We're all here to build something useful together.

---

Thank you for contributing to Vouch! 🚀
