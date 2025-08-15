# Raven Betanet Dual CLI Tools

[![CI/CD](https://github.com/DOGECOIN87/raven-betanet-dual-cli/actions/workflows/spec-linter.yml/badge.svg)](https://github.com/DOGECOIN87/raven-betanet-dual-cli/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/DOGECOIN87/raven-betanet-dual-cli)](https://goreportcard.com/report/github.com/DOGECOIN87/raven-betanet-dual-cli)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Two powerful CLI tools for the Raven Betanet 1.1 bounty deliverables:

1. **`raven-linter`** - Spec-compliance linter with SBOM generation
2. **`chrome-utls-gen`** - Chrome TLS ClientHello template generator with JA3 testing

## 🚀 Quick Start

### Installation

#### Download Pre-built Binaries

```bash
# Linux (amd64)
curl -L https://github.com/DOGECOIN87/raven-betanet-dual-cli/releases/latest/download/raven-linter-linux-amd64 -o raven-linter
curl -L https://github.com/DOGECOIN87/raven-betanet-dual-cli/releases/latest/download/chrome-utls-gen-linux-amd64 -o chrome-utls-gen
chmod +x raven-linter chrome-utls-gen

# macOS (amd64)
curl -L https://github.com/DOGECOIN87/raven-betanet-dual-cli/releases/latest/download/raven-linter-darwin-amd64 -o raven-linter
curl -L https://github.com/DOGECOIN87/raven-betanet-dual-cli/releases/latest/download/chrome-utls-gen-darwin-amd64 -o chrome-utls-gen
chmod +x raven-linter chrome-utls-gen

# Windows (amd64)
curl -L https://github.com/DOGECOIN87/raven-betanet-dual-cli/releases/latest/download/raven-linter-windows-amd64.exe -o raven-linter.exe
curl -L https://github.com/DOGECOIN87/raven-betanet-dual-cli/releases/latest/download/chrome-utls-gen-windows-amd64.exe -o chrome-utls-gen.exe
```

#### Build from Source

```bash
git clone https://github.com/DOGECOIN87/raven-betanet-dual-cli.git
cd raven-betanet-dual-cli
make build
```

### Basic Usage

```bash
# Run compliance checks
./raven-linter check ./my-binary

# Generate Chrome ClientHello template
./chrome-utls-gen generate --output clienthello.bin

# Test JA3 fingerprint
./chrome-utls-gen ja3-test --target example.com:443
```

## 📋 Raven Linter (`raven-linter`)

Validates binaries against all 11 compliance checks from §11 of the Raven Betanet 1.1 specification and generates Software Bill of Materials (SBOM).

### Features

- ✅ **Complete Compliance Checking**: All 11 checks from Betanet 1.1 spec §11
- 📊 **SBOM Generation**: CycloneDX v1.5 and SPDX 2.3 JSON formats
- 🔄 **CI/CD Integration**: JSON output and proper exit codes
- 🛡️ **Security Analysis**: Cryptographic validation and security flags
- 📱 **Cross-Platform**: Linux, macOS, Windows support

### Usage Examples

```bash
# Basic compliance check
raven-linter check ./my-binary

# JSON output for CI/CD
raven-linter check ./my-binary --format json

# Generate SBOM alongside compliance checks
raven-linter check ./my-binary --sbom

# Custom SBOM format and location
raven-linter check ./my-binary --sbom --sbom-format spdx --sbom-output ./reports/sbom.json

# Verbose output for troubleshooting
raven-linter check ./my-binary --verbose

# Check for updates
raven-linter update --check-only
```

### Compliance Checks

The linter implements all 11 mandatory compliance checks:

#### Binary Analysis (Checks 1-4)
1. **File Signature Validation** - Validates binary file signature and format (ELF, PE, Mach-O)
2. **Binary Metadata Extraction** - Extracts architecture, entry point, and sections
3. **Dependency Analysis** - Analyzes binary dependencies and imported libraries
4. **Binary Format Compliance** - Validates format compliance and structure integrity

#### Cryptographic Validation (Checks 5-8)
5. **Certificate Validation** - Validates embedded certificates and certificate chains
6. **Signature Verification** - Verifies digital signatures and code signing certificates
7. **Hash Integrity Checks** - Verifies binary integrity using cryptographic hashes
8. **Encryption Standard Compliance** - Validates compliance with encryption standards

#### Security & Metadata (Checks 9-11)
9. **Security Flag Validation** - Validates security flags and compiler protections (ASLR, DEP, PIE, etc.)
10. **Version Information Extraction** - Extracts and validates version information
11. **License Compliance Verification** - Validates license compliance and identifies embedded licenses

### Exit Codes

- `0` - All compliance checks passed
- `1` - One or more compliance checks failed
- `2` - Invalid arguments or configuration error

### SBOM Generation

Generates comprehensive Software Bill of Materials in industry-standard formats:

- **CycloneDX v1.5 JSON** (default) - Modern SBOM format with rich metadata
- **SPDX 2.3 JSON** - Established standard for software composition analysis

SBOM includes:
- Main application component
- Dynamic dependencies
- Inferred libraries from symbols
- Embedded packages (Go modules, Rust crates, etc.)
- License information
- Security metadata

## 🌐 Chrome uTLS Generator (`chrome-utls-gen`)

Generates deterministic TLS ClientHello templates identical to Chrome Stable versions and provides JA3 fingerprint testing capabilities.

### Features

- 🔒 **Deterministic ClientHello Generation**: Byte-perfect Chrome TLS handshakes
- 🧪 **JA3 Fingerprint Testing**: Real-world connection testing and verification
- 🔄 **Automatic Updates**: Chrome version tracking via Chromium API
- 📦 **Template Caching**: Offline usage with local template storage
- 🎯 **Version Support**: Chrome 70+ with N and N-2 stable versions

### Usage Examples

```bash
# Generate ClientHello for latest Chrome stable
chrome-utls-gen generate --output clienthello.bin

# Generate for specific Chrome version
chrome-utls-gen generate --version 120.0.6099.109 --output chrome120.bin

# Test JA3 fingerprint against server
chrome-utls-gen ja3-test --target example.com:443

# Verify against expected JA3 hash
chrome-utls-gen ja3-test --target example.com:443 --expected cd08e31494f9531f560d64c695473da9

# Update Chrome version templates
chrome-utls-gen update

# Dry run to see what would be updated
chrome-utls-gen update --dry-run

# Check for binary updates
chrome-utls-gen self-update --check-only
```

### Supported Chrome Versions

- **Chrome 133+**: Latest fingerprints with modern TLS features
- **Chrome 131-132**: Recent stable versions
- **Chrome 120-130**: Widely deployed versions
- **Chrome 115-119**: Post-quantum cryptography support
- **Chrome 106-114**: Extension shuffling behavior
- **Chrome 70-105**: Legacy support for older deployments

### JA3 Fingerprint Testing

JA3 is a method for fingerprinting TLS clients based on ClientHello parameters:

- **Real Connection Testing**: Establishes actual TLS connections
- **Fingerprint Extraction**: Calculates JA3 string and hash
- **Verification**: Compares against expected Chrome signatures
- **Detailed Reporting**: Connection timing, TLS version, cipher suites

### Template Caching

- **Local Storage**: `~/.raven-betanet/templates/`
- **JSON Format**: Rich metadata with generation timestamps
- **Offline Usage**: Works without internet connectivity
- **Automatic Cleanup**: Configurable template expiration

## 🔧 Configuration

Both tools support configuration via files and environment variables.

### Configuration File

Create `~/.raven-betanet/config.yaml`:

```yaml
log:
  level: info
  format: text

http:
  timeout: 30s
  max_retries: 3
  user_agent: "raven-betanet-dual-cli/1.0"

chrome:
  api_endpoint: "https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Linux"
  cache_ttl: 24h
  update_check: true

sbom:
  default_format: cyclonedx
  validate: true
  include_tests: false

compliance:
  strict_mode: false
  fail_fast: false
  report_format: text
```

### Environment Variables

```bash
# Logging
export LOG_LEVEL=debug
export LOG_FORMAT=json

# HTTP Client
export HTTP_TIMEOUT=60s
export HTTP_MAX_RETRIES=5

# Chrome Configuration
export CHROME_CACHE_DIR=/custom/cache/path
export CHROME_UPDATE_CHECK=false

# SBOM Configuration
export SBOM_DEFAULT_FORMAT=spdx
export SBOM_OUTPUT_DIR=/custom/sbom/path

# Compliance Configuration
export COMPLIANCE_STRICT_MODE=true
export COMPLIANCE_SKIP_CHECKS=check-1,check-2
```

## 🏗️ Development

### Prerequisites

- Go 1.21+
- Make
- Git

### Building

```bash
# Build both tools
make build

# Build for all platforms
make build-all

# Run tests
make test

# Run linting
make lint

# Generate coverage report
make test-coverage
```

### Project Structure

```
├── cmd/
│   ├── raven-linter/          # Raven linter CLI
│   └── chrome-utls-gen/       # Chrome uTLS generator CLI
├── internal/
│   ├── checks/                # Compliance check implementations
│   ├── sbom/                  # SBOM generation and models
│   ├── tlsgen/                # TLS generation and JA3 calculation
│   └── utils/                 # Shared utilities
├── tests/
│   ├── fixtures/              # Test fixtures and sample binaries
│   ├── golden/                # Golden files for testing
│   └── integration/           # Integration tests
└── .github/workflows/         # CI/CD workflows
```

### Testing

```bash
# Unit tests
go test ./...

# Integration tests
go test -tags=integration ./tests/integration/...

# Performance tests
go test -run=TestPerformance ./tests/integration/...

# Generate golden files
go run ./tests/golden/chrome_handshakes/generate_clienthello.go 120.0.6099.109
```

## 🚀 CI/CD Integration

### GitHub Actions

The project includes comprehensive GitHub Actions workflows:

- **Spec Linter CI/CD** (`.github/workflows/spec-linter.yml`)
- **Chrome uTLS Gen CI/CD** (`.github/workflows/chrome-utls-gen.yml`)
- **Auto-refresh** (`.github/workflows/auto-refresh.yml`)
- **Release** (`.github/workflows/release.yml`)

### Example CI Integration

```yaml
name: Binary Compliance Check
on: [push, pull_request]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Download raven-linter
        run: |
          curl -L https://github.com/DOGECOIN87/raven-betanet-dual-cli/releases/latest/download/raven-linter-linux-amd64 -o raven-linter
          chmod +x raven-linter
      
      - name: Build application
        run: go build -o my-app ./cmd/my-app
      
      - name: Run compliance checks
        run: ./raven-linter check my-app --format json --sbom
      
      - name: Upload SBOM
        uses: actions/upload-artifact@v3
        with:
          name: sbom
          path: sbom.json
```

## 📊 Performance

### Benchmarks

- **Compliance Checks**: ~2-5 seconds for typical binaries
- **SBOM Generation**: ~1-3 seconds additional overhead
- **ClientHello Generation**: ~100-500ms per template
- **JA3 Testing**: ~1-5 seconds per target (network dependent)

### Resource Usage

- **Memory**: ~50-100MB peak usage
- **CPU**: Single-threaded with concurrent I/O
- **Disk**: Minimal temporary files, configurable cache

## 🛠️ Troubleshooting

### Common Issues

#### Raven Linter

**Issue**: "Binary format not recognized"
```bash
# Solution: Check if binary is corrupted or unsupported format
file ./my-binary
raven-linter check ./my-binary --verbose
```

**Issue**: "SBOM generation failed"
```bash
# Solution: Check write permissions and disk space
raven-linter check ./my-binary --sbom --sbom-output ./custom/path/sbom.json --verbose
```

#### Chrome uTLS Gen

**Issue**: "Failed to fetch Chrome versions"
```bash
# Solution: Check network connectivity and proxy settings
chrome-utls-gen update --verbose
export HTTP_PROXY=http://proxy:8080
```

**Issue**: "JA3 test connection failed"
```bash
# Solution: Check target accessibility and firewall settings
chrome-utls-gen ja3-test --target example.com:443 --timeout 30s --verbose
```

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
# Environment variable
export LOG_LEVEL=debug

# Command line flag
raven-linter check ./my-binary --verbose
chrome-utls-gen generate --verbose
```

### Support

- 📖 **Documentation**: Check this README and inline help (`--help`)
- 🐛 **Issues**: [GitHub Issues](https://github.com/DOGECOIN87/raven-betanet-dual-cli/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/DOGECOIN87/raven-betanet-dual-cli/discussions)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on:

- Code of conduct
- Development setup
- Submission process
- Coding standards

### Quick Contribution Steps

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`make test`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## 🏆 Raven Betanet 1.1 Bounty Compliance

This project fully implements the Raven Betanet 1.1 bounty requirements:

### ✅ Spec-Compliance Linter (`raven-linter`)
- [x] All 11 compliance checks from §11 of Betanet 1.1 spec
- [x] JSON and text output formats
- [x] Proper exit codes (0=pass, 1=fail)
- [x] SBOM generation (CycloneDX v1.5, SPDX 2.3)
- [x] GitHub Actions integration with artifact upload
- [x] Cross-platform builds (Linux, macOS, Windows)
- [x] Comprehensive test coverage

### ✅ Chrome uTLS Template Generator (`chrome-utls-gen`)
- [x] Deterministic ClientHello generation for Chrome Stable (N, N-2)
- [x] JA3 fingerprint calculation and verification
- [x] Chrome version auto-update via Chromium API
- [x] Template caching for offline usage
- [x] Real connection testing against servers
- [x] Scheduled GitHub Actions for auto-refresh
- [x] Golden file testing for reproducibility

### ✅ Quality Assurance
- [x] Unit tests with >80% coverage
- [x] Integration tests for CLI functionality
- [x] Golden file tests for deterministic output
- [x] Cross-platform compatibility testing
- [x] Security scanning (gosec, govulncheck)
- [x] Linting (golangci-lint) with zero issues
- [x] Performance benchmarks

### ✅ Documentation & Usability
- [x] Comprehensive README with examples
- [x] Inline help for all commands
- [x] Troubleshooting guide
- [x] CI/CD integration examples
- [x] Contributing guidelines
- [x] License compliance

---

**Built with ❤️ for the Raven Betanet community**