# Makefile for Raven Betanet Dual CLI Tools

# Version information
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Binary names
RAVEN_LINTER_BIN = raven-linter
CHROME_UTLS_GEN_BIN = chrome-utls-gen

# Build directories
BUILD_DIR = bin
DIST_DIR = dist

# Cross-compilation targets
PLATFORMS = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

# Build flags with optimization and version embedding
LDFLAGS = -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"
CGO_ENABLED = 0

# Default target
.PHONY: all
all: build

# Build both tools for current platform
.PHONY: build
build: build-raven-linter build-chrome-utls-gen

# Build raven-linter for current platform
.PHONY: build-raven-linter
build-raven-linter:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) go build $(LDFLAGS) -o $(BUILD_DIR)/$(RAVEN_LINTER_BIN) ./cmd/raven-linter

# Build chrome-utls-gen for current platform
.PHONY: build-chrome-utls-gen
build-chrome-utls-gen:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) go build $(LDFLAGS) -o $(BUILD_DIR)/$(CHROME_UTLS_GEN_BIN) ./cmd/chrome-utls-gen

# Cross-compile for all platforms
.PHONY: build-all
build-all: clean-dist
	@echo "Building for all platforms..."
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d'/' -f1); \
		arch=$$(echo $$platform | cut -d'/' -f2); \
		echo "Building for $$os/$$arch..."; \
		\
		raven_output="$(DIST_DIR)/$(RAVEN_LINTER_BIN)-$(VERSION)-$$os-$$arch"; \
		chrome_output="$(DIST_DIR)/$(CHROME_UTLS_GEN_BIN)-$(VERSION)-$$os-$$arch"; \
		\
		if [ "$$os" = "windows" ]; then \
			raven_output="$$raven_output.exe"; \
			chrome_output="$$chrome_output.exe"; \
		fi; \
		\
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=$(CGO_ENABLED) go build $(LDFLAGS) -o $$raven_output ./cmd/raven-linter || exit 1; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=$(CGO_ENABLED) go build $(LDFLAGS) -o $$chrome_output ./cmd/chrome-utls-gen || exit 1; \
	done
	@echo "Cross-compilation complete!"

# Generate checksums for all built binaries
.PHONY: checksums
checksums:
	@echo "Generating checksums..."
	@cd $(DIST_DIR) && find . -name "$(RAVEN_LINTER_BIN)-*" -o -name "$(CHROME_UTLS_GEN_BIN)-*" | sort | xargs sha256sum > checksums.txt
	@echo "Checksums generated in $(DIST_DIR)/checksums.txt"

# Build release artifacts (cross-compile + checksums)
.PHONY: release
release: build-all checksums
	@echo "Release artifacts ready in $(DIST_DIR)/"
	@ls -la $(DIST_DIR)/

# Compress binaries (optional, requires upx)
.PHONY: compress
compress:
	@echo "Compressing binaries..."
	@if command -v upx >/dev/null 2>&1; then \
		find $(DIST_DIR) -name "$(RAVEN_LINTER_BIN)-*" -o -name "$(CHROME_UTLS_GEN_BIN)-*" | grep -v ".txt" | xargs upx --best --lzma; \
		echo "Binaries compressed with UPX"; \
	else \
		echo "UPX not found, skipping compression"; \
	fi

# Test
.PHONY: test
test:
	go test ./...

# Test with coverage
.PHONY: test-coverage
test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Lint
.PHONY: lint
lint:
	go vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found, skipping advanced linting"; \
	fi

# Security scan
.PHONY: security
security:
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not found, skipping security scan"; \
	fi

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)/

# Clean distribution artifacts
.PHONY: clean-dist
clean-dist:
	rm -rf $(DIST_DIR)/

# Clean all artifacts
.PHONY: clean-all
clean-all: clean clean-dist
	rm -f coverage.out coverage.html

# Install dependencies
.PHONY: deps
deps:
	go mod download
	go mod tidy

# Install development tools
.PHONY: install-tools
install-tools:
	@echo "Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	@echo "Development tools installed"

# Show build information
.PHONY: info
info:
	@echo "Build Information:"
	@echo "  Version: $(VERSION)"
	@echo "  Commit:  $(COMMIT)"
	@echo "  Date:    $(DATE)"
	@echo "  Platforms: $(PLATFORMS)"
	@echo "  Build Dir: $(BUILD_DIR)"
	@echo "  Dist Dir:  $(DIST_DIR)"

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build         - Build both tools for current platform"
	@echo "  build-all     - Cross-compile for all platforms"
	@echo "  release       - Build release artifacts with checksums"
	@echo "  compress      - Compress binaries with UPX (if available)"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  lint          - Run linters"
	@echo "  security      - Run security scan"
	@echo "  clean         - Clean build artifacts"
	@echo "  clean-all     - Clean all artifacts"
	@echo "  deps          - Install dependencies"
	@echo "  install-tools - Install development tools"
	@echo "  info          - Show build information"
	@echo "  help          - Show this help"