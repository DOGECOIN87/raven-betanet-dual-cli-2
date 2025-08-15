# Requirements Document

## Introduction

This specification defines the requirements for completing two CLI tools for the Raven Betanet 1.1 bounty deliverables: a spec-compliance linter (`raven-linter`) and a Chrome uTLS template generator (`chrome-utls-gen`). The project must implement all 11 compliance checks from §11 of the Betanet 1.1 spec, generate SBOMs in multiple formats, create deterministic Chrome TLS ClientHello templates, and provide comprehensive CI/CD integration.

## Requirements

### Requirement 1: Spec-Compliance Linter CLI (raven-linter)

**User Story:** As a developer integrating with Raven Betanet 1.1, I want a CLI tool that validates my binary against all 11 compliance checks from §11 of the spec, so that I can ensure my software meets the network requirements before deployment.

#### Acceptance Criteria

1. WHEN I run `raven-linter check <binary>` THEN the system SHALL execute all 11 compliance checks from §11 of Betanet 1.1 spec
2. WHEN I run `raven-linter check <binary> --format json` THEN the system SHALL output results in machine-readable JSON format for CI/CD integration
3. WHEN I run `raven-linter check <binary> --format text` THEN the system SHALL output results in human-readable text format
4. WHEN all compliance checks pass THEN the system SHALL exit with code 0
5. WHEN any compliance check fails THEN the system SHALL exit with code 1
6. WHEN invalid arguments are provided THEN the system SHALL exit with code 2
7. WHEN I run `raven-linter check <binary> --sbom` THEN the system SHALL generate an SBOM file as sbom.json
8. WHEN I specify `--sbom-format cyclonedx` THEN the system SHALL generate SBOM in CycloneDX v1.5 JSON format
9. WHEN I specify `--sbom-format spdx` THEN the system SHALL generate SBOM in SPDX 2.3 JSON format

### Requirement 2: Binary Analysis Checks (Checks 1-4)

**User Story:** As a security auditor, I want the linter to perform comprehensive binary analysis including file signature validation, metadata extraction, dependency analysis, and format compliance, so that I can verify the binary's structural integrity.

#### Acceptance Criteria

1. WHEN check 1 executes THEN the system SHALL validate binary file signature and format (ELF, PE, Mach-O)
2. WHEN check 2 executes THEN the system SHALL extract binary metadata including architecture, entry point, and sections
3. WHEN check 3 executes THEN the system SHALL analyze binary dependencies and imported libraries
4. WHEN check 4 executes THEN the system SHALL validate binary format compliance and structure integrity
5. WHEN any binary analysis check fails THEN the system SHALL provide detailed error information in the results
6. WHEN binary format is unsupported THEN the system SHALL fail check 1 with appropriate error message

### Requirement 3: Cryptographic Validation Checks (Checks 5-8)

**User Story:** As a security engineer, I want the linter to validate cryptographic aspects of binaries including certificates, signatures, hashes, and encryption standards, so that I can ensure the binary meets security requirements.

#### Acceptance Criteria

1. WHEN check 5 executes THEN the system SHALL validate certificate information if present
2. WHEN check 6 executes THEN the system SHALL verify digital signatures if present
3. WHEN check 7 executes THEN the system SHALL perform hash integrity checks
4. WHEN check 8 executes THEN the system SHALL validate encryption standard compliance
5. WHEN cryptographic validation fails THEN the system SHALL provide specific failure reasons
6. WHEN no cryptographic information is present THEN the system SHALL handle gracefully with appropriate status

### Requirement 4: Security and Metadata Checks (Checks 9-11)

**User Story:** As a compliance officer, I want the linter to validate security flags, version information, and license compliance, so that I can ensure the binary meets regulatory and security requirements.

#### Acceptance Criteria

1. WHEN check 9 executes THEN the system SHALL validate security flag settings (ASLR, DEP, etc.)
2. WHEN check 10 executes THEN the system SHALL extract and validate version information
3. WHEN check 11 executes THEN the system SHALL verify license compliance information
4. WHEN security flags are missing THEN the system SHALL report specific missing flags
5. WHEN version information is incomplete THEN the system SHALL report missing version components

### Requirement 5: SBOM Generation

**User Story:** As a DevOps engineer, I want the linter to generate Software Bill of Materials in industry-standard formats, so that I can integrate with supply chain security tools and meet compliance requirements.

#### Acceptance Criteria

1. WHEN SBOM generation is requested THEN the system SHALL support CycloneDX v1.5 JSON format
2. WHEN SBOM generation is requested THEN the system SHALL support SPDX 2.3 JSON format
3. WHEN generating SBOM THEN the system SHALL include all detected components and dependencies
4. WHEN generating SBOM THEN the system SHALL validate output against official schemas
5. WHEN SBOM generation fails THEN the system SHALL continue with compliance checks and warn about SBOM failure
6. WHEN SBOM is generated THEN the system SHALL include metadata about the tool, target binary, and generation timestamp

### Requirement 6: Chrome uTLS Template Generator CLI (chrome-utls-gen)

**User Story:** As a network security researcher, I want a CLI tool that generates deterministic TLS ClientHello templates identical to Chrome Stable versions, so that I can perform accurate TLS fingerprinting and testing.

#### Acceptance Criteria

1. WHEN I run `chrome-utls-gen generate` THEN the system SHALL create a deterministic ClientHello blob identical to Chrome Stable (N or N-2)
2. WHEN I run `chrome-utls-gen ja3-test <target>` THEN the system SHALL connect to the target and extract JA3 fingerprint
3. WHEN I run `chrome-utls-gen update` THEN the system SHALL fetch latest Chrome versions and regenerate templates
4. WHEN generating ClientHello THEN the system SHALL produce identical bytes to real Chrome connections
5. WHEN testing JA3 THEN the system SHALL verify exact match to expected Chrome fingerprint values
6. WHEN updating templates THEN the system SHALL use official Chromium release API

### Requirement 7: Chrome Version Management

**User Story:** As a security tester, I want the tool to automatically manage Chrome Stable (N) and Stable (N-2) versions, so that I can test against current and previous stable releases without manual version tracking.

#### Acceptance Criteria

1. WHEN fetching Chrome versions THEN the system SHALL use official Chromium dashboard API
2. WHEN determining versions THEN the system SHALL identify current Stable (N) and previous Stable (N-2)
3. WHEN caching versions THEN the system SHALL store templates locally for offline usage
4. WHEN versions are cached THEN the system SHALL include metadata and generation timestamps
5. WHEN API is unavailable THEN the system SHALL fall back to cached versions with appropriate warnings

### Requirement 8: JA3 Fingerprint Testing

**User Story:** As a penetration tester, I want to test JA3 fingerprints against real servers and verify they match expected Chrome signatures, so that I can validate the accuracy of generated ClientHello templates.

#### Acceptance Criteria

1. WHEN testing JA3 fingerprint THEN the system SHALL establish real TLS connection to target server
2. WHEN connection succeeds THEN the system SHALL extract JA3 string and hash from handshake
3. WHEN expected JA3 is provided THEN the system SHALL verify exact match
4. WHEN no expected JA3 is provided THEN the system SHALL compare against known Chrome fingerprints
5. WHEN connection fails THEN the system SHALL provide detailed error information and troubleshooting guidance
6. WHEN JA3 mismatch occurs THEN the system SHALL report expected vs actual values

### Requirement 9: CI/CD Integration

**User Story:** As a DevOps engineer, I want GitHub Actions workflows that automatically run compliance checks, generate SBOMs, update Chrome templates, and handle releases, so that I can integrate these tools into automated pipelines.

#### Acceptance Criteria

1. WHEN PR is created THEN the system SHALL run spec-linter workflow with compliance checks
2. WHEN compliance checks fail THEN the system SHALL fail the workflow and prevent merge
3. WHEN SBOM is generated THEN the system SHALL upload it as a workflow artifact
4. WHEN Chrome versions update THEN the system SHALL automatically refresh templates via scheduled workflow
5. WHEN templates are updated THEN the system SHALL create PR with new templates
6. WHEN release is tagged THEN the system SHALL build cross-platform binaries and create GitHub release

### Requirement 10: Cross-Platform Support

**User Story:** As a developer working across different platforms, I want both CLI tools to work on Linux, macOS, and Windows, so that I can use them regardless of my development environment.

#### Acceptance Criteria

1. WHEN building binaries THEN the system SHALL support Linux (amd64, arm64)
2. WHEN building binaries THEN the system SHALL support macOS (amd64, arm64)
3. WHEN building binaries THEN the system SHALL support Windows (amd64)
4. WHEN running on any platform THEN the system SHALL provide identical functionality
5. WHEN building THEN the system SHALL embed version, commit, and build date via ldflags
6. WHEN distributing THEN the system SHALL provide checksums for all binary artifacts

### Requirement 11: Documentation and Usability

**User Story:** As a new user of these tools, I want comprehensive documentation with installation instructions, usage examples, and troubleshooting guides, so that I can quickly understand and effectively use the tools.

#### Acceptance Criteria

1. WHEN reading README THEN the system SHALL provide clear installation instructions
2. WHEN reading README THEN the system SHALL include usage examples for all commands
3. WHEN reading README THEN the system SHALL describe all 11 compliance checks with one-liner explanations
4. WHEN running `--help` THEN the system SHALL provide comprehensive command documentation
5. WHEN errors occur THEN the system SHALL provide actionable error messages with troubleshooting guidance
6. WHEN contributing THEN the system SHALL provide contribution guidelines and development setup instructions

### Requirement 12: Testing and Quality Assurance

**User Story:** As a maintainer, I want comprehensive test coverage including unit tests, integration tests, and golden file comparisons, so that I can ensure the tools work correctly and maintain quality over time.

#### Acceptance Criteria

1. WHEN running tests THEN the system SHALL include unit tests for all compliance checks
2. WHEN running tests THEN the system SHALL include integration tests for CLI commands
3. WHEN testing ClientHello generation THEN the system SHALL use golden file comparisons
4. WHEN testing JA3 calculation THEN the system SHALL verify against known Chrome fingerprints
5. WHEN running linting THEN the system SHALL pass golangci-lint with zero issues
6. WHEN running `go vet` THEN the system SHALL report no issues