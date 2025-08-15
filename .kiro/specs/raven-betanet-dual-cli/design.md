Raven Betanet Dual CLI – Full Implementation Spec (No Placeholders)

Goal: Implement two CLI tools in Go 1.21+ for Raven Betanet 1.1 compliance and Chrome TLS ClientHello generation, meeting all bounty criteria at https://ravendevteam.org/betanet/.

1. Tools Overview
raven-linter

Performs 11 compliance checks on binaries:

Binary format + architecture

Dependency analysis

Certificate & signature validation

Security flags & metadata checks

SBOM generation (CycloneDX / SPDX)

chrome-utls-gen

Generates deterministic Chrome TLS ClientHello templates + JA3 fingerprints for version-specific testing.

2. CLI Syntax

raven-linter
raven-linter --binary ./path/to/binary \
             --output-format json \
             --sbom-format cyclonedx \
             --checks 1,2,3,5,9 \
             --skip-platforms windows \
             --config ./config.yaml

chrome-utls-gen

chrome-utls-gen --chrome-version stable \
                --output ./templates/chrome_120.json \
                --update-cache

3. Package Structure

cmd/
  raven-linter/main.go
  chrome-utls-gen/main.go

internal/
  checks/
    check_interface.go
    binary_analysis.go
    crypto_validation.go
    security_metadata.go
  sbom/
    models.go
    extractor.go
    cyclonedx.go
    spdx.go
  tlsgen/
    chrome_version.go
    handshake_gen.go
    ja3_calculator.go
    version_cache.go
  utils/
    config.go
    http_client.go
    logging.go
    updater.go

4. Compliance Checks – Exact Logic & Libraries

Check 1 – Binary Format Validation

    Use debug/elf, debug/pe, debug/macho

    Detect ELF, PE, Mach-O, verify correctness.

Check 2 – Architecture Validation

    Extract architecture (amd64, arm64, 386) using binary.FileHeader data.

Check 3 – Entry Point & Section Validation

    Use Sections from debug/* to verify required segments (.text, .data).

    Ensure entry point is non-zero.

Check 4 – Dependency Analysis

    Parse Imports (Windows) or DynamicSection (ELF) to list linked libraries.

    Fail if blacklisted dependencies present.

Check 5 – Certificate Presence

    Use crypto/x509 to load embedded certs (from PE optional headers / Mach-O LC_CODE_SIGNATURE / ELF notes).

    Fail if missing.

Check 6 – Certificate Validity

    Validate with x509.Verify() against system roots.

Check 7 – Digital Signature Verification

    Use crypto + platform-specific signature extractors (Mach-O: codesign segment, PE: WIN_CERTIFICATE).

Check 8 – Hash Verification

    Calculate SHA256 + SHA512 with crypto/sha256, crypto/sha512.

    Compare against provided manifest (config file).

Check 9 – Security Flags

    ELF: Check NX bit, RELRO, PIE via readelf-style parsing.

    PE: Check DEP, ASLR via optional header flags.

Check 10 – Version Metadata

    Extract build version from .rdata, .note, or __info_plist.

Check 11 – License Compliance

    Search for LICENSE file in binary dir; parse with github.com/google/licenseclassifier.

5. SBOM Generation

CycloneDX: Use github.com/CycloneDX/cyclonedx-go
SPDX: Use github.com/spdx/tools-golang

Extraction:

    Detect components from dependency analysis.

    Hashes: SHA1, SHA256, SHA512 for each component.

    Output validated against JSON schema.

6. Chrome TLS Generation

Chrome Version Source:

    API: https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Linux

    Store as JSON in cache dir: ~/.raven-cache/chrome_versions.json

Template Generation:

    Use utls (github.com/refraction-networking/utls) to generate ClientHello matching Chrome stable/stable-2.

    Save template JSON in templates/.

JA3 Calculation:

    Implement with utls handshake data + RFC 8446 field parsing.

    Hash with crypto/md5.

7. Cache & Data Persistence

Cache Dir: ~/.raven-cache

    chrome_versions.json – fetched from API

    clienthello_cache.json – generated templates

Template Dir:

    templates/chrome_<version>.json

8. Error Handling

    User Errors → Exit 2

    Compliance Failures → Exit 1

    System Errors → Exit 3

All errors output JSON if --output-format json is set.
9. Testing

    Unit tests for each compliance check using testing package.

    Golden files for SBOM, ClientHello, JA3.

    Cross-platform builds in GitHub Actions (Linux, Windows, macOS).

    Benchmarks for binary parsing.

10. Deliverables

    Fully working CLI binaries for Linux, Windows, macOS.

    100% functional code — no placeholders, no TODOs.

    Passes all 11 compliance checks.

    Generates valid Chrome TLS templates & JA3 fingerprints.