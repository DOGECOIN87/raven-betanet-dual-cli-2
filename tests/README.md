# Test Suite

This directory contains the comprehensive test suite for the Raven Betanet dual CLI project.

## Structure

- `fixtures/` - Test fixtures and sample data
  - `sample_binaries/` - Binary files for compliance testing
  - `test_configs/` - Configuration files for testing
- `golden/` - Golden files for output comparison
  - `chrome_handshakes/` - Expected Chrome TLS handshake data
  - `compliance_results/` - Expected compliance check results
  - `sbom_outputs/` - Expected SBOM generation outputs
- `integration/` - End-to-end integration tests
  - `framework_test.go` - Test framework validation
  - `raven_linter_e2e_test.go` - Raven linter end-to-end tests
  - `chrome_utls_gen_e2e_test.go` - Chrome uTLS generator end-to-end tests
  - `dual_cli_e2e_test.go` - Combined dual CLI integration tests
- `utils/` - Test utilities and helpers
  - `test_runner.go` - Test execution framework with cleanup

## Test Categories

### Unit Tests
Located in individual package directories alongside source code.

### Integration Tests
End-to-end tests that exercise complete CLI workflows:

1. **Raven Linter E2E Tests** (`raven_linter_e2e_test.go`)
   - Full compliance checking workflow
   - SBOM generation testing
   - Error scenario handling
   - Performance testing with large binaries

2. **Chrome uTLS Generator E2E Tests** (`chrome_utls_gen_e2e_test.go`)
   - ClientHello generation workflow
   - JA3 fingerprint testing
   - Template caching and updates
   - Network connectivity testing

3. **Dual CLI Integration Tests** (`dual_cli_e2e_test.go`)
   - Cross-tool validation
   - Parallel execution testing
   - CI/CD pipeline simulation
   - Performance comparison

### Golden File Testing
Tests use golden files to ensure consistent output:
- Compliance reports (JSON format)
- SBOM outputs (CycloneDX and SPDX formats)
- Chrome handshake metadata

## Running Tests

```bash
# Run all tests
go test ./tests/...

# Run integration tests only
go test ./tests/integration/...

# Run specific test suite
go test ./tests/integration/ -run TestRavenLinterE2E
go test ./tests/integration/ -run TestChromeUtlsGenE2E
go test ./tests/integration/ -run TestDualCLIIntegration

# Run with verbose output
go test -v ./tests/...

# Run short tests only (skip network-dependent tests)
go test -short ./tests/...

# Update golden files
UPDATE_GOLDEN=true go test ./tests/...

# Run with timeout for long-running tests
go test -timeout 10m ./tests/integration/...
```

## Test Configuration

### Environment Variables
- `UPDATE_GOLDEN=true` - Update golden files instead of comparing
- `SKIP_NETWORK_TESTS=true` - Skip tests requiring network connectivity

### Test Timeouts
- Short tests: 5 seconds
- Medium tests: 30 seconds  
- Long tests: 2 minutes

### Test Fixtures
Required test fixtures are validated during test execution:
- Valid ELF binary for compliance testing
- Invalid ELF binary for failure testing
- Corrupted binary for error handling
- Large binary for performance testing
- Chrome handshake golden files
- Configuration files

## CI/CD Integration

The test suite is designed for CI/CD environments:

1. **Build Verification**: Tests build both CLI tools
2. **Functional Testing**: Validates core functionality
3. **Integration Testing**: Tests tool interaction
4. **Performance Testing**: Ensures reasonable execution times
5. **Error Handling**: Validates graceful failure modes

### CI Pipeline Simulation
The `TestCICDSimulation` test simulates a complete CI/CD pipeline:
1. TLS template updates
2. ClientHello generation
3. Compliance checking
4. SBOM generation
5. Artifact validation

## Test Data Management

### Golden Files
Golden files are used for deterministic output validation:
- Update with `UPDATE_GOLDEN=true` when output format changes
- Stored in `tests/golden/` with descriptive names
- Validated for JSON structure and required fields

### Test Fixtures
Binary fixtures are generated using `tests/fixtures/sample_binaries/generate_test_binaries.go`:
- Valid ELF binary with proper metadata
- Invalid ELF binary with compliance issues
- Corrupted binary for error testing
- Large binary for performance testing

## Debugging Tests

### Verbose Output
Use `-v` flag for detailed test output including:
- Test execution progress
- Performance metrics
- Error details
- File paths and sizes

### Test Isolation
Each test uses isolated temporary directories:
- Automatic cleanup after test completion
- No interference between test runs
- Deterministic test execution

### Network Test Handling
Network-dependent tests (JA3 testing, Chrome version updates):
- Gracefully handle connectivity issues
- Skip tests when network is unavailable
- Use reasonable timeouts
- Log network-related failures

## Contributing

When adding new tests:

1. Use the `testutils.TestRunner` for resource management
2. Follow the existing test structure and naming
3. Add golden files for deterministic output validation
4. Include both success and failure scenarios
5. Add performance bounds for long-running operations
6. Document any new test fixtures or requirements