# Sample Binary Fixtures

This directory contains binary files used for compliance testing.

## Files

- `valid_elf_binary` - A valid ELF binary that should pass all compliance checks
- `invalid_elf_binary` - An ELF binary with compliance issues for testing failure scenarios
- `valid_pe_binary.exe` - A valid PE binary for Windows compatibility testing
- `valid_macho_binary` - A valid Mach-O binary for macOS compatibility testing
- `corrupted_binary` - A corrupted binary file for error handling tests
- `large_binary` - A large binary (>100MB) for performance testing

## Generation

These binaries are generated using the `generate_test_binaries.go` script.
Run `go run generate_test_binaries.go` to regenerate test fixtures.

## Security Note

These are test fixtures only and contain no malicious code.
They are minimal binaries created specifically for testing purposes.