# Chrome TLS Handshake Golden Files

This directory contains golden files for Chrome TLS handshakes used in testing.

## Structure

- `chrome_stable_N/` - Current stable version handshakes
- `chrome_stable_N-2/` - N-2 stable version handshakes
- `ja3_fingerprints.json` - Expected JA3 fingerprints for each version

## Files per version

- `clienthello.bin` - Raw ClientHello bytes
- `ja3_string.txt` - JA3 string representation
- `ja3_hash.txt` - MD5 hash of JA3 string
- `metadata.json` - Version and generation metadata

## Usage

These files are used by integration tests to verify that generated handshakes
match expected Chrome behavior. Update with `UPDATE_GOLDEN=true` environment variable.