package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	// Sample Chrome ClientHello bytes (simplified for testing)
	// This represents a typical Chrome TLS 1.3 handshake
	clientHelloHex := "16030100f4010000f00303" + // TLS record header + handshake header
		"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" + // Random
		"00" + // Session ID length
		"001a" + // Cipher suites length
		"1301130213031302c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035" + // Cipher suites
		"0100" + // Compression methods
		"0075" + // Extensions length
		// SNI extension
		"00000010000e00000b6578616d706c652e636f6d" +
		// Supported groups
		"000a00080006001d00170018" +
		// Signature algorithms
		"000d00140012040308040401050308050501080606010201" +
		// Supported versions
		"002b00030203040304"

	clientHelloBytes, err := hex.DecodeString(clientHelloHex)
	if err != nil {
		fmt.Printf("Error decoding hex: %v\n", err)
		return
	}

	// Write to chrome_stable_N directory
	stableNPath := filepath.Join("chrome_stable_N", "clienthello.bin")
	if err := os.WriteFile(stableNPath, clientHelloBytes, 0644); err != nil {
		fmt.Printf("Error writing stable N file: %v\n", err)
		return
	}

	fmt.Printf("Generated ClientHello binary: %s (%d bytes)\n", stableNPath, len(clientHelloBytes))
}