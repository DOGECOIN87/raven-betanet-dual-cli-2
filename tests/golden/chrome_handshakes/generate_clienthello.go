package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ChromeHandshakeGolden represents a golden Chrome handshake for testing
type ChromeHandshakeGolden struct {
	Version     string    `json:"version"`
	JA3String   string    `json:"ja3_string"`
	JA3Hash     string    `json:"ja3_hash"`
	GeneratedAt time.Time `json:"generated_at"`
	Metadata    struct {
		UTLSFingerprint string   `json:"utls_fingerprint"`
		TLSVersion      string   `json:"tls_version"`
		CipherSuites    []string `json:"cipher_suites"`
		Extensions      []string `json:"extensions"`
	} `json:"metadata"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <chrome-version>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s 120.0.6099.109\n", os.Args[0])
		os.Exit(1)
	}

	chromeVersion := os.Args[1]
	
	// Generate ClientHello for the specified Chrome version
	clientHelloBytes, ja3String, ja3Hash, err := generateChromeClientHello(chromeVersion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate ClientHello: %v\n", err)
		os.Exit(1)
	}

	// Create output directory
	outputDir := fmt.Sprintf("chrome_stable_%s", chromeVersion)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	// Write ClientHello binary
	clientHelloPath := filepath.Join(outputDir, "clienthello.bin")
	if err := os.WriteFile(clientHelloPath, clientHelloBytes, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write ClientHello binary: %v\n", err)
		os.Exit(1)
	}

	// Write JA3 string
	ja3StringPath := filepath.Join(outputDir, "ja3_string.txt")
	if err := os.WriteFile(ja3StringPath, []byte(ja3String), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write JA3 string: %v\n", err)
		os.Exit(1)
	}

	// Write JA3 hash
	ja3HashPath := filepath.Join(outputDir, "ja3_hash.txt")
	if err := os.WriteFile(ja3HashPath, []byte(ja3Hash), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write JA3 hash: %v\n", err)
		os.Exit(1)
	}

	// Create metadata
	golden := ChromeHandshakeGolden{
		Version:     chromeVersion,
		JA3String:   ja3String,
		JA3Hash:     ja3Hash,
		GeneratedAt: time.Now(),
	}

	golden.Metadata.UTLSFingerprint = getUTLSFingerprintForVersion(chromeVersion)
	golden.Metadata.TLSVersion = "TLS 1.3"
	golden.Metadata.CipherSuites = []string{
		"TLS_AES_128_GCM_SHA256",
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
	}
	golden.Metadata.Extensions = []string{
		"server_name",
		"status_request",
		"supported_groups",
		"signature_algorithms",
		"application_layer_protocol_negotiation",
		"key_share",
		"supported_versions",
	}

	// Write metadata
	metadataPath := filepath.Join(outputDir, "metadata.json")
	metadataBytes, err := json.MarshalIndent(golden, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal metadata: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(metadataPath, metadataBytes, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write metadata: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated golden files for Chrome %s in %s/\n", chromeVersion, outputDir)
	fmt.Printf("Files created:\n")
	fmt.Printf("  - clienthello.bin (%d bytes)\n", len(clientHelloBytes))
	fmt.Printf("  - ja3_string.txt\n")
	fmt.Printf("  - ja3_hash.txt\n")
	fmt.Printf("  - metadata.json\n")
}

// generateChromeClientHello generates a ClientHello for the specified Chrome version
func generateChromeClientHello(version string) ([]byte, string, string, error) {
	// Map Chrome version to uTLS ClientHelloID
	clientHelloID := getClientHelloIDForVersion(version)

	// Create uTLS config
	config := &utls.Config{
		ServerName: "example.com",
		NextProtos: []string{"h2", "http/1.1"},
	}

	// Create uTLS connection (without actually connecting)
	conn := utls.UClient(nil, config, clientHelloID)

	// Build the ClientHello
	err := conn.BuildHandshakeState()
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to build handshake state: %w", err)
	}

	// Get the ClientHello message
	clientHello := conn.HandshakeState.Hello
	if clientHello == nil {
		return nil, "", "", fmt.Errorf("failed to generate ClientHello message")
	}

	// Marshal the ClientHello to bytes
	clientHelloBytes, err := clientHello.Marshal()
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to marshal ClientHello: %w", err)
	}

	// Calculate JA3 fingerprint (simplified)
	ja3String := calculateJA3String(clientHello)
	ja3Hash := calculateJA3Hash(ja3String)

	return clientHelloBytes, ja3String, ja3Hash, nil
}

// getClientHelloIDForVersion maps Chrome version to uTLS ClientHelloID
func getClientHelloIDForVersion(version string) utls.ClientHelloID {
	// This is a simplified mapping - real implementation would parse version properly
	switch {
	case version >= "133":
		return utls.HelloChrome_133
	case version >= "131":
		return utls.HelloChrome_131
	case version >= "120":
		return utls.HelloChrome_120
	case version >= "115":
		return utls.HelloChrome_115_PQ
	case version >= "106":
		return utls.HelloChrome_106_Shuffle
	case version >= "102":
		return utls.HelloChrome_102
	case version >= "100":
		return utls.HelloChrome_100
	default:
		return utls.HelloChrome_100
	}
}

// getUTLSFingerprintForVersion returns the uTLS fingerprint name for a Chrome version
func getUTLSFingerprintForVersion(version string) string {
	switch {
	case version >= "133":
		return "HelloChrome_133"
	case version >= "131":
		return "HelloChrome_131"
	case version >= "120":
		return "HelloChrome_120"
	case version >= "115":
		return "HelloChrome_115_PQ"
	case version >= "106":
		return "HelloChrome_106_Shuffle"
	case version >= "102":
		return "HelloChrome_102"
	case version >= "100":
		return "HelloChrome_100"
	default:
		return "HelloChrome_100"
	}
}

// calculateJA3String calculates JA3 string from ClientHello (simplified)
func calculateJA3String(clientHello *utls.ClientHelloMsg) string {
	// This is a simplified JA3 calculation for golden file generation
	// Real implementation would properly parse all ClientHello fields
	
	// TLS version
	tlsVersion := fmt.Sprintf("%d", clientHello.Vers)
	
	// Cipher suites
	var cipherSuites []string
	for _, suite := range clientHello.CipherSuites {
		cipherSuites = append(cipherSuites, fmt.Sprintf("%d", suite))
	}
	cipherSuitesStr := strings.Join(cipherSuites, "-")
	
	// Extensions (simplified)
	var extensions []string
	for _, ext := range clientHello.Extensions {
		extensions = append(extensions, fmt.Sprintf("%d", ext.ExtensionType()))
	}
	extensionsStr := strings.Join(extensions, "-")
	
	// Elliptic curves and formats (simplified)
	ellipticCurves := "29-23-24"  // X25519, secp256r1, secp384r1
	ellipticFormats := "0"        // uncompressed
	
	return fmt.Sprintf("%s,%s,%s,%s,%s", tlsVersion, cipherSuitesStr, extensionsStr, ellipticCurves, ellipticFormats)
}

// calculateJA3Hash calculates MD5 hash of JA3 string
func calculateJA3Hash(ja3String string) string {
	hash := md5.Sum([]byte(ja3String))
	return fmt.Sprintf("%x", hash)
}