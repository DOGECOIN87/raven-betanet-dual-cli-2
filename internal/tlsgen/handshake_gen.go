package tlsgen

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ClientHelloTemplate represents a generated Chrome ClientHello template
type ClientHelloTemplate struct {
	Version     ChromeVersion `json:"version"`
	Bytes       []byte        `json:"bytes"`
	JA3String   string        `json:"ja3_string"`
	JA3Hash     string        `json:"ja3_hash"`
	GeneratedAt time.Time     `json:"generated_at"`
	Metadata    TemplateMetadata `json:"metadata"`
}

// TemplateMetadata contains additional information about the template
type TemplateMetadata struct {
	UTLSFingerprint    string   `json:"utls_fingerprint"`
	TLSVersions        []string `json:"tls_versions"`
	CipherSuites       []string `json:"cipher_suites"`
	SupportedGroups    []string `json:"supported_groups"`
	SignatureAlgorithms []string `json:"signature_algorithms"`
	ALPNProtocols      []string `json:"alpn_protocols"`
	Extensions         []string `json:"extensions"`
}

// TLSGenerator handles generation of Chrome TLS ClientHello templates
type TLSGenerator struct {
	randomSource func([]byte) (int, error)
}

// NewTLSGenerator creates a new TLS generator
func NewTLSGenerator() *TLSGenerator {
	return &TLSGenerator{
		randomSource: rand.Read,
	}
}

// NewTLSGeneratorWithRandomSource creates a TLS generator with custom random source
func NewTLSGeneratorWithRandomSource(randomSource func([]byte) (int, error)) *TLSGenerator {
	return &TLSGenerator{
		randomSource: randomSource,
	}
}

// GenerateTemplate generates a ClientHello template for the specified Chrome version
func (g *TLSGenerator) GenerateTemplate(version ChromeVersion) (*ClientHelloTemplate, error) {
	// Validate Chrome version
	if err := version.Validate(); err != nil {
		return nil, fmt.Errorf("invalid Chrome version: %w", err)
	}

	if !version.IsSupported() {
		return nil, fmt.Errorf("Chrome version %s is not supported (minimum: 70)", version.String())
	}

	// Map Chrome version to uTLS ClientHelloID
	clientHelloID, err := g.mapVersionToClientHelloID(version)
	if err != nil {
		return nil, fmt.Errorf("failed to map Chrome version to uTLS fingerprint: %w", err)
	}

	// Generate ClientHello bytes
	clientHelloBytes, err := g.generateClientHelloBytes(clientHelloID, version)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ClientHello bytes: %w", err)
	}

	// Calculate JA3 fingerprint
	ja3String, ja3Hash, err := g.calculateJA3FromBytes(clientHelloBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate JA3 fingerprint: %w", err)
	}

	// Create template metadata
	metadata := g.createTemplateMetadata(version, clientHelloID)

	template := &ClientHelloTemplate{
		Version:     version,
		Bytes:       clientHelloBytes,
		JA3String:   ja3String,
		JA3Hash:     ja3Hash,
		GeneratedAt: time.Now(),
		Metadata:    metadata,
	}

	return template, nil
}

// mapVersionToClientHelloID maps a Chrome version to the appropriate uTLS ClientHelloID
func (g *TLSGenerator) mapVersionToClientHelloID(version ChromeVersion) (utls.ClientHelloID, error) {
	switch {
	case version.Major >= 133:
		return utls.HelloChrome_133, nil
	case version.Major >= 131:
		return utls.HelloChrome_131, nil
	case version.Major >= 120:
		return utls.HelloChrome_120, nil
	case version.Major >= 115:
		return utls.HelloChrome_115_PQ, nil
	case version.Major >= 106:
		return utls.HelloChrome_106_Shuffle, nil
	case version.Major >= 102:
		return utls.HelloChrome_102, nil
	case version.Major >= 100:
		return utls.HelloChrome_100, nil
	case version.Major >= 96:
		return utls.HelloChrome_96, nil
	case version.Major >= 87:
		return utls.HelloChrome_87, nil
	case version.Major >= 83:
		return utls.HelloChrome_83, nil
	case version.Major >= 72:
		return utls.HelloChrome_72, nil
	case version.Major >= 70:
		return utls.HelloChrome_70, nil
	default:
		return utls.HelloChrome_100, fmt.Errorf("unsupported Chrome version: %s", version.String())
	}
}

// generateClientHelloBytes generates the actual ClientHello bytes using uTLS
func (g *TLSGenerator) generateClientHelloBytes(clientHelloID utls.ClientHelloID, version ChromeVersion) ([]byte, error) {
	// Create a uTLS config
	config := &utls.Config{
		ServerName: "example.com", // Dummy server name for ClientHello generation
		NextProtos: version.GetALPNProtocols(),
	}

	// Create uTLS connection (without actually connecting)
	conn := utls.UClient(nil, config, clientHelloID)

	// Build the ClientHello
	err := conn.BuildHandshakeState()
	if err != nil {
		return nil, fmt.Errorf("failed to build handshake state: %w", err)
	}

	// Get the ClientHello message
	clientHello := conn.HandshakeState.Hello

	if clientHello == nil {
		return nil, fmt.Errorf("failed to generate ClientHello message")
	}

	// Marshal the ClientHello to bytes
	clientHelloBytes, err := clientHello.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ClientHello: %w", err)
	}

	// Ensure deterministic output by setting consistent random values
	// This is important for reproducible ClientHello generation
	if err := g.makeDeterministic(clientHelloBytes, version); err != nil {
		return nil, fmt.Errorf("failed to make ClientHello deterministic: %w", err)
	}

	return clientHelloBytes, nil
}

// makeDeterministic ensures the ClientHello is deterministic by replacing random values
func (g *TLSGenerator) makeDeterministic(clientHelloBytes []byte, version ChromeVersion) error {
	// For deterministic ClientHello generation, we need to replace random values
	// with predictable ones based on the Chrome version
	
	// The ClientHello contains a 32-byte random field at a fixed offset
	// We'll replace it with a deterministic value based on the version
	if len(clientHelloBytes) < 43 { // Minimum ClientHello size
		return fmt.Errorf("ClientHello too short: %d bytes", len(clientHelloBytes))
	}

	// Find the random field in the ClientHello (typically at offset 11-42)
	// This is a simplified approach - real implementation might need more sophisticated parsing
	randomOffset := 11
	if len(clientHelloBytes) >= randomOffset+32 {
		// Generate deterministic "random" bytes based on version
		deterministicRandom := g.generateDeterministicRandom(version)
		copy(clientHelloBytes[randomOffset:randomOffset+32], deterministicRandom)
	}

	return nil
}

// generateDeterministicRandom generates deterministic "random" bytes based on Chrome version
func (g *TLSGenerator) generateDeterministicRandom(version ChromeVersion) []byte {
	// Create a deterministic 32-byte array based on the Chrome version
	random := make([]byte, 32)
	
	// Use version components to create deterministic values
	versionBytes := []byte(fmt.Sprintf("%d.%d.%d.%d", version.Major, version.Minor, version.Build, version.Patch))
	
	// Fill the random array with deterministic values
	for i := 0; i < 32; i++ {
		if i < len(versionBytes) {
			random[i] = versionBytes[i]
		} else {
			// Use a simple pattern based on version and position
			random[i] = byte((version.Major + version.Minor + i) % 256)
		}
	}
	
	return random
}

// calculateJA3FromBytes calculates JA3 fingerprint from ClientHello bytes
func (g *TLSGenerator) calculateJA3FromBytes(clientHelloBytes []byte) (string, string, error) {
	// Parse the ClientHello to extract JA3 components
	ja3Components, err := g.parseClientHelloForJA3(clientHelloBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse ClientHello for JA3: %w", err)
	}

	// Build JA3 string
	ja3String := g.buildJA3String(ja3Components)

	// Calculate JA3 hash
	ja3Hash := g.calculateJA3Hash(ja3String)

	return ja3String, ja3Hash, nil
}

// JA3Components represents the components needed for JA3 calculation
type JA3Components struct {
	TLSVersion          uint16
	CipherSuites        []uint16
	Extensions          []uint16
	EllipticCurves      []uint16
	EllipticCurveFormats []uint8
}

// parseClientHelloForJA3 parses ClientHello bytes to extract JA3 components
func (g *TLSGenerator) parseClientHelloForJA3(clientHelloBytes []byte) (*JA3Components, error) {
	// This is a simplified JA3 parsing implementation
	// Real implementation would need full TLS message parsing
	
	if len(clientHelloBytes) < 43 {
		return nil, fmt.Errorf("ClientHello too short for JA3 parsing")
	}

	components := &JA3Components{}

	// Parse TLS version (bytes 9-10 in ClientHello)
	if len(clientHelloBytes) >= 11 {
		components.TLSVersion = uint16(clientHelloBytes[9])<<8 | uint16(clientHelloBytes[10])
	}

	// For a complete implementation, we would parse:
	// - Cipher suites list
	// - Extensions list  
	// - Elliptic curves from supported_groups extension
	// - EC point formats from ec_point_formats extension

	// Simplified implementation with common Chrome values
	components.CipherSuites = []uint16{
		0x1301, // TLS_AES_128_GCM_SHA256
		0x1302, // TLS_AES_256_GCM_SHA384
		0x1303, // TLS_CHACHA20_POLY1305_SHA256
		0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
		0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	}

	components.Extensions = []uint16{
		0,     // server_name
		5,     // status_request
		10,    // supported_groups
		11,    // ec_point_formats
		13,    // signature_algorithms
		16,    // application_layer_protocol_negotiation
		18,    // signed_certificate_timestamp
		21,    // padding
		23,    // extended_master_secret
		27,    // compress_certificate
		35,    // session_ticket
		43,    // supported_versions
		45,    // psk_key_exchange_modes
		51,    // key_share
		17513, // application_settings
	}

	components.EllipticCurves = []uint16{
		29, // X25519
		23, // secp256r1
		24, // secp384r1
	}

	components.EllipticCurveFormats = []uint8{
		0, // uncompressed
	}

	return components, nil
}

// buildJA3String builds the JA3 string from components
func (g *TLSGenerator) buildJA3String(components *JA3Components) string {
	// JA3 format: TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurveFormats
	
	// Convert components to comma-separated strings
	cipherSuites := g.uint16SliceToString(components.CipherSuites)
	extensions := g.uint16SliceToString(components.Extensions)
	ellipticCurves := g.uint16SliceToString(components.EllipticCurves)
	ellipticCurveFormats := g.uint8SliceToString(components.EllipticCurveFormats)

	return fmt.Sprintf("%d,%s,%s,%s,%s",
		components.TLSVersion,
		cipherSuites,
		extensions,
		ellipticCurves,
		ellipticCurveFormats,
	)
}

// uint16SliceToString converts a slice of uint16 to comma-separated string
func (g *TLSGenerator) uint16SliceToString(slice []uint16) string {
	if len(slice) == 0 {
		return ""
	}

	result := fmt.Sprintf("%d", slice[0])
	for i := 1; i < len(slice); i++ {
		result += fmt.Sprintf("-%d", slice[i])
	}
	return result
}

// uint8SliceToString converts a slice of uint8 to comma-separated string
func (g *TLSGenerator) uint8SliceToString(slice []uint8) string {
	if len(slice) == 0 {
		return ""
	}

	result := fmt.Sprintf("%d", slice[0])
	for i := 1; i < len(slice); i++ {
		result += fmt.Sprintf("-%d", slice[i])
	}
	return result
}

// calculateJA3Hash calculates MD5 hash of JA3 string
func (g *TLSGenerator) calculateJA3Hash(ja3String string) string {
	// Note: MD5 is used here because it's part of the JA3 specification
	hash := md5.Sum([]byte(ja3String))
	return fmt.Sprintf("%x", hash)
}

// createTemplateMetadata creates metadata for the template
func (g *TLSGenerator) createTemplateMetadata(version ChromeVersion, clientHelloID utls.ClientHelloID) TemplateMetadata {
	return TemplateMetadata{
		UTLSFingerprint:     version.GetUTLSFingerprint(),
		TLSVersions:         version.GetTLSVersions(),
		CipherSuites:        version.GetCipherSuites(),
		SupportedGroups:     version.GetSupportedGroups(),
		SignatureAlgorithms: version.GetSignatureAlgorithms(),
		ALPNProtocols:       version.GetALPNProtocols(),
		Extensions:          g.getExtensionNames(version),
	}
}

// getExtensionNames returns the TLS extension names for the Chrome version
func (g *TLSGenerator) getExtensionNames(version ChromeVersion) []string {
	extensions := []string{
		"server_name",
		"status_request",
		"supported_groups",
		"ec_point_formats",
		"signature_algorithms",
		"application_layer_protocol_negotiation",
		"signed_certificate_timestamp",
		"padding",
		"extended_master_secret",
		"compress_certificate",
		"session_ticket",
		"supported_versions",
		"psk_key_exchange_modes",
		"key_share",
		"application_settings",
	}

	// Add version-specific extensions
	if version.HasPostQuantumSupport() {
		extensions = append(extensions, "post_quantum_key_share")
	}

	if version.HasExtensionShuffling() {
		extensions = append(extensions, "extension_shuffling")
	}

	return extensions
}

// ValidateTemplate validates a ClientHello template
func (g *TLSGenerator) ValidateTemplate(template *ClientHelloTemplate) error {
	if template == nil {
		return fmt.Errorf("template is nil")
	}

	if err := template.Version.Validate(); err != nil {
		return fmt.Errorf("invalid version: %w", err)
	}

	if len(template.Bytes) == 0 {
		return fmt.Errorf("template bytes are empty")
	}

	if template.JA3String == "" {
		return fmt.Errorf("JA3 string is empty")
	}

	if template.JA3Hash == "" {
		return fmt.Errorf("JA3 hash is empty")
	}

	if template.GeneratedAt.IsZero() {
		return fmt.Errorf("generation timestamp is zero")
	}

	return nil
}

// CompareTemplates compares two templates for equality
func (g *TLSGenerator) CompareTemplates(template1, template2 *ClientHelloTemplate) bool {
	if template1 == nil || template2 == nil {
		return false
	}

	if !template1.Version.Equal(template2.Version) {
		return false
	}

	if len(template1.Bytes) != len(template2.Bytes) {
		return false
	}

	for i, b := range template1.Bytes {
		if b != template2.Bytes[i] {
			return false
		}
	}

	return template1.JA3Hash == template2.JA3Hash
}