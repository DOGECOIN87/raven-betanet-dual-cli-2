package tlsgen

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ClientHelloTemplate represents a generated TLS ClientHello template
type ClientHelloTemplate struct {
	Version     ChromeVersion `json:"version"`
	Bytes       []byte        `json:"bytes"`
	JA3Hash     string        `json:"ja3_hash"`
	JA3String   string        `json:"ja3_string"`
	GeneratedAt time.Time     `json:"generated_at"`
}

// TLSGenerator handles Chrome TLS ClientHello generation
type TLSGenerator struct {
	timeout time.Duration
}

// NewTLSGenerator creates a new TLS generator
func NewTLSGenerator() *TLSGenerator {
	return &TLSGenerator{
		timeout: 10 * time.Second,
	}
}

// NewTLSGeneratorWithTimeout creates a TLS generator with custom timeout
func NewTLSGeneratorWithTimeout(timeout time.Duration) *TLSGenerator {
	return &TLSGenerator{
		timeout: timeout,
	}
}

// GenerateClientHello generates a Chrome-like ClientHello for the given version
func (tg *TLSGenerator) GenerateClientHello(version ChromeVersion) ([]byte, error) {
	// Map Chrome version to appropriate uTLS ClientHelloID
	clientHelloID, err := tg.mapChromeVersionToClientHelloID(version)
	if err != nil {
		return nil, fmt.Errorf("failed to map Chrome version to ClientHelloID: %w", err)
	}

	// Create a temporary connection to capture the ClientHello
	clientHelloBytes, err := tg.captureClientHello(clientHelloID)
	if err != nil {
		return nil, fmt.Errorf("failed to capture ClientHello: %w", err)
	}

	return clientHelloBytes, nil
}

// GenerateTemplate generates a complete ClientHello template with JA3 fingerprint
func (tg *TLSGenerator) GenerateTemplate(version ChromeVersion) (*ClientHelloTemplate, error) {
	clientHelloBytes, err := tg.GenerateClientHello(version)
	if err != nil {
		return nil, err
	}

	// Calculate JA3 fingerprint
	ja3String, ja3Hash, err := tg.calculateJA3(clientHelloBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate JA3 fingerprint: %w", err)
	}

	return &ClientHelloTemplate{
		Version:     version,
		Bytes:       clientHelloBytes,
		JA3Hash:     ja3Hash,
		JA3String:   ja3String,
		GeneratedAt: time.Now(),
	}, nil
}

// mapChromeVersionToClientHelloID maps Chrome version to uTLS ClientHelloID
func (tg *TLSGenerator) mapChromeVersionToClientHelloID(version ChromeVersion) (utls.ClientHelloID, error) {
	// Map Chrome versions to appropriate uTLS fingerprints
	// This mapping is based on Chrome's TLS behavior patterns
	
	switch {
	case version.Major >= 133:
		// Chrome 133+ uses the latest fingerprint
		return utls.HelloChrome_133, nil
	case version.Major >= 131:
		// Chrome 131-132
		return utls.HelloChrome_131, nil
	case version.Major >= 120:
		// Chrome 120-130
		return utls.HelloChrome_120, nil
	case version.Major >= 115:
		// Chrome 115-119 with post-quantum support
		return utls.HelloChrome_115_PQ, nil
	case version.Major >= 106:
		// Chrome 106-114 with extension shuffling
		return utls.HelloChrome_106_Shuffle, nil
	case version.Major >= 102:
		// Chrome 102-105
		return utls.HelloChrome_102, nil
	case version.Major >= 100:
		// Chrome 100-101
		return utls.HelloChrome_100, nil
	case version.Major >= 96:
		// Chrome 96-99
		return utls.HelloChrome_96, nil
	case version.Major >= 87:
		// Chrome 87-95
		return utls.HelloChrome_87, nil
	case version.Major >= 83:
		// Chrome 83-86
		return utls.HelloChrome_83, nil
	case version.Major >= 72:
		// Chrome 72-82
		return utls.HelloChrome_72, nil
	case version.Major >= 70:
		// Chrome 70-71
		return utls.HelloChrome_70, nil
	default:
		// Fallback to Chrome 100 for older versions
		return utls.HelloChrome_100, nil
	}
}

// captureClientHello captures the ClientHello bytes using uTLS
func (tg *TLSGenerator) captureClientHello(clientHelloID utls.ClientHelloID) ([]byte, error) {
	// Create a mock connection to capture the ClientHello
	// We'll use a pipe to capture the raw TLS handshake data
	
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var clientHelloBytes []byte
	var captureErr error

	// Channel to signal completion
	done := make(chan struct{})

	// Server side: capture the ClientHello
	go func() {
		defer close(done)
		
		// Read the ClientHello from the connection
		buffer := make([]byte, 4096)
		n, err := serverConn.Read(buffer)
		if err != nil {
			captureErr = fmt.Errorf("failed to read ClientHello: %w", err)
			return
		}
		
		clientHelloBytes = buffer[:n]
	}()

	// Client side: send the ClientHello
	go func() {
		config := &utls.Config{
			ServerName:         "example.com",
			InsecureSkipVerify: true,
		}

		uConn := utls.UClient(clientConn, config, clientHelloID)
		defer uConn.Close()

		// Trigger the handshake to send ClientHello
		_ = uConn.Handshake()
	}()

	// Wait for completion with timeout
	select {
	case <-done:
		if captureErr != nil {
			return nil, captureErr
		}
		if len(clientHelloBytes) == 0 {
			return nil, fmt.Errorf("no ClientHello data captured")
		}
		return clientHelloBytes, nil
	case <-time.After(tg.timeout):
		return nil, fmt.Errorf("timeout capturing ClientHello")
	}
}

// calculateJA3 calculates JA3 fingerprint from ClientHello bytes
func (tg *TLSGenerator) calculateJA3(clientHelloBytes []byte) (string, string, error) {
	// Use the dedicated JA3Calculator for accurate fingerprint calculation
	calc := NewJA3Calculator()
	ja3, err := calc.CalculateJA3FromBytes(clientHelloBytes)
	if err != nil {
		return "", "", err
	}
	
	return ja3.String, ja3.Hash, nil
}

// extractJA3String extracts JA3 components from ClientHello
func (tg *TLSGenerator) extractJA3String(handshakeData []byte) string {
	// JA3 format: TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
	
	// Parse ClientHello structure
	ch, err := tg.parseClientHello(handshakeData)
	if err != nil {
		// Return a default Chrome-like JA3 string on parse error
		return "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
	}
	
	// Build JA3 string components
	tlsVersion := strconv.Itoa(int(ch.Version))
	cipherSuites := tg.joinInts(ch.CipherSuites, "-")
	extensions := tg.joinInts(ch.Extensions, "-")
	ellipticCurves := tg.joinInts(ch.EllipticCurves, "-")
	ellipticCurvePointFormats := tg.joinInts(ch.EllipticCurvePointFormats, "-")
	
	return fmt.Sprintf("%s,%s,%s,%s,%s", tlsVersion, cipherSuites, extensions, ellipticCurves, ellipticCurvePointFormats)
}

// calculateMD5Hash calculates MD5 hash of the JA3 string
func (tg *TLSGenerator) calculateMD5Hash(ja3String string) string {
	hash := md5.Sum([]byte(ja3String))
	return fmt.Sprintf("%x", hash)
}

// ClientHelloInfo holds parsed ClientHello information for JA3 calculation
type ClientHelloInfo struct {
	Version                    uint16
	CipherSuites              []uint16
	Extensions                []uint16
	EllipticCurves            []uint16
	EllipticCurvePointFormats []uint16
}

// parseClientHello parses ClientHello message to extract JA3 components
func (tg *TLSGenerator) parseClientHello(data []byte) (*ClientHelloInfo, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("ClientHello too short")
	}
	
	// Skip handshake header (4 bytes: type + length)
	offset := 4
	
	if len(data) < offset+2 {
		return nil, fmt.Errorf("ClientHello missing version")
	}
	
	// Parse TLS version (2 bytes)
	version := binary.BigEndian.Uint16(data[offset:offset+2])
	offset += 2
	
	// Skip random (32 bytes)
	if len(data) < offset+32 {
		return nil, fmt.Errorf("ClientHello missing random")
	}
	offset += 32
	
	// Skip session ID
	if len(data) < offset+1 {
		return nil, fmt.Errorf("ClientHello missing session ID length")
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen
	
	// Parse cipher suites
	if len(data) < offset+2 {
		return nil, fmt.Errorf("ClientHello missing cipher suites length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[offset:offset+2]))
	offset += 2
	
	if len(data) < offset+cipherSuitesLen {
		return nil, fmt.Errorf("ClientHello cipher suites truncated")
	}
	
	var cipherSuites []uint16
	for i := 0; i < cipherSuitesLen; i += 2 {
		cipherSuite := binary.BigEndian.Uint16(data[offset+i:offset+i+2])
		cipherSuites = append(cipherSuites, cipherSuite)
	}
	offset += cipherSuitesLen
	
	// Skip compression methods
	if len(data) < offset+1 {
		return nil, fmt.Errorf("ClientHello missing compression methods length")
	}
	compressionLen := int(data[offset])
	offset += 1 + compressionLen
	
	// Parse extensions
	var extensions []uint16
	var ellipticCurves []uint16
	var ellipticCurvePointFormats []uint16
	
	if len(data) >= offset+2 {
		extensionsLen := int(binary.BigEndian.Uint16(data[offset:offset+2]))
		offset += 2
		
		if len(data) >= offset+extensionsLen {
			extensionsData := data[offset:offset+extensionsLen]
			extensions, ellipticCurves, ellipticCurvePointFormats = tg.parseExtensions(extensionsData)
		}
	}
	
	return &ClientHelloInfo{
		Version:                    version,
		CipherSuites:              cipherSuites,
		Extensions:                extensions,
		EllipticCurves:            ellipticCurves,
		EllipticCurvePointFormats: ellipticCurvePointFormats,
	}, nil
}

// parseExtensions parses TLS extensions and extracts relevant information
func (tg *TLSGenerator) parseExtensions(data []byte) ([]uint16, []uint16, []uint16) {
	var extensions []uint16
	var ellipticCurves []uint16
	var ellipticCurvePointFormats []uint16
	
	offset := 0
	for offset < len(data) {
		if len(data) < offset+4 {
			break
		}
		
		extType := binary.BigEndian.Uint16(data[offset:offset+2])
		extLen := int(binary.BigEndian.Uint16(data[offset+2:offset+4]))
		offset += 4
		
		if len(data) < offset+extLen {
			break
		}
		
		extensions = append(extensions, extType)
		
		// Parse specific extensions for JA3
		switch extType {
		case 10: // supported_groups (elliptic curves)
			if extLen >= 2 {
				listLen := int(binary.BigEndian.Uint16(data[offset:offset+2]))
				if extLen >= 2+listLen {
					for i := 2; i < 2+listLen; i += 2 {
						if offset+i+2 <= len(data) {
							curve := binary.BigEndian.Uint16(data[offset+i:offset+i+2])
							ellipticCurves = append(ellipticCurves, curve)
						}
					}
				}
			}
		case 11: // ec_point_formats
			if extLen >= 1 {
				listLen := int(data[offset])
				for i := 1; i < 1+listLen && i < extLen; i++ {
					ellipticCurvePointFormats = append(ellipticCurvePointFormats, uint16(data[offset+i]))
				}
			}
		}
		
		offset += extLen
	}
	
	// Sort extensions for JA3 (excluding GREASE values)
	extensions = tg.filterAndSortExtensions(extensions)
	
	return extensions, ellipticCurves, ellipticCurvePointFormats
}

// filterAndSortExtensions filters out GREASE values and sorts extensions
func (tg *TLSGenerator) filterAndSortExtensions(extensions []uint16) []uint16 {
	if len(extensions) == 0 {
		return []uint16{}
	}
	
	var filtered []uint16
	
	for _, ext := range extensions {
		// Filter out GREASE values (0x?A?A pattern)
		if !tg.isGREASE(ext) {
			filtered = append(filtered, ext)
		}
	}
	
	// Sort extensions
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i] < filtered[j]
	})
	
	return filtered
}

// isGREASE checks if a value is a GREASE value
func (tg *TLSGenerator) isGREASE(value uint16) bool {
	// GREASE values follow the pattern 0x?A?A where both nibbles are the same
	return (value&0x0F0F) == 0x0A0A && ((value&0xF000)>>12) == ((value&0x00F0)>>4)
}

// joinInts joins a slice of uint16 values with a separator
func (tg *TLSGenerator) joinInts(values []uint16, sep string) string {
	if len(values) == 0 {
		return ""
	}
	
	var parts []string
	for _, v := range values {
		parts = append(parts, strconv.Itoa(int(v)))
	}
	
	return strings.Join(parts, sep)
}

// GetSupportedVersions returns the Chrome versions supported by this generator
func (tg *TLSGenerator) GetSupportedVersions() []ChromeVersion {
	// Return a list of Chrome versions that we can generate ClientHellos for
	supportedVersions := []ChromeVersion{
		{Major: 120, Minor: 0, Build: 6099, Patch: 109},
		{Major: 119, Minor: 0, Build: 6045, Patch: 105},
		{Major: 118, Minor: 0, Build: 5993, Patch: 88},
		{Major: 117, Minor: 0, Build: 5938, Patch: 92},
		{Major: 116, Minor: 0, Build: 5845, Patch: 96},
		{Major: 115, Minor: 0, Build: 5790, Patch: 102},
		{Major: 114, Minor: 0, Build: 5735, Patch: 90},
		{Major: 113, Minor: 0, Build: 5672, Patch: 63},
		{Major: 112, Minor: 0, Build: 5615, Patch: 49},
	}
	
	return supportedVersions
}