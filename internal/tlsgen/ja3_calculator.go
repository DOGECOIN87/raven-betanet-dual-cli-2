package tlsgen

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// JA3Calculator handles JA3 fingerprint calculation and testing
type JA3Calculator struct {
	timeout time.Duration
}

// NewJA3Calculator creates a new JA3 calculator
func NewJA3Calculator() *JA3Calculator {
	return &JA3Calculator{
		timeout: 10 * time.Second,
	}
}

// NewJA3CalculatorWithTimeout creates a JA3 calculator with custom timeout
func NewJA3CalculatorWithTimeout(timeout time.Duration) *JA3Calculator {
	return &JA3Calculator{
		timeout: timeout,
	}
}

// ConnectionResult represents the result of a JA3 test connection
type ConnectionResult struct {
	Target          string        `json:"target"`
	Connected       bool          `json:"connected"`
	JA3Fingerprint  string        `json:"ja3_fingerprint"`
	JA3String       string        `json:"ja3_string"`
	TLSVersion      string        `json:"tls_version"`
	CipherSuite     string        `json:"cipher_suite"`
	ResponseTime    time.Duration `json:"response_time"`
	Error           string        `json:"error,omitempty"`
}

// JA3Fingerprint represents a complete JA3 fingerprint
type JA3Fingerprint struct {
	String string `json:"string"`
	Hash   string `json:"hash"`
}

// CalculateJA3FromBytes calculates JA3 fingerprint from raw ClientHello bytes
func (calc *JA3Calculator) CalculateJA3FromBytes(clientHelloBytes []byte) (*JA3Fingerprint, error) {
	// Parse the TLS record to extract ClientHello
	if len(clientHelloBytes) < 5 {
		return nil, fmt.Errorf("ClientHello too short: %d bytes", len(clientHelloBytes))
	}

	// Basic TLS record parsing
	// TLS record format: [type(1)][version(2)][length(2)][data...]
	if clientHelloBytes[0] != 0x16 { // Handshake record type
		return nil, fmt.Errorf("not a TLS handshake record, got type: 0x%02x", clientHelloBytes[0])
	}

	// Skip TLS record header (5 bytes) to get to handshake message
	if len(clientHelloBytes) < 9 {
		return nil, fmt.Errorf("ClientHello handshake message too short: %d bytes", len(clientHelloBytes))
	}

	handshakeData := clientHelloBytes[5:]
	if handshakeData[0] != 0x01 { // ClientHello handshake type
		return nil, fmt.Errorf("not a ClientHello message, got type: 0x%02x", handshakeData[0])
	}

	// Parse ClientHello and extract JA3 components
	ja3String, err := calc.extractJA3String(handshakeData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JA3 string: %w", err)
	}

	ja3Hash := calc.calculateMD5Hash(ja3String)

	return &JA3Fingerprint{
		String: ja3String,
		Hash:   ja3Hash,
	}, nil
}

// TestConnection tests a connection to a target server and extracts JA3 fingerprint
func (calc *JA3Calculator) TestConnection(target string, clientHelloID utls.ClientHelloID) (*ConnectionResult, error) {
	startTime := time.Now()
	
	result := &ConnectionResult{
		Target:    target,
		Connected: false,
	}

	// Parse target to ensure it has a port
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		// If no port specified, assume HTTPS (443)
		host = target
		port = "443"
		target = net.JoinHostPort(host, port)
	}

	// Create TLS connection with uTLS
	conn, err := net.DialTimeout("tcp", target, calc.timeout)
	if err != nil {
		result.Error = fmt.Sprintf("failed to connect: %v", err)
		result.ResponseTime = time.Since(startTime)
		return result, nil
	}
	defer conn.Close()

	// Create uTLS connection
	config := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // For testing purposes
	}

	uConn := utls.UClient(conn, config, clientHelloID)
	defer uConn.Close()

	// Perform handshake
	err = uConn.Handshake()
	if err != nil {
		result.Error = fmt.Sprintf("TLS handshake failed: %v", err)
		result.ResponseTime = time.Since(startTime)
		return result, nil
	}

	result.Connected = true
	result.ResponseTime = time.Since(startTime)

	// Get connection state
	state := uConn.ConnectionState()
	result.TLSVersion = calc.tlsVersionToString(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	// Extract JA3 fingerprint from the ClientHello we sent
	clientHelloBytes, err := calc.captureClientHelloBytes(clientHelloID)
	if err != nil {
		result.Error = fmt.Sprintf("failed to capture ClientHello: %v", err)
		return result, nil
	}

	ja3, err := calc.CalculateJA3FromBytes(clientHelloBytes)
	if err != nil {
		result.Error = fmt.Sprintf("failed to calculate JA3: %v", err)
		return result, nil
	}

	result.JA3String = ja3.String
	result.JA3Fingerprint = ja3.Hash

	return result, nil
}

// VerifyJA3Fingerprint verifies that a JA3 fingerprint matches expected Chrome signatures
func (calc *JA3Calculator) VerifyJA3Fingerprint(ja3Hash string, expectedHashes []string) bool {
	for _, expected := range expectedHashes {
		if strings.EqualFold(ja3Hash, expected) {
			return true
		}
	}
	return false
}

// GetKnownChromeJA3Hashes returns known JA3 hashes for different Chrome versions
func (calc *JA3Calculator) GetKnownChromeJA3Hashes() map[string][]string {
	return map[string][]string{
		"chrome_120+": {
			"cd08e31494f9531f560d64c695473da9", // Chrome 120+ typical JA3
			"b32309a26951912be7dba376398abc3b", // Chrome 120+ alternative
		},
		"chrome_115-119": {
			"72a589da586844d7f0818ce684948eea", // Chrome 115-119 typical JA3
			"a0e9f5d64349fb13191bc781f81f42e1", // Chrome 115-119 alternative
		},
		"chrome_100-114": {
			"769,47-53-5-10-49171-49172-49161-49162-52393-52392-49175-49176-49169-49170-49165-49166-49199-49200-49195-49196-49188-49192-49162-49172-136-135-57-56,0-5-10-11-13-18-23-27-35-43-45-51-65281,23-24-25,0",
		},
	}
}

// extractJA3String extracts JA3 components from ClientHello handshake data
func (calc *JA3Calculator) extractJA3String(handshakeData []byte) (string, error) {
	// Parse ClientHello structure
	ch, err := calc.parseClientHelloForJA3(handshakeData)
	if err != nil {
		return "", fmt.Errorf("failed to parse ClientHello: %w", err)
	}
	
	// Build JA3 string components
	tlsVersion := strconv.Itoa(int(ch.Version))
	cipherSuites := calc.joinInts(ch.CipherSuites, "-")
	extensions := calc.joinInts(ch.Extensions, "-")
	ellipticCurves := calc.joinInts(ch.EllipticCurves, "-")
	ellipticCurvePointFormats := calc.joinInts(ch.EllipticCurvePointFormats, "-")
	
	return fmt.Sprintf("%s,%s,%s,%s,%s", tlsVersion, cipherSuites, extensions, ellipticCurves, ellipticCurvePointFormats), nil
}

// calculateMD5Hash calculates MD5 hash of the JA3 string
func (calc *JA3Calculator) calculateMD5Hash(ja3String string) string {
	hash := md5.Sum([]byte(ja3String))
	return fmt.Sprintf("%x", hash)
}

// ClientHelloJA3Info holds parsed ClientHello information for JA3 calculation
type ClientHelloJA3Info struct {
	Version                    uint16
	CipherSuites              []uint16
	Extensions                []uint16
	EllipticCurves            []uint16
	EllipticCurvePointFormats []uint16
}

// parseClientHelloForJA3 parses ClientHello message to extract JA3 components
func (calc *JA3Calculator) parseClientHelloForJA3(data []byte) (*ClientHelloJA3Info, error) {
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
			extensions, ellipticCurves, ellipticCurvePointFormats = calc.parseExtensionsForJA3(extensionsData)
		}
	}
	
	// Filter GREASE values and sort for JA3
	cipherSuites = calc.filterGREASEFromCipherSuites(cipherSuites)
	extensions = calc.filterAndSortExtensions(extensions)
	
	return &ClientHelloJA3Info{
		Version:                    version,
		CipherSuites:              cipherSuites,
		Extensions:                extensions,
		EllipticCurves:            ellipticCurves,
		EllipticCurvePointFormats: ellipticCurvePointFormats,
	}, nil
}

// parseExtensionsForJA3 parses TLS extensions and extracts relevant information for JA3
func (calc *JA3Calculator) parseExtensionsForJA3(data []byte) ([]uint16, []uint16, []uint16) {
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
	
	return extensions, ellipticCurves, ellipticCurvePointFormats
}

// filterGREASEFromCipherSuites filters out GREASE values from cipher suites
func (calc *JA3Calculator) filterGREASEFromCipherSuites(cipherSuites []uint16) []uint16 {
	if len(cipherSuites) == 0 {
		return []uint16{}
	}
	
	var filtered []uint16
	
	for _, suite := range cipherSuites {
		if !calc.isGREASE(suite) {
			filtered = append(filtered, suite)
		}
	}
	
	if len(filtered) == 0 {
		return []uint16{}
	}
	
	return filtered
}

// filterAndSortExtensions filters out GREASE values and sorts extensions for JA3
func (calc *JA3Calculator) filterAndSortExtensions(extensions []uint16) []uint16 {
	if len(extensions) == 0 {
		return []uint16{}
	}
	
	var filtered []uint16
	
	for _, ext := range extensions {
		// Filter out GREASE values (0x?A?A pattern)
		if !calc.isGREASE(ext) {
			filtered = append(filtered, ext)
		}
	}
	
	// Sort extensions for JA3 (maintain original order, don't sort)
	// JA3 specification requires original order, not sorted order
	return filtered
}

// isGREASE checks if a value is a GREASE value
func (calc *JA3Calculator) isGREASE(value uint16) bool {
	// GREASE values follow the pattern 0x?A?A where both nibbles are the same
	return (value&0x0F0F) == 0x0A0A && ((value&0xF000)>>12) == ((value&0x00F0)>>4)
}

// joinInts joins a slice of uint16 values with a separator
func (calc *JA3Calculator) joinInts(values []uint16, sep string) string {
	if len(values) == 0 {
		return ""
	}
	
	var parts []string
	for _, v := range values {
		parts = append(parts, strconv.Itoa(int(v)))
	}
	
	return strings.Join(parts, sep)
}

// tlsVersionToString converts TLS version number to string
func (calc *JA3Calculator) tlsVersionToString(version uint16) string {
	switch version {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// captureClientHelloBytes captures the raw ClientHello bytes for a given ClientHelloID
func (calc *JA3Calculator) captureClientHelloBytes(clientHelloID utls.ClientHelloID) ([]byte, error) {
	// Create a mock connection to capture the ClientHello
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
	case <-time.After(calc.timeout):
		return nil, fmt.Errorf("timeout capturing ClientHello")
	}
}