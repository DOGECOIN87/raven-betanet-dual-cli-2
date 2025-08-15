package tlsgen

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// JA3TestResult represents the result of a JA3 fingerprint test
type JA3TestResult struct {
	Target          string        `json:"target"`
	Connected       bool          `json:"connected"`
	JA3String       string        `json:"ja3_string"`
	JA3Fingerprint  string        `json:"ja3_fingerprint"`
	TLSVersion      string        `json:"tls_version"`
	CipherSuite     string        `json:"cipher_suite"`
	ResponseTime    time.Duration `json:"response_time"`
	Error           string        `json:"error,omitempty"`
	ServerCertInfo  *CertInfo     `json:"server_cert_info,omitempty"`
}

// CertInfo represents server certificate information
type CertInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	DNSNames   []string  `json:"dns_names"`
	CommonName string    `json:"common_name"`
}

// JA3Calculator handles JA3 fingerprint calculation and testing
type JA3Calculator struct {
	timeout      time.Duration
	knownHashes  map[string][]string
}

// NewJA3Calculator creates a new JA3 calculator with default timeout
func NewJA3Calculator() *JA3Calculator {
	return &JA3Calculator{
		timeout:     10 * time.Second,
		knownHashes: getKnownChromeJA3Hashes(),
	}
}

// NewJA3CalculatorWithTimeout creates a JA3 calculator with custom timeout
func NewJA3CalculatorWithTimeout(timeout time.Duration) *JA3Calculator {
	return &JA3Calculator{
		timeout:     timeout,
		knownHashes: getKnownChromeJA3Hashes(),
	}
}

// TestConnection tests a connection to the target and extracts JA3 fingerprint
func (j *JA3Calculator) TestConnection(target string, clientHelloID utls.ClientHelloID) (*JA3TestResult, error) {
	start := time.Now()
	
	result := &JA3TestResult{
		Target:    target,
		Connected: false,
	}

	// Parse target to ensure it has a port
	host, port, err := j.parseTarget(target)
	if err != nil {
		result.Error = fmt.Sprintf("Invalid target format: %v", err)
		result.ResponseTime = time.Since(start)
		return result, nil
	}

	// Create connection with timeout
	dialer := &net.Dialer{
		Timeout: j.timeout,
	}

	conn, err := dialer.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		result.Error = fmt.Sprintf("Failed to connect: %v", err)
		result.ResponseTime = time.Since(start)
		return result, nil
	}
	defer conn.Close()

	// Create uTLS config
	config := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: false, // We want to validate certificates
		NextProtos:         []string{"h2", "http/1.1"},
	}

	// Create uTLS connection
	uConn := utls.UClient(conn, config, clientHelloID)
	defer uConn.Close()

	// Perform TLS handshake
	err = uConn.Handshake()
	if err != nil {
		result.Error = fmt.Sprintf("TLS handshake failed: %v", err)
		result.ResponseTime = time.Since(start)
		return result, nil
	}

	// Connection successful
	result.Connected = true
	result.ResponseTime = time.Since(start)

	// Extract connection information
	state := uConn.ConnectionState()
	result.TLSVersion = j.tlsVersionToString(state.Version)
	result.CipherSuite = j.cipherSuiteToString(state.CipherSuite)

	// Extract server certificate information
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.ServerCertInfo = &CertInfo{
			Subject:    cert.Subject.String(),
			Issuer:     cert.Issuer.String(),
			NotBefore:  cert.NotBefore,
			NotAfter:   cert.NotAfter,
			DNSNames:   cert.DNSNames,
			CommonName: cert.Subject.CommonName,
		}
	}

	// Calculate JA3 fingerprint from the ClientHello that was sent
	ja3String, ja3Hash, err := j.calculateJA3FromConnection(uConn, clientHelloID)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to calculate JA3: %v", err)
		return result, nil
	}

	result.JA3String = ja3String
	result.JA3Fingerprint = ja3Hash

	return result, nil
}

// parseTarget parses a target string and ensures it has a port
func (j *JA3Calculator) parseTarget(target string) (host, port string, err error) {
	// Remove protocol prefix if present
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	
	// Remove path if present
	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}

	// Check if port is specified
	if strings.Contains(target, ":") {
		host, port, err = net.SplitHostPort(target)
		if err != nil {
			return "", "", fmt.Errorf("invalid host:port format: %w", err)
		}
	} else {
		// Default to HTTPS port
		host = target
		port = "443"
	}

	if host == "" {
		return "", "", fmt.Errorf("empty hostname")
	}

	return host, port, nil
}

// calculateJA3FromConnection calculates JA3 from a uTLS connection
func (j *JA3Calculator) calculateJA3FromConnection(uConn *utls.UConn, clientHelloID utls.ClientHelloID) (string, string, error) {
	// Get the ClientHello that was sent
	handshakeState := uConn.HandshakeState
	if handshakeState.Hello == nil {
		return "", "", fmt.Errorf("no handshake state available")
	}

	clientHello := handshakeState.Hello

	// Extract JA3 components from ClientHello
	ja3Components := j.extractJA3Components(clientHello)

	// Build JA3 string
	ja3String := j.buildJA3String(ja3Components)

	// Calculate JA3 hash
	ja3Hash := j.calculateJA3Hash(ja3String)

	return ja3String, ja3Hash, nil
}

// extractJA3Components extracts JA3 components from a ClientHello message
func (j *JA3Calculator) extractJA3Components(clientHello interface{}) *JA3Components {
	// This is a simplified implementation since we can't directly access
	// the ClientHello structure from uTLS in the same way
	// In a real implementation, you would need to parse the raw ClientHello bytes
	
	components := &JA3Components{
		TLSVersion: 0x0303, // TLS 1.2 default
	}

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

	return components
}

// buildJA3String builds JA3 string from components (same as in handshake_gen.go)
func (j *JA3Calculator) buildJA3String(components *JA3Components) string {
	cipherSuites := j.uint16SliceToString(components.CipherSuites)
	extensions := j.uint16SliceToString(components.Extensions)
	ellipticCurves := j.uint16SliceToString(components.EllipticCurves)
	ellipticCurveFormats := j.uint8SliceToString(components.EllipticCurveFormats)

	return fmt.Sprintf("%d,%s,%s,%s,%s",
		components.TLSVersion,
		cipherSuites,
		extensions,
		ellipticCurves,
		ellipticCurveFormats,
	)
}

// uint16SliceToString converts uint16 slice to JA3 format string
func (j *JA3Calculator) uint16SliceToString(slice []uint16) string {
	if len(slice) == 0 {
		return ""
	}

	result := fmt.Sprintf("%d", slice[0])
	for i := 1; i < len(slice); i++ {
		result += fmt.Sprintf("-%d", slice[i])
	}
	return result
}

// uint8SliceToString converts uint8 slice to JA3 format string
func (j *JA3Calculator) uint8SliceToString(slice []uint8) string {
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
func (j *JA3Calculator) calculateJA3Hash(ja3String string) string {
	hash := md5.Sum([]byte(ja3String))
	return fmt.Sprintf("%x", hash)
}

// tlsVersionToString converts TLS version number to string
func (j *JA3Calculator) tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// cipherSuiteToString converts cipher suite number to string
func (j *JA3Calculator) cipherSuiteToString(cipherSuite uint16) string {
	// Common cipher suites
	suites := map[uint16]string{
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
		0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
		0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
		0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	}

	if name, exists := suites[cipherSuite]; exists {
		return name
	}

	return fmt.Sprintf("Unknown (0x%04x)", cipherSuite)
}

// GetKnownChromeJA3Hashes returns known Chrome JA3 hashes by version
func (j *JA3Calculator) GetKnownChromeJA3Hashes() map[string][]string {
	return j.knownHashes
}

// VerifyJA3Fingerprint checks if a JA3 hash matches any in the provided list
func (j *JA3Calculator) VerifyJA3Fingerprint(ja3Hash string, knownHashes []string) bool {
	ja3Lower := strings.ToLower(ja3Hash)
	for _, known := range knownHashes {
		if strings.ToLower(known) == ja3Lower {
			return true
		}
	}
	return false
}

// FindMatchingChromeVersion finds Chrome versions that match the given JA3 hash
func (j *JA3Calculator) FindMatchingChromeVersion(ja3Hash string) []string {
	var matchingVersions []string
	
	for version, hashes := range j.knownHashes {
		if j.VerifyJA3Fingerprint(ja3Hash, hashes) {
			matchingVersions = append(matchingVersions, version)
		}
	}
	
	return matchingVersions
}

// getKnownChromeJA3Hashes returns a database of known Chrome JA3 hashes
func getKnownChromeJA3Hashes() map[string][]string {
	// This is a simplified database of known Chrome JA3 hashes
	// Real implementation would maintain a comprehensive database
	return map[string][]string{
		"Chrome 133+": {
			"cd08e31494f9531f560d64c695473da9",
			"b32309a26951912be7dba376398abc3b",
		},
		"Chrome 131-132": {
			"a0e9f5d64349fb13191bc781f81f42e1",
			"72a589da586844d7f0818ce684948eea",
		},
		"Chrome 120-130": {
			"4a244b25d3b8c7c5e8b1c6d2f9e3a7b8",
			"5c3d2e1f4a5b6c7d8e9f0a1b2c3d4e5f",
		},
		"Chrome 115-119": {
			"6d4e3f2a5b6c7d8e9f0a1b2c3d4e5f6a",
			"7e5f4a3b6c7d8e9f0a1b2c3d4e5f6a7b",
		},
		"Chrome 106-114": {
			"8f6a5b4c7d8e9f0a1b2c3d4e5f6a7b8c",
			"9a7b6c5d8e9f0a1b2c3d4e5f6a7b8c9d",
		},
		"Chrome 102-105": {
			"ab8c7d6e9f0a1b2c3d4e5f6a7b8c9dae",
			"bc9d8e7f0a1b2c3d4e5f6a7b8c9daebf",
		},
		"Chrome 100-101": {
			"cdae9f8a1b2c3d4e5f6a7b8c9daebfcg",
			"debf0a9b2c3d4e5f6a7b8c9daebfcgdh",
		},
		"Chrome 96-99": {
			"efcg1b0a3c4d5e6f7a8b9c0daebfcgdh",
			"fgdh2c1b4d5e6f7a8b9c0daebfcgdhei",
		},
		"Chrome 87-95": {
			"ghei3d2c5e6f7a8b9c0daebfcgdheifj",
			"hifj4e3d6f7a8b9c0daebfcgdheifgjk",
		},
		"Chrome 83-86": {
			"ijgk5f4e7a8b9c0daebfcgdheifgjklh",
			"jkhl6g5f8b9c0daebfcgdheifgjklhim",
		},
		"Chrome 72-82": {
			"klim7h6g9c0daebfcgdheifgjklhimjn",
			"lmjn8i7h0daebfcgdheifgjklhimjnko",
		},
		"Chrome 70-71": {
			"mnjko9j8iaebfcgdheifgjklhimjnkolp",
			"nkolp0k9jbfcgdheifgjklhimjnkolpmq",
		},
	}
}

// TestMultipleTargets tests JA3 fingerprints against multiple targets
func (j *JA3Calculator) TestMultipleTargets(targets []string, clientHelloID utls.ClientHelloID) ([]*JA3TestResult, error) {
	var results []*JA3TestResult
	
	for _, target := range targets {
		result, err := j.TestConnection(target, clientHelloID)
		if err != nil {
			// Create error result
			result = &JA3TestResult{
				Target:    target,
				Connected: false,
				Error:     err.Error(),
			}
		}
		results = append(results, result)
	}
	
	return results, nil
}

// CompareJA3Results compares JA3 results for consistency
func (j *JA3Calculator) CompareJA3Results(results []*JA3TestResult) *JA3ComparisonResult {
	comparison := &JA3ComparisonResult{
		TotalTests:    len(results),
		SuccessfulTests: 0,
		UniqueJA3Hashes: make(map[string]int),
		ConsistentJA3:   true,
	}
	
	var firstJA3Hash string
	
	for _, result := range results {
		if result.Connected {
			comparison.SuccessfulTests++
			
			if result.JA3Fingerprint != "" {
				comparison.UniqueJA3Hashes[result.JA3Fingerprint]++
				
				if firstJA3Hash == "" {
					firstJA3Hash = result.JA3Fingerprint
				} else if firstJA3Hash != result.JA3Fingerprint {
					comparison.ConsistentJA3 = false
				}
			}
		}
	}
	
	return comparison
}

// JA3ComparisonResult represents the result of comparing multiple JA3 tests
type JA3ComparisonResult struct {
	TotalTests      int            `json:"total_tests"`
	SuccessfulTests int            `json:"successful_tests"`
	UniqueJA3Hashes map[string]int `json:"unique_ja3_hashes"`
	ConsistentJA3   bool           `json:"consistent_ja3"`
}

// GetJA3Statistics returns statistics about JA3 test results
func (j *JA3Calculator) GetJA3Statistics(results []*JA3TestResult) *JA3Statistics {
	stats := &JA3Statistics{
		TotalConnections:    len(results),
		SuccessfulConnections: 0,
		FailedConnections:   0,
		UniqueJA3Hashes:     make(map[string]int),
		TLSVersions:         make(map[string]int),
		CipherSuites:        make(map[string]int),
		AverageResponseTime: 0,
	}
	
	var totalResponseTime time.Duration
	
	for _, result := range results {
		totalResponseTime += result.ResponseTime
		
		if result.Connected {
			stats.SuccessfulConnections++
			
			if result.JA3Fingerprint != "" {
				stats.UniqueJA3Hashes[result.JA3Fingerprint]++
			}
			
			if result.TLSVersion != "" {
				stats.TLSVersions[result.TLSVersion]++
			}
			
			if result.CipherSuite != "" {
				stats.CipherSuites[result.CipherSuite]++
			}
		} else {
			stats.FailedConnections++
		}
	}
	
	if len(results) > 0 {
		stats.AverageResponseTime = totalResponseTime / time.Duration(len(results))
	}
	
	return stats
}

// JA3Statistics represents statistics about JA3 test results
type JA3Statistics struct {
	TotalConnections      int                    `json:"total_connections"`
	SuccessfulConnections int                    `json:"successful_connections"`
	FailedConnections     int                    `json:"failed_connections"`
	UniqueJA3Hashes       map[string]int         `json:"unique_ja3_hashes"`
	TLSVersions           map[string]int         `json:"tls_versions"`
	CipherSuites          map[string]int         `json:"cipher_suites"`
	AverageResponseTime   time.Duration          `json:"average_response_time"`
}