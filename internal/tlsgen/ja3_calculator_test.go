package tlsgen

import (
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	utls "github.com/refraction-networking/utls"
)

func TestNewJA3Calculator(t *testing.T) {
	calc := NewJA3Calculator()
	
	assert.NotNil(t, calc)
	assert.Equal(t, 10*time.Second, calc.timeout)
}

func TestNewJA3CalculatorWithTimeout(t *testing.T) {
	timeout := 5 * time.Second
	calc := NewJA3CalculatorWithTimeout(timeout)
	
	assert.NotNil(t, calc)
	assert.Equal(t, timeout, calc.timeout)
}

func TestCalculateJA3FromBytes(t *testing.T) {
	calc := NewJA3Calculator()
	
	testCases := []struct {
		name        string
		data        []byte
		expectError bool
		errorMsg    string
	}{
		{
			name:        "too short",
			data:        []byte{0x16, 0x03},
			expectError: true,
			errorMsg:    "ClientHello too short",
		},
		{
			name:        "not handshake record",
			data:        []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00},
			expectError: true,
			errorMsg:    "not a TLS handshake record",
		},
		{
			name:        "handshake too short",
			data:        []byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x01},
			expectError: true,
			errorMsg:    "ClientHello handshake message too short",
		},
		{
			name:        "not ClientHello",
			data:        []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00},
			expectError: true,
			errorMsg:    "not a ClientHello message",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := calc.CalculateJA3FromBytes(tc.data)
			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCalculateJA3FromValidBytes(t *testing.T) {
	calc := NewJA3Calculator()
	
	// Create a valid ClientHello wrapped in TLS record
	clientHello := createTestClientHelloWithTLSRecord()
	
	ja3, err := calc.CalculateJA3FromBytes(clientHello)
	require.NoError(t, err)
	assert.NotNil(t, ja3)
	
	// Verify JA3 string format
	assert.NotEmpty(t, ja3.String)
	assert.Contains(t, ja3.String, ",") // Should contain commas
	
	// Split and check components
	parts := strings.Split(ja3.String, ",")
	assert.Len(t, parts, 5) // TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
	
	// Verify hash
	assert.NotEmpty(t, ja3.Hash)
	assert.Len(t, ja3.Hash, 32) // MD5 hash should be 32 hex characters
	
	// Verify hash matches string
	expectedHash := calc.calculateMD5Hash(ja3.String)
	assert.Equal(t, expectedHash, ja3.Hash)
}

func TestJA3CalculatorMD5Hash(t *testing.T) {
	calc := NewJA3Calculator()
	
	testCases := []struct {
		input    string
		expected string
	}{
		{
			input:    "771,4865-4866-4867,0-23-65281,29-23-24,0",
			expected: "650293d7a2ffb5335422221c5d75a9c9",
		},
		{
			input:    "",
			expected: "d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			input:    "test",
			expected: "098f6bcd4621d373cade4e832627b4f6",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := calc.calculateMD5Hash(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestJA3CalculatorIsGREASE(t *testing.T) {
	calc := NewJA3Calculator()
	
	testCases := []struct {
		name     string
		value    uint16
		expected bool
	}{
		{
			name:     "GREASE value 0x0A0A",
			value:    0x0A0A,
			expected: true,
		},
		{
			name:     "GREASE value 0x1A1A",
			value:    0x1A1A,
			expected: true,
		},
		{
			name:     "GREASE value 0x2A2A",
			value:    0x2A2A,
			expected: true,
		},
		{
			name:     "GREASE value 0x3A3A",
			value:    0x3A3A,
			expected: true,
		},
		{
			name:     "Non-GREASE value 0x0000",
			value:    0x0000,
			expected: false,
		},
		{
			name:     "Non-GREASE value 0x0023",
			value:    0x0023,
			expected: false,
		},
		{
			name:     "Non-GREASE value 0x1234",
			value:    0x1234,
			expected: false,
		},
		{
			name:     "Non-GREASE value 0x1A2A (different nibbles)",
			value:    0x1A2A,
			expected: false,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := calc.isGREASE(tc.value)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestFilterGREASEFromCipherSuites(t *testing.T) {
	calc := NewJA3Calculator()
	
	testCases := []struct {
		name     string
		input    []uint16
		expected []uint16
	}{
		{
			name:     "no GREASE values",
			input:    []uint16{0x1301, 0x1302, 0x1303},
			expected: []uint16{0x1301, 0x1302, 0x1303},
		},
		{
			name:     "with GREASE values",
			input:    []uint16{0x1301, 0x0A0A, 0x1302, 0x1A1A, 0x1303},
			expected: []uint16{0x1301, 0x1302, 0x1303},
		},
		{
			name:     "all GREASE values",
			input:    []uint16{0x0A0A, 0x1A1A, 0x2A2A},
			expected: []uint16{},
		},
		{
			name:     "empty slice",
			input:    []uint16{},
			expected: []uint16{},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := calc.filterGREASEFromCipherSuites(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestJA3CalculatorFilterAndSortExtensions(t *testing.T) {
	calc := NewJA3Calculator()
	
	testCases := []struct {
		name     string
		input    []uint16
		expected []uint16
	}{
		{
			name:     "empty slice",
			input:    []uint16{},
			expected: []uint16{},
		},
		{
			name:     "no GREASE values - maintain order",
			input:    []uint16{23, 0, 65281, 10},
			expected: []uint16{23, 0, 65281, 10}, // JA3 maintains original order
		},
		{
			name:     "with GREASE values",
			input:    []uint16{23, 0x0A0A, 65281, 0x1A1A, 10},
			expected: []uint16{23, 65281, 10}, // GREASE filtered, order maintained
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := calc.filterAndSortExtensions(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestJA3CalculatorJoinInts(t *testing.T) {
	calc := NewJA3Calculator()
	
	testCases := []struct {
		name     string
		values   []uint16
		sep      string
		expected string
	}{
		{
			name:     "empty slice",
			values:   []uint16{},
			sep:      "-",
			expected: "",
		},
		{
			name:     "single value",
			values:   []uint16{123},
			sep:      "-",
			expected: "123",
		},
		{
			name:     "multiple values with dash",
			values:   []uint16{123, 456, 789},
			sep:      "-",
			expected: "123-456-789",
		},
		{
			name:     "multiple values with comma",
			values:   []uint16{123, 456, 789},
			sep:      ",",
			expected: "123,456,789",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := calc.joinInts(tc.values, tc.sep)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestTLSVersionToString(t *testing.T) {
	calc := NewJA3Calculator()
	
	testCases := []struct {
		version  uint16
		expected string
	}{
		{0x0300, "SSL 3.0"},
		{0x0301, "TLS 1.0"},
		{0x0302, "TLS 1.1"},
		{0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"},
		{0x9999, "Unknown (0x9999)"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := calc.tlsVersionToString(tc.version)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestVerifyJA3Fingerprint(t *testing.T) {
	calc := NewJA3Calculator()
	
	testCases := []struct {
		name          string
		ja3Hash       string
		expectedHashes []string
		expected      bool
	}{
		{
			name:          "exact match",
			ja3Hash:       "cd08e31494f9531f560d64c695473da9",
			expectedHashes: []string{"cd08e31494f9531f560d64c695473da9", "b32309a26951912be7dba376398abc3b"},
			expected:      true,
		},
		{
			name:          "case insensitive match",
			ja3Hash:       "CD08E31494F9531F560D64C695473DA9",
			expectedHashes: []string{"cd08e31494f9531f560d64c695473da9", "b32309a26951912be7dba376398abc3b"},
			expected:      true,
		},
		{
			name:          "no match",
			ja3Hash:       "ffffffffffffffffffffffffffffffff",
			expectedHashes: []string{"cd08e31494f9531f560d64c695473da9", "b32309a26951912be7dba376398abc3b"},
			expected:      false,
		},
		{
			name:          "empty expected hashes",
			ja3Hash:       "cd08e31494f9531f560d64c695473da9",
			expectedHashes: []string{},
			expected:      false,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := calc.VerifyJA3Fingerprint(tc.ja3Hash, tc.expectedHashes)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetKnownChromeJA3Hashes(t *testing.T) {
	calc := NewJA3Calculator()
	
	hashes := calc.GetKnownChromeJA3Hashes()
	
	assert.NotEmpty(t, hashes)
	assert.Contains(t, hashes, "chrome_120+")
	assert.Contains(t, hashes, "chrome_115-119")
	assert.Contains(t, hashes, "chrome_100-114")
	
	// Verify each category has at least one hash
	for category, hashList := range hashes {
		assert.NotEmpty(t, hashList, "Category %s should have at least one hash", category)
	}
}

func TestParseClientHelloForJA3(t *testing.T) {
	calc := NewJA3Calculator()
	
	// Create a minimal valid ClientHello message
	clientHello := createTestClientHelloHandshake()
	
	info, err := calc.parseClientHelloForJA3(clientHello)
	require.NoError(t, err)
	assert.NotNil(t, info)
	
	// Check basic fields
	assert.Equal(t, uint16(0x0303), info.Version) // TLS 1.2
	assert.NotEmpty(t, info.CipherSuites)
	assert.NotEmpty(t, info.Extensions)
}

func TestParseClientHelloForJA3Errors(t *testing.T) {
	calc := NewJA3Calculator()
	
	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "too short",
			data: []byte{0x01, 0x00},
		},
		{
			name: "missing version",
			data: []byte{0x01, 0x00, 0x00, 0x10}, // handshake header only
		},
		{
			name: "missing random",
			data: []byte{0x01, 0x00, 0x00, 0x10, 0x03, 0x03}, // header + version
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := calc.parseClientHelloForJA3(tc.data)
			assert.Error(t, err)
		})
	}
}

func TestExtractJA3String(t *testing.T) {
	calc := NewJA3Calculator()
	
	// Create a test ClientHello handshake
	clientHello := createTestClientHelloHandshake()
	
	ja3String, err := calc.extractJA3String(clientHello)
	require.NoError(t, err)
	
	// Should not be empty and should contain the expected format
	assert.NotEmpty(t, ja3String)
	assert.Contains(t, ja3String, ",") // Should contain commas separating components
	
	// Split and check components
	parts := strings.Split(ja3String, ",")
	assert.Len(t, parts, 5) // TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
	
	// First part should be TLS version
	assert.Equal(t, "771", parts[0]) // TLS 1.2 = 0x0303 = 771
}

// Helper function to create a minimal valid ClientHello handshake message for testing
func createTestClientHelloHandshake() []byte {
	var data []byte
	
	// Handshake header (4 bytes)
	data = append(data, 0x01) // ClientHello type
	data = append(data, 0x00, 0x00, 0x00) // Length placeholder (will be updated)
	
	// TLS version (2 bytes)
	data = append(data, 0x03, 0x03) // TLS 1.2
	
	// Random (32 bytes)
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}
	data = append(data, random...)
	
	// Session ID length (1 byte) + Session ID (0 bytes)
	data = append(data, 0x00)
	
	// Cipher suites length (2 bytes) + cipher suites
	cipherSuites := []uint16{0x1301, 0x1302, 0x1303} // TLS 1.3 cipher suites
	data = append(data, 0x00, byte(len(cipherSuites)*2))
	for _, suite := range cipherSuites {
		data = binary.BigEndian.AppendUint16(data, suite)
	}
	
	// Compression methods length (1 byte) + compression methods
	data = append(data, 0x01, 0x00) // No compression
	
	// Extensions length (2 bytes) + extensions
	extensions := []byte{
		0x00, 0x0a, // Extension type: supported_groups
		0x00, 0x04, // Extension length
		0x00, 0x02, // List length
		0x00, 0x1d, // X25519
	}
	data = append(data, 0x00, byte(len(extensions)))
	data = append(data, extensions...)
	
	// Update handshake message length
	messageLen := len(data) - 4
	data[1] = byte(messageLen >> 16)
	data[2] = byte(messageLen >> 8)
	data[3] = byte(messageLen)
	
	return data
}

// Helper function to create a ClientHello wrapped in TLS record for testing
func createTestClientHelloWithTLSRecord() []byte {
	handshake := createTestClientHelloHandshake()
	
	// Create TLS record wrapper
	var record []byte
	record = append(record, 0x16) // Handshake record type
	record = append(record, 0x03, 0x03) // TLS 1.2 version
	
	// Record length (2 bytes)
	recordLen := len(handshake)
	record = append(record, byte(recordLen>>8), byte(recordLen))
	
	// Append handshake data
	record = append(record, handshake...)
	
	return record
}

// Integration test for TestConnection - requires network access
func TestTestConnectionIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	calc := NewJA3CalculatorWithTimeout(5 * time.Second)
	
	// Test with a mock HTTPS server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	
	// Extract host and port from test server URL
	serverURL := strings.TrimPrefix(server.URL, "https://")
	
	result, err := calc.TestConnection(serverURL, utls.HelloChrome_120)
	require.NoError(t, err)
	assert.NotNil(t, result)
	
	// Should successfully connect to test server
	assert.True(t, result.Connected)
	assert.Empty(t, result.Error)
	assert.NotEmpty(t, result.JA3Fingerprint)
	assert.NotEmpty(t, result.JA3String)
	assert.Greater(t, result.ResponseTime, time.Duration(0))
}

func TestTestConnectionErrors(t *testing.T) {
	calc := NewJA3CalculatorWithTimeout(1 * time.Second)
	
	testCases := []struct {
		name   string
		target string
	}{
		{
			name:   "invalid host",
			target: "invalid-host-that-does-not-exist.com:443",
		},
		{
			name:   "connection refused",
			target: "127.0.0.1:9999", // Assuming this port is not open
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := calc.TestConnection(tc.target, utls.HelloChrome_120)
			require.NoError(t, err) // Method should not return error, but populate result.Error
			assert.NotNil(t, result)
			assert.False(t, result.Connected)
			assert.NotEmpty(t, result.Error)
		})
	}
}

func TestCaptureClientHelloBytes(t *testing.T) {
	calc := NewJA3Calculator()
	
	// Test capturing ClientHello bytes
	clientHelloBytes, err := calc.captureClientHelloBytes(utls.HelloChrome_120)
	require.NoError(t, err)
	assert.NotEmpty(t, clientHelloBytes)
	
	// Verify it's a valid TLS handshake record
	assert.Equal(t, byte(0x16), clientHelloBytes[0]) // Handshake record type
	assert.True(t, len(clientHelloBytes) > 5) // Should have at least TLS record header
}