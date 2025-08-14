package tlsgen

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTLSGenerator(t *testing.T) {
	generator := NewTLSGenerator()
	
	assert.NotNil(t, generator)
	assert.Equal(t, 10*time.Second, generator.timeout)
}

func TestNewTLSGeneratorWithTimeout(t *testing.T) {
	timeout := 5 * time.Second
	generator := NewTLSGeneratorWithTimeout(timeout)
	
	assert.NotNil(t, generator)
	assert.Equal(t, timeout, generator.timeout)
}

func TestMapChromeVersionToClientHelloID(t *testing.T) {
	generator := NewTLSGenerator()
	
	testCases := []struct {
		name     string
		version  ChromeVersion
		expected string // We'll check the string representation
	}{
		{
			name:     "Chrome 133+",
			version:  ChromeVersion{Major: 133, Minor: 0, Build: 6099, Patch: 109},
			expected: "133",
		},
		{
			name:     "Chrome 131-132",
			version:  ChromeVersion{Major: 131, Minor: 0, Build: 6099, Patch: 109},
			expected: "131",
		},
		{
			name:     "Chrome 120-130",
			version:  ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: "120",
		},
		{
			name:     "Chrome 115-119",
			version:  ChromeVersion{Major: 115, Minor: 0, Build: 5790, Patch: 102},
			expected: "115_PQ",
		},
		{
			name:     "Chrome 106-114",
			version:  ChromeVersion{Major: 108, Minor: 0, Build: 5359, Patch: 124},
			expected: "106",
		},
		{
			name:     "Chrome 100-101",
			version:  ChromeVersion{Major: 100, Minor: 0, Build: 4896, Patch: 75},
			expected: "100",
		},
		{
			name:     "Chrome older than 100",
			version:  ChromeVersion{Major: 95, Minor: 0, Build: 4638, Patch: 69},
			expected: "87", // Actually maps to Chrome 87 for version 95
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			clientHelloID, err := generator.mapChromeVersionToClientHelloID(tc.version)
			require.NoError(t, err)
			assert.Contains(t, clientHelloID.Str(), tc.expected)
		})
	}
}

func TestCalculateMD5Hash(t *testing.T) {
	generator := NewTLSGenerator()
	
	testCases := []struct {
		input    string
		expected string
	}{
		{
			input:    "771,4865-4866-4867,0-23-65281,29-23-24,0",
			expected: "650293d7a2ffb5335422221c5d75a9c9", // Correct MD5 hash
		},
		{
			input:    "",
			expected: "d41d8cd98f00b204e9800998ecf8427e", // MD5 of empty string
		},
		{
			input:    "test",
			expected: "098f6bcd4621d373cade4e832627b4f6", // MD5 of "test"
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := generator.calculateMD5Hash(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestJoinInts(t *testing.T) {
	generator := NewTLSGenerator()
	
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
			result := generator.joinInts(tc.values, tc.sep)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIsGREASE(t *testing.T) {
	generator := NewTLSGenerator()
	
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
			result := generator.isGREASE(tc.value)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestFilterAndSortExtensions(t *testing.T) {
	generator := NewTLSGenerator()
	
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
			name:     "no GREASE values",
			input:    []uint16{23, 0, 65281, 10},
			expected: []uint16{0, 10, 23, 65281},
		},
		{
			name:     "with GREASE values",
			input:    []uint16{23, 0x0A0A, 65281, 0x1A1A, 10},
			expected: []uint16{10, 23, 65281}, // 0x0A0A and 0x1A1A should be filtered out
		},
		{
			name:     "already sorted",
			input:    []uint16{0, 10, 23, 65281},
			expected: []uint16{0, 10, 23, 65281},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := generator.filterAndSortExtensions(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParseClientHelloBasic(t *testing.T) {
	generator := NewTLSGenerator()
	
	// Create a minimal valid ClientHello message
	clientHello := createTestClientHello()
	
	info, err := generator.parseClientHello(clientHello)
	require.NoError(t, err)
	assert.NotNil(t, info)
	
	// Check basic fields
	assert.Equal(t, uint16(0x0303), info.Version) // TLS 1.2
	assert.NotEmpty(t, info.CipherSuites)
}

func TestParseClientHelloErrors(t *testing.T) {
	generator := NewTLSGenerator()
	
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
			_, err := generator.parseClientHello(tc.data)
			assert.Error(t, err)
		})
	}
}

func TestCalculateJA3Errors(t *testing.T) {
	generator := NewTLSGenerator()
	
	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "too short",
			data: []byte{0x16, 0x03},
		},
		{
			name: "not handshake record",
			data: []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00},
		},
		{
			name: "handshake too short",
			data: []byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x01},
		},
		{
			name: "not ClientHello",
			data: []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := generator.calculateJA3(tc.data)
			assert.Error(t, err)
		})
	}
}

func TestGetSupportedVersions(t *testing.T) {
	generator := NewTLSGenerator()
	
	versions := generator.GetSupportedVersions()
	
	assert.NotEmpty(t, versions)
	assert.True(t, len(versions) >= 9) // Should have at least 9 supported versions
	
	// Check that versions are in descending order (newest first)
	for i := 1; i < len(versions); i++ {
		assert.True(t, versions[i-1].IsNewer(versions[i]) || versions[i-1].Equal(versions[i]))
	}
	
	// Check that all versions have reasonable major version numbers
	for _, version := range versions {
		assert.True(t, version.Major >= 100, "Version major should be >= 100")
		assert.True(t, version.Major <= 130, "Version major should be <= 130")
	}
}

// Helper function to create a minimal valid ClientHello for testing
func createTestClientHello() []byte {
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

func TestExtractJA3StringWithValidData(t *testing.T) {
	generator := NewTLSGenerator()
	
	// Create a test ClientHello
	clientHello := createTestClientHello()
	
	ja3String := generator.extractJA3String(clientHello)
	
	// Should not be empty and should contain the expected format
	assert.NotEmpty(t, ja3String)
	assert.Contains(t, ja3String, ",") // Should contain commas separating components
	
	// Split and check components
	parts := strings.Split(ja3String, ",")
	assert.Len(t, parts, 5) // TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
}

func TestExtractJA3StringWithInvalidData(t *testing.T) {
	generator := NewTLSGenerator()
	
	// Test with invalid data - should return default Chrome-like JA3
	invalidData := []byte{0x01, 0x00}
	
	ja3String := generator.extractJA3String(invalidData)
	
	// Should return the default Chrome-like JA3 string
	expected := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
	assert.Equal(t, expected, ja3String)
}