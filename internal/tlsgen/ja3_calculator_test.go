package tlsgen

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJA3Calculator(t *testing.T) {
	calc := NewJA3Calculator()
	assert.NotNil(t, calc)
	assert.Equal(t, 10*time.Second, calc.timeout)
	assert.NotNil(t, calc.knownHashes)
}

func TestNewJA3CalculatorWithTimeout(t *testing.T) {
	timeout := 30 * time.Second
	calc := NewJA3CalculatorWithTimeout(timeout)
	assert.NotNil(t, calc)
	assert.Equal(t, timeout, calc.timeout)
}

func TestJA3Calculator_ParseTarget(t *testing.T) {
	calc := NewJA3Calculator()

	tests := []struct {
		name         string
		target       string
		expectedHost string
		expectedPort string
		expectError  bool
	}{
		{
			name:         "host with port",
			target:       "example.com:443",
			expectedHost: "example.com",
			expectedPort: "443",
			expectError:  false,
		},
		{
			name:         "host without port",
			target:       "example.com",
			expectedHost: "example.com",
			expectedPort: "443",
			expectError:  false,
		},
		{
			name:         "https URL",
			target:       "https://example.com:8443",
			expectedHost: "example.com",
			expectedPort: "8443",
			expectError:  false,
		},
		{
			name:         "https URL without port",
			target:       "https://example.com",
			expectedHost: "example.com",
			expectedPort: "443",
			expectError:  false,
		},
		{
			name:         "URL with path",
			target:       "https://example.com:443/path",
			expectedHost: "example.com",
			expectedPort: "443",
			expectError:  false,
		},
		{
			name:        "empty target",
			target:      "",
			expectError: true,
		},
		{
			name:        "invalid host:port format",
			target:      "example.com:invalid:extra",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := calc.parseTarget(tt.target)
			
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedHost, host)
				assert.Equal(t, tt.expectedPort, port)
			}
		})
	}
}

func TestJA3Calculator_BuildJA3String(t *testing.T) {
	calc := NewJA3Calculator()

	components := &JA3Components{
		TLSVersion:   771,
		CipherSuites: []uint16{4865, 4866, 4867},
		Extensions:   []uint16{0, 23, 65281},
		EllipticCurves: []uint16{29, 23, 24},
		EllipticCurveFormats: []uint8{0},
	}

	ja3String := calc.buildJA3String(components)
	expected := "771,4865-4866-4867,0-23-65281,29-23-24,0"
	assert.Equal(t, expected, ja3String)
}

func TestJA3Calculator_Uint16SliceToString(t *testing.T) {
	calc := NewJA3Calculator()

	tests := []struct {
		name     string
		input    []uint16
		expected string
	}{
		{
			name:     "empty slice",
			input:    []uint16{},
			expected: "",
		},
		{
			name:     "single element",
			input:    []uint16{4865},
			expected: "4865",
		},
		{
			name:     "multiple elements",
			input:    []uint16{4865, 4866, 4867},
			expected: "4865-4866-4867",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calc.uint16SliceToString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJA3Calculator_Uint8SliceToString(t *testing.T) {
	calc := NewJA3Calculator()

	tests := []struct {
		name     string
		input    []uint8
		expected string
	}{
		{
			name:     "empty slice",
			input:    []uint8{},
			expected: "",
		},
		{
			name:     "single element",
			input:    []uint8{0},
			expected: "0",
		},
		{
			name:     "multiple elements",
			input:    []uint8{0, 1, 2},
			expected: "0-1-2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calc.uint8SliceToString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJA3Calculator_CalculateJA3Hash(t *testing.T) {
	calc := NewJA3Calculator()

	ja3String := "771,4865-4866-4867,0-23-65281,29-23-24,0"
	hash := calc.calculateJA3Hash(ja3String)

	// Should be a valid MD5 hash (32 hex characters)
	assert.Len(t, hash, 32)
	assert.Regexp(t, "^[a-f0-9]{32}$", hash)

	// Same input should produce same hash
	hash2 := calc.calculateJA3Hash(ja3String)
	assert.Equal(t, hash, hash2)

	// Different input should produce different hash
	differentJA3String := "771,4865-4866,0-23,29-23,0"
	differentHash := calc.calculateJA3Hash(differentJA3String)
	assert.NotEqual(t, hash, differentHash)
}

func TestJA3Calculator_TLSVersionToString(t *testing.T) {
	calc := NewJA3Calculator()

	tests := []struct {
		version  uint16
		expected string
	}{
		{0x0301, "TLS 1.0"},
		{0x0302, "TLS 1.1"},
		{0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"},
		{0x9999, "Unknown (0x9999)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := calc.tlsVersionToString(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJA3Calculator_CipherSuiteToString(t *testing.T) {
	calc := NewJA3Calculator()

	tests := []struct {
		suite    uint16
		expected string
	}{
		{0x1301, "TLS_AES_128_GCM_SHA256"},
		{0x1302, "TLS_AES_256_GCM_SHA384"},
		{0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
		{0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
		{0x9999, "Unknown (0x9999)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := calc.cipherSuiteToString(tt.suite)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJA3Calculator_GetKnownChromeJA3Hashes(t *testing.T) {
	calc := NewJA3Calculator()
	hashes := calc.GetKnownChromeJA3Hashes()

	assert.NotEmpty(t, hashes)
	assert.Contains(t, hashes, "Chrome 133+")
	assert.Contains(t, hashes, "Chrome 120-130")
	assert.Contains(t, hashes, "Chrome 70-71")

	// Each version should have at least one hash
	for version, hashList := range hashes {
		assert.NotEmpty(t, hashList, "Version %s should have at least one hash", version)
	}
}

func TestJA3Calculator_VerifyJA3Fingerprint(t *testing.T) {
	calc := NewJA3Calculator()

	knownHashes := []string{
		"cd08e31494f9531f560d64c695473da9",
		"b32309a26951912be7dba376398abc3b",
		"a0e9f5d64349fb13191bc781f81f42e1",
	}

	// Test exact match
	assert.True(t, calc.VerifyJA3Fingerprint("cd08e31494f9531f560d64c695473da9", knownHashes))

	// Test case insensitive match
	assert.True(t, calc.VerifyJA3Fingerprint("CD08E31494F9531F560D64C695473DA9", knownHashes))

	// Test no match
	assert.False(t, calc.VerifyJA3Fingerprint("unknown_hash", knownHashes))

	// Test empty hash list
	assert.False(t, calc.VerifyJA3Fingerprint("cd08e31494f9531f560d64c695473da9", []string{}))
}

func TestJA3Calculator_FindMatchingChromeVersion(t *testing.T) {
	calc := NewJA3Calculator()

	// Test with a hash that should match Chrome 133+
	matchingVersions := calc.FindMatchingChromeVersion("cd08e31494f9531f560d64c695473da9")
	assert.NotEmpty(t, matchingVersions)

	// Test with unknown hash
	unknownVersions := calc.FindMatchingChromeVersion("unknown_hash_that_does_not_exist")
	assert.Empty(t, unknownVersions)
}

func TestJA3Calculator_ExtractJA3Components(t *testing.T) {
	calc := NewJA3Calculator()

	// Test with mock ClientHello (since we can't easily create a real one in tests)
	components := calc.extractJA3Components(nil) // Simplified implementation doesn't use the parameter

	assert.NotNil(t, components)
	assert.Equal(t, uint16(0x0303), components.TLSVersion) // TLS 1.2
	assert.NotEmpty(t, components.CipherSuites)
	assert.NotEmpty(t, components.Extensions)
	assert.NotEmpty(t, components.EllipticCurves)
	assert.NotEmpty(t, components.EllipticCurveFormats)

	// Check for expected cipher suites
	assert.Contains(t, components.CipherSuites, uint16(0x1301)) // TLS_AES_128_GCM_SHA256
	assert.Contains(t, components.CipherSuites, uint16(0x1302)) // TLS_AES_256_GCM_SHA384

	// Check for expected extensions
	assert.Contains(t, components.Extensions, uint16(0))  // server_name
	assert.Contains(t, components.Extensions, uint16(10)) // supported_groups

	// Check for expected elliptic curves
	assert.Contains(t, components.EllipticCurves, uint16(29)) // X25519
	assert.Contains(t, components.EllipticCurves, uint16(23)) // secp256r1

	// Check elliptic curve formats
	assert.Contains(t, components.EllipticCurveFormats, uint8(0)) // uncompressed
}

func TestJA3Calculator_GetJA3Statistics(t *testing.T) {
	calc := NewJA3Calculator()

	results := []*JA3TestResult{
		{
			Target:          "example.com:443",
			Connected:       true,
			JA3Fingerprint:  "hash1",
			TLSVersion:      "TLS 1.3",
			CipherSuite:     "TLS_AES_128_GCM_SHA256",
			ResponseTime:    100 * time.Millisecond,
		},
		{
			Target:          "test.com:443",
			Connected:       true,
			JA3Fingerprint:  "hash2",
			TLSVersion:      "TLS 1.3",
			CipherSuite:     "TLS_AES_256_GCM_SHA384",
			ResponseTime:    200 * time.Millisecond,
		},
		{
			Target:       "failed.com:443",
			Connected:    false,
			ResponseTime: 50 * time.Millisecond,
		},
	}

	stats := calc.GetJA3Statistics(results)

	assert.Equal(t, 3, stats.TotalConnections)
	assert.Equal(t, 2, stats.SuccessfulConnections)
	assert.Equal(t, 1, stats.FailedConnections)
	assert.Equal(t, 2, len(stats.UniqueJA3Hashes))
	assert.Equal(t, 1, stats.UniqueJA3Hashes["hash1"])
	assert.Equal(t, 1, stats.UniqueJA3Hashes["hash2"])
	assert.Equal(t, 2, stats.TLSVersions["TLS 1.3"]) // Two successful connections both used TLS 1.3
	assert.Equal(t, 1, stats.CipherSuites["TLS_AES_128_GCM_SHA256"])
	assert.Equal(t, 1, stats.CipherSuites["TLS_AES_256_GCM_SHA384"])
	// Average response time: (100+200+50)/3 = 350/3 ≈ 116.67ms
	expectedAvg := (100*time.Millisecond + 200*time.Millisecond + 50*time.Millisecond) / 3
	assert.Equal(t, expectedAvg, stats.AverageResponseTime)
}

func TestJA3Calculator_CompareJA3Results(t *testing.T) {
	calc := NewJA3Calculator()

	// Test consistent results
	consistentResults := []*JA3TestResult{
		{Connected: true, JA3Fingerprint: "hash1"},
		{Connected: true, JA3Fingerprint: "hash1"},
		{Connected: true, JA3Fingerprint: "hash1"},
	}

	comparison := calc.CompareJA3Results(consistentResults)
	assert.Equal(t, 3, comparison.TotalTests)
	assert.Equal(t, 3, comparison.SuccessfulTests)
	assert.True(t, comparison.ConsistentJA3)
	assert.Equal(t, 1, len(comparison.UniqueJA3Hashes))
	assert.Equal(t, 3, comparison.UniqueJA3Hashes["hash1"])

	// Test inconsistent results
	inconsistentResults := []*JA3TestResult{
		{Connected: true, JA3Fingerprint: "hash1"},
		{Connected: true, JA3Fingerprint: "hash2"},
		{Connected: false},
	}

	comparison = calc.CompareJA3Results(inconsistentResults)
	assert.Equal(t, 3, comparison.TotalTests)
	assert.Equal(t, 2, comparison.SuccessfulTests)
	assert.False(t, comparison.ConsistentJA3)
	assert.Equal(t, 2, len(comparison.UniqueJA3Hashes))
}

// Benchmark tests
func BenchmarkJA3Calculator_CalculateJA3Hash(b *testing.B) {
	calc := NewJA3Calculator()
	ja3String := "771,4865-4866-4867,0-23-65281,29-23-24,0"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = calc.calculateJA3Hash(ja3String)
	}
}

func BenchmarkJA3Calculator_BuildJA3String(b *testing.B) {
	calc := NewJA3Calculator()
	components := &JA3Components{
		TLSVersion:   771,
		CipherSuites: []uint16{4865, 4866, 4867},
		Extensions:   []uint16{0, 23, 65281},
		EllipticCurves: []uint16{29, 23, 24},
		EllipticCurveFormats: []uint8{0},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = calc.buildJA3String(components)
	}
}