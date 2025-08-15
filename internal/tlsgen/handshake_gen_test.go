package tlsgen

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTLSGenerator(t *testing.T) {
	generator := NewTLSGenerator()
	assert.NotNil(t, generator)
	assert.NotNil(t, generator.randomSource)
}

func TestTLSGenerator_GenerateTemplate(t *testing.T) {
	generator := NewTLSGenerator()
	
	version := ChromeVersion{
		Major: 120,
		Minor: 0,
		Build: 6099,
		Patch: 109,
	}

	template, err := generator.GenerateTemplate(version)
	require.NoError(t, err)
	require.NotNil(t, template)

	assert.Equal(t, version, template.Version)
	assert.NotEmpty(t, template.Bytes)
	assert.NotEmpty(t, template.JA3String)
	assert.NotEmpty(t, template.JA3Hash)
	assert.False(t, template.GeneratedAt.IsZero())
	assert.NotEmpty(t, template.Metadata.UTLSFingerprint)
}

func TestTLSGenerator_GenerateTemplate_UnsupportedVersion(t *testing.T) {
	generator := NewTLSGenerator()
	
	version := ChromeVersion{
		Major: 69, // Unsupported version
		Minor: 0,
		Build: 0,
		Patch: 0,
	}

	template, err := generator.GenerateTemplate(version)
	assert.Error(t, err)
	assert.Nil(t, template)
	assert.Contains(t, err.Error(), "not supported")
}

func TestTLSGenerator_GenerateTemplate_InvalidVersion(t *testing.T) {
	generator := NewTLSGenerator()
	
	version := ChromeVersion{
		Major: -1, // Invalid version
		Minor: 0,
		Build: 0,
		Patch: 0,
	}

	template, err := generator.GenerateTemplate(version)
	assert.Error(t, err)
	assert.Nil(t, template)
	assert.Contains(t, err.Error(), "invalid Chrome version")
}

func TestTLSGenerator_ValidateTemplate(t *testing.T) {
	generator := NewTLSGenerator()

	// Valid template
	validTemplate := &ClientHelloTemplate{
		Version: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
		Bytes:   []byte{0x16, 0x03, 0x01, 0x00, 0x10}, // Sample bytes
		JA3String: "771,4865-4866-4867,0-23-65281,29-23-24,0",
		JA3Hash: "cd08e31494f9531f560d64c695473da9",
		GeneratedAt: time.Now(),
	}

	err := generator.ValidateTemplate(validTemplate)
	assert.NoError(t, err)

	// Invalid template - nil
	err = generator.ValidateTemplate(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "template is nil")

	// Invalid template - empty bytes
	invalidTemplate := &ClientHelloTemplate{
		Version: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
		Bytes:   []byte{},
		JA3String: "771,4865-4866-4867,0-23-65281,29-23-24,0",
		JA3Hash: "cd08e31494f9531f560d64c695473da9",
		GeneratedAt: time.Now(),
	}

	err = generator.ValidateTemplate(invalidTemplate)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "template bytes are empty")

	// Invalid template - empty JA3 string
	invalidTemplate.Bytes = []byte{0x16, 0x03, 0x01, 0x00, 0x10}
	invalidTemplate.JA3String = ""

	err = generator.ValidateTemplate(invalidTemplate)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JA3 string is empty")
}

func TestTLSGenerator_CompareTemplates(t *testing.T) {
	generator := NewTLSGenerator()

	template1 := &ClientHelloTemplate{
		Version: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
		Bytes:   []byte{0x16, 0x03, 0x01, 0x00, 0x10},
		JA3Hash: "cd08e31494f9531f560d64c695473da9",
	}

	template2 := &ClientHelloTemplate{
		Version: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
		Bytes:   []byte{0x16, 0x03, 0x01, 0x00, 0x10},
		JA3Hash: "cd08e31494f9531f560d64c695473da9",
	}

	template3 := &ClientHelloTemplate{
		Version: ChromeVersion{Major: 121, Minor: 0, Build: 6100, Patch: 110},
		Bytes:   []byte{0x16, 0x03, 0x01, 0x00, 0x11},
		JA3Hash: "different_hash",
	}

	// Same templates should be equal
	assert.True(t, generator.CompareTemplates(template1, template2))

	// Different templates should not be equal
	assert.False(t, generator.CompareTemplates(template1, template3))

	// Nil templates should not be equal
	assert.False(t, generator.CompareTemplates(template1, nil))
	assert.False(t, generator.CompareTemplates(nil, template2))
	assert.False(t, generator.CompareTemplates(nil, nil))
}

func TestTLSGenerator_BuildJA3String(t *testing.T) {
	generator := NewTLSGenerator()

	components := &JA3Components{
		TLSVersion:   771,
		CipherSuites: []uint16{4865, 4866, 4867},
		Extensions:   []uint16{0, 23, 65281},
		EllipticCurves: []uint16{29, 23, 24},
		EllipticCurveFormats: []uint8{0},
	}

	ja3String := generator.buildJA3String(components)
	expected := "771,4865-4866-4867,0-23-65281,29-23-24,0"
	assert.Equal(t, expected, ja3String)
}

func TestTLSGenerator_Uint16SliceToString(t *testing.T) {
	generator := NewTLSGenerator()

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
			result := generator.uint16SliceToString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTLSGenerator_Uint8SliceToString(t *testing.T) {
	generator := NewTLSGenerator()

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
			result := generator.uint8SliceToString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTLSGenerator_CalculateJA3Hash(t *testing.T) {
	generator := NewTLSGenerator()

	ja3String := "771,4865-4866-4867,0-23-65281,29-23-24,0"
	hash := generator.calculateJA3Hash(ja3String)

	// Should be a valid MD5 hash (32 hex characters)
	assert.Len(t, hash, 32)
	assert.Regexp(t, "^[a-f0-9]{32}$", hash)

	// Same input should produce same hash
	hash2 := generator.calculateJA3Hash(ja3String)
	assert.Equal(t, hash, hash2)

	// Different input should produce different hash
	differentJA3String := "771,4865-4866,0-23,29-23,0"
	differentHash := generator.calculateJA3Hash(differentJA3String)
	assert.NotEqual(t, hash, differentHash)
}

func TestTLSGenerator_CreateTemplateMetadata(t *testing.T) {
	generator := NewTLSGenerator()

	version := ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109}
	
	// We can't easily test the actual uTLS ClientHelloID, so we'll test the metadata creation
	// by calling the method indirectly through GenerateTemplate
	template, err := generator.GenerateTemplate(version)
	require.NoError(t, err)

	metadata := template.Metadata

	assert.Equal(t, "HelloChrome_120", metadata.UTLSFingerprint)
	assert.Contains(t, metadata.TLSVersions, "TLS 1.2")
	assert.Contains(t, metadata.TLSVersions, "TLS 1.3")
	assert.Contains(t, metadata.CipherSuites, "TLS_AES_128_GCM_SHA256")
	assert.Contains(t, metadata.SupportedGroups, "X25519")
	assert.Contains(t, metadata.SignatureAlgorithms, "ecdsa_secp256r1_sha256")
	assert.Contains(t, metadata.ALPNProtocols, "h2")
	assert.NotEmpty(t, metadata.Extensions)
}

func TestTLSGenerator_GetExtensionNames(t *testing.T) {
	generator := NewTLSGenerator()

	// Test Chrome 120 (has post-quantum support)
	version120 := ChromeVersion{Major: 120}
	extensions120 := generator.getExtensionNames(version120)

	assert.Contains(t, extensions120, "server_name")
	assert.Contains(t, extensions120, "supported_groups")
	assert.Contains(t, extensions120, "key_share")
	assert.Contains(t, extensions120, "post_quantum_key_share")

	// Test Chrome 110 (has extension shuffling)
	version110 := ChromeVersion{Major: 110}
	extensions110 := generator.getExtensionNames(version110)

	assert.Contains(t, extensions110, "server_name")
	assert.Contains(t, extensions110, "extension_shuffling")
	assert.NotContains(t, extensions110, "post_quantum_key_share")

	// Test Chrome 100 (no special features)
	version100 := ChromeVersion{Major: 100}
	extensions100 := generator.getExtensionNames(version100)

	assert.Contains(t, extensions100, "server_name")
	assert.NotContains(t, extensions100, "post_quantum_key_share")
	assert.NotContains(t, extensions100, "extension_shuffling")
}

func TestTLSGenerator_GenerateDeterministicRandom(t *testing.T) {
	generator := NewTLSGenerator()

	version := ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109}
	
	random1 := generator.generateDeterministicRandom(version)
	random2 := generator.generateDeterministicRandom(version)

	// Should be deterministic (same input produces same output)
	assert.Equal(t, random1, random2)
	assert.Len(t, random1, 32)

	// Different version should produce different random
	differentVersion := ChromeVersion{Major: 121, Minor: 0, Build: 6100, Patch: 110}
	differentRandom := generator.generateDeterministicRandom(differentVersion)
	assert.NotEqual(t, random1, differentRandom)
}

// Benchmark tests
func BenchmarkTLSGenerator_GenerateTemplate(b *testing.B) {
	generator := NewTLSGenerator()
	version := ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		template, err := generator.GenerateTemplate(version)
		require.NoError(b, err)
		require.NotNil(b, template)
	}
}

func BenchmarkTLSGenerator_CalculateJA3Hash(b *testing.B) {
	generator := NewTLSGenerator()
	ja3String := "771,4865-4866-4867,0-23-65281,29-23-24,0"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = generator.calculateJA3Hash(ja3String)
	}
}