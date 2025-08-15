package tlsgen

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name        string
		versionStr  string
		expected    ChromeVersion
		expectError bool
	}{
		{
			name:       "full version",
			versionStr: "120.0.6099.109",
			expected: ChromeVersion{
				Major: 120,
				Minor: 0,
				Build: 6099,
				Patch: 109,
			},
		},
		{
			name:       "version with v prefix",
			versionStr: "v120.0.6099.109",
			expected: ChromeVersion{
				Major: 120,
				Minor: 0,
				Build: 6099,
				Patch: 109,
			},
		},
		{
			name:       "three part version",
			versionStr: "120.0.6099",
			expected: ChromeVersion{
				Major: 120,
				Minor: 0,
				Build: 6099,
				Patch: 0,
			},
		},
		{
			name:       "two part version",
			versionStr: "120.0",
			expected: ChromeVersion{
				Major: 120,
				Minor: 0,
				Build: 0,
				Patch: 0,
			},
		},
		{
			name:       "single part version",
			versionStr: "120",
			expected: ChromeVersion{
				Major: 120,
				Minor: 0,
				Build: 0,
				Patch: 0,
			},
		},
		{
			name:        "invalid version",
			versionStr:  "invalid",
			expectError: true,
		},
		{
			name:        "empty version",
			versionStr:  "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, err := ParseVersion(tt.versionStr)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, version)
			} else {
				require.NoError(t, err)
				require.NotNil(t, version)
				assert.Equal(t, tt.expected.Major, version.Major)
				assert.Equal(t, tt.expected.Minor, version.Minor)
				assert.Equal(t, tt.expected.Build, version.Build)
				assert.Equal(t, tt.expected.Patch, version.Patch)
			}
		})
	}
}

func TestChromeVersionString(t *testing.T) {
	version := ChromeVersion{
		Major: 120,
		Minor: 0,
		Build: 6099,
		Patch: 109,
	}

	assert.Equal(t, "120.0.6099.109", version.String())
	assert.Equal(t, "120.0.6099", version.ShortString())
	assert.Equal(t, "120.0", version.GetMajorMinor())
	assert.Equal(t, "120.0.6099", version.GetMajorMinorBuild())
}

func TestChromeVersionComparison(t *testing.T) {
	v120 := ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109}
	v121 := ChromeVersion{Major: 121, Minor: 0, Build: 6100, Patch: 110}
	v120Same := ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109}

	// Test IsNewer
	assert.True(t, v121.IsNewer(v120))
	assert.False(t, v120.IsNewer(v121))
	assert.False(t, v120.IsNewer(v120Same))

	// Test IsOlder
	assert.True(t, v120.IsOlder(v121))
	assert.False(t, v121.IsOlder(v120))
	assert.False(t, v120.IsOlder(v120Same))

	// Test Equal
	assert.True(t, v120.Equal(v120Same))
	assert.False(t, v120.Equal(v121))
}

func TestChromeVersionSupport(t *testing.T) {
	tests := []struct {
		name      string
		version   ChromeVersion
		supported bool
	}{
		{
			name:      "Chrome 120 supported",
			version:   ChromeVersion{Major: 120},
			supported: true,
		},
		{
			name:      "Chrome 70 supported",
			version:   ChromeVersion{Major: 70},
			supported: true,
		},
		{
			name:      "Chrome 69 not supported",
			version:   ChromeVersion{Major: 69},
			supported: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.supported, tt.version.IsSupported())
		})
	}
}

func TestChromeVersionUTLSFingerprint(t *testing.T) {
	tests := []struct {
		name        string
		version     ChromeVersion
		fingerprint string
	}{
		{
			name:        "Chrome 133",
			version:     ChromeVersion{Major: 133},
			fingerprint: "HelloChrome_133",
		},
		{
			name:        "Chrome 120",
			version:     ChromeVersion{Major: 120},
			fingerprint: "HelloChrome_120",
		},
		{
			name:        "Chrome 115",
			version:     ChromeVersion{Major: 115},
			fingerprint: "HelloChrome_115_PQ",
		},
		{
			name:        "Chrome 100",
			version:     ChromeVersion{Major: 100},
			fingerprint: "HelloChrome_100",
		},
		{
			name:        "Chrome 69 fallback",
			version:     ChromeVersion{Major: 69},
			fingerprint: "HelloChrome_100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.fingerprint, tt.version.GetUTLSFingerprint())
		})
	}
}

func TestChromeVersionFeatures(t *testing.T) {
	tests := []struct {
		name                    string
		version                 ChromeVersion
		hasPostQuantumSupport   bool
		hasExtensionShuffling   bool
	}{
		{
			name:                    "Chrome 120",
			version:                 ChromeVersion{Major: 120},
			hasPostQuantumSupport:   true,
			hasExtensionShuffling:   false,
		},
		{
			name:                    "Chrome 115",
			version:                 ChromeVersion{Major: 115},
			hasPostQuantumSupport:   true,
			hasExtensionShuffling:   false,
		},
		{
			name:                    "Chrome 110",
			version:                 ChromeVersion{Major: 110},
			hasPostQuantumSupport:   false,
			hasExtensionShuffling:   true,
		},
		{
			name:                    "Chrome 100",
			version:                 ChromeVersion{Major: 100},
			hasPostQuantumSupport:   false,
			hasExtensionShuffling:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.hasPostQuantumSupport, tt.version.HasPostQuantumSupport())
			assert.Equal(t, tt.hasExtensionShuffling, tt.version.HasExtensionShuffling())
		})
	}
}

func TestChromeVersionTLSVersions(t *testing.T) {
	v120 := ChromeVersion{Major: 120}
	v69 := ChromeVersion{Major: 69}

	tlsVersions120 := v120.GetTLSVersions()
	assert.Contains(t, tlsVersions120, "TLS 1.2")
	assert.Contains(t, tlsVersions120, "TLS 1.3")

	tlsVersions69 := v69.GetTLSVersions()
	assert.Contains(t, tlsVersions69, "TLS 1.2")
	assert.NotContains(t, tlsVersions69, "TLS 1.3")
}

func TestChromeVersionCipherSuites(t *testing.T) {
	version := ChromeVersion{Major: 120}
	cipherSuites := version.GetCipherSuites()

	assert.NotEmpty(t, cipherSuites)
	assert.Contains(t, cipherSuites, "TLS_AES_128_GCM_SHA256")
	assert.Contains(t, cipherSuites, "TLS_AES_256_GCM_SHA384")
	assert.Contains(t, cipherSuites, "TLS_CHACHA20_POLY1305_SHA256")
}

func TestChromeVersionSupportedGroups(t *testing.T) {
	v120 := ChromeVersion{Major: 120}
	v100 := ChromeVersion{Major: 100}

	groups120 := v120.GetSupportedGroups()
	assert.Contains(t, groups120, "X25519")
	assert.Contains(t, groups120, "secp256r1")
	assert.Contains(t, groups120, "X25519Kyber768Draft00") // Post-quantum

	groups100 := v100.GetSupportedGroups()
	assert.Contains(t, groups100, "X25519")
	assert.Contains(t, groups100, "secp256r1")
	assert.NotContains(t, groups100, "X25519Kyber768Draft00") // No post-quantum
}

func TestChromeVersionALPNProtocols(t *testing.T) {
	version := ChromeVersion{Major: 120}
	protocols := version.GetALPNProtocols()

	assert.Contains(t, protocols, "h2")
	assert.Contains(t, protocols, "http/1.1")
}

func TestChromeVersionDistance(t *testing.T) {
	v120 := ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109}
	v121 := ChromeVersion{Major: 121, Minor: 0, Build: 6100, Patch: 110}
	v120Same := ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109}

	// Distance to same version should be 0
	assert.Equal(t, 0, v120.GetVersionDistance(v120Same))

	// Distance to different version should be > 0
	distance := v120.GetVersionDistance(v121)
	assert.Greater(t, distance, 0)

	// Distance should be symmetric
	assert.Equal(t, distance, v121.GetVersionDistance(v120))
}

func TestChromeVersionValidation(t *testing.T) {
	tests := []struct {
		name        string
		version     ChromeVersion
		expectError bool
	}{
		{
			name:        "valid version",
			version:     ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expectError: false,
		},
		{
			name:        "negative major",
			version:     ChromeVersion{Major: -1, Minor: 0, Build: 0, Patch: 0},
			expectError: true,
		},
		{
			name:        "negative minor",
			version:     ChromeVersion{Major: 120, Minor: -1, Build: 0, Patch: 0},
			expectError: true,
		},
		{
			name:        "zero major",
			version:     ChromeVersion{Major: 0, Minor: 0, Build: 0, Patch: 0},
			expectError: true,
		},
		{
			name:        "major too high",
			version:     ChromeVersion{Major: 1000, Minor: 0, Build: 0, Patch: 0},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.version.Validate()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestChromeVersionClone(t *testing.T) {
	original := ChromeVersion{
		Major:    120,
		Minor:    0,
		Build:    6099,
		Patch:    109,
		Channel:  "stable",
		Platform: "linux",
		Date:     time.Now(),
	}

	cloned := original.Clone()

	// Should be equal but different instances
	assert.True(t, original.Equal(cloned))
	assert.Equal(t, original.Channel, cloned.Channel)
	assert.Equal(t, original.Platform, cloned.Platform)
	assert.Equal(t, original.Date, cloned.Date)

	// Modifying clone shouldn't affect original
	cloned.Major = 121
	assert.NotEqual(t, original.Major, cloned.Major)
}

func TestChromeVersionIsVersionInRange(t *testing.T) {
	v120 := ChromeVersion{Major: 120}
	v115 := ChromeVersion{Major: 115}
	v125 := ChromeVersion{Major: 125}

	// v120 should be in range [115, 125]
	assert.True(t, v120.IsVersionInRange(v115, v125))

	// v120 should not be in range [125, 130]
	v130 := ChromeVersion{Major: 130}
	assert.False(t, v120.IsVersionInRange(v125, v130))

	// Edge cases
	assert.True(t, v120.IsVersionInRange(v120, v125)) // Equal to min
	assert.True(t, v120.IsVersionInRange(v115, v120)) // Equal to max
}

func TestChromeVersionStable(t *testing.T) {
	stableVersion := ChromeVersion{Channel: "stable"}
	betaVersion := ChromeVersion{Channel: "beta"}
	devVersion := ChromeVersion{Channel: "dev"}

	assert.True(t, stableVersion.IsStable())
	assert.False(t, betaVersion.IsStable())
	assert.False(t, devVersion.IsStable())

	// Case insensitive
	stableUpperVersion := ChromeVersion{Channel: "STABLE"}
	assert.True(t, stableUpperVersion.IsStable())
}