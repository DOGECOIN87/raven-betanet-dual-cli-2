package tlsgen

import (
	"testing"
	"time"
)

func TestChromeVersion_String(t *testing.T) {
	tests := []struct {
		name     string
		version  ChromeVersion
		expected string
	}{
		{
			name: "standard version",
			version: ChromeVersion{
				Major: 120,
				Minor: 0,
				Build: 6099,
				Patch: 109,
			},
			expected: "120.0.6099.109",
		},
		{
			name: "version with zeros",
			version: ChromeVersion{
				Major: 119,
				Minor: 0,
				Build: 0,
				Patch: 0,
			},
			expected: "119.0.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.version.String()
			if result != tt.expected {
				t.Errorf("String() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name        string
		versionStr  string
		expected    *ChromeVersion
		expectError bool
	}{
		{
			name:       "valid version",
			versionStr: "120.0.6099.109",
			expected: &ChromeVersion{
				Major: 120,
				Minor: 0,
				Build: 6099,
				Patch: 109,
			},
			expectError: false,
		},
		{
			name:       "version with zeros",
			versionStr: "119.0.0.0",
			expected: &ChromeVersion{
				Major: 119,
				Minor: 0,
				Build: 0,
				Patch: 0,
			},
			expectError: false,
		},
		{
			name:        "invalid format - too few parts",
			versionStr:  "120.0.6099",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "invalid format - too many parts",
			versionStr:  "120.0.6099.109.1",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "invalid major version",
			versionStr:  "abc.0.6099.109",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "invalid minor version",
			versionStr:  "120.abc.6099.109",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "invalid build version",
			versionStr:  "120.0.abc.109",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "invalid patch version",
			versionStr:  "120.0.6099.abc",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "empty string",
			versionStr:  "",
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseVersion(tt.versionStr)
			
			if tt.expectError {
				if err == nil {
					t.Errorf("ParseVersion() expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("ParseVersion() unexpected error: %v", err)
				return
			}
			
			if result == nil {
				t.Errorf("ParseVersion() returned nil result")
				return
			}
			
			if result.Major != tt.expected.Major ||
				result.Minor != tt.expected.Minor ||
				result.Build != tt.expected.Build ||
				result.Patch != tt.expected.Patch {
				t.Errorf("ParseVersion() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestChromeVersion_Compare(t *testing.T) {
	tests := []struct {
		name     string
		version1 ChromeVersion
		version2 ChromeVersion
		expected int
	}{
		{
			name: "equal versions",
			version1: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: 0,
		},
		{
			name: "version1 newer major",
			version1: ChromeVersion{Major: 121, Minor: 0, Build: 6099, Patch: 109},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: 1,
		},
		{
			name: "version1 older major",
			version1: ChromeVersion{Major: 119, Minor: 0, Build: 6099, Patch: 109},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: -1,
		},
		{
			name: "version1 newer minor",
			version1: ChromeVersion{Major: 120, Minor: 1, Build: 6099, Patch: 109},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: 1,
		},
		{
			name: "version1 older minor",
			version1: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			version2: ChromeVersion{Major: 120, Minor: 1, Build: 6099, Patch: 109},
			expected: -1,
		},
		{
			name: "version1 newer build",
			version1: ChromeVersion{Major: 120, Minor: 0, Build: 6100, Patch: 109},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: 1,
		},
		{
			name: "version1 older build",
			version1: ChromeVersion{Major: 120, Minor: 0, Build: 6098, Patch: 109},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: -1,
		},
		{
			name: "version1 newer patch",
			version1: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 110},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: 1,
		},
		{
			name: "version1 older patch",
			version1: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 108},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.version1.Compare(tt.version2)
			if result != tt.expected {
				t.Errorf("Compare() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestChromeVersion_IsNewer(t *testing.T) {
	tests := []struct {
		name     string
		version1 ChromeVersion
		version2 ChromeVersion
		expected bool
	}{
		{
			name: "version1 is newer",
			version1: ChromeVersion{Major: 121, Minor: 0, Build: 6099, Patch: 109},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: true,
		},
		{
			name: "version1 is older",
			version1: ChromeVersion{Major: 119, Minor: 0, Build: 6099, Patch: 109},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: false,
		},
		{
			name: "versions are equal",
			version1: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.version1.IsNewer(tt.version2)
			if result != tt.expected {
				t.Errorf("IsNewer() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestChromeVersion_IsOlder(t *testing.T) {
	tests := []struct {
		name     string
		version1 ChromeVersion
		version2 ChromeVersion
		expected bool
	}{
		{
			name: "version1 is older",
			version1: ChromeVersion{Major: 119, Minor: 0, Build: 6099, Patch: 109},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: true,
		},
		{
			name: "version1 is newer",
			version1: ChromeVersion{Major: 121, Minor: 0, Build: 6099, Patch: 109},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: false,
		},
		{
			name: "versions are equal",
			version1: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.version1.IsOlder(tt.version2)
			if result != tt.expected {
				t.Errorf("IsOlder() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestChromeVersion_Equal(t *testing.T) {
	tests := []struct {
		name     string
		version1 ChromeVersion
		version2 ChromeVersion
		expected bool
	}{
		{
			name: "versions are equal",
			version1: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: true,
		},
		{
			name: "versions differ in major",
			version1: ChromeVersion{Major: 121, Minor: 0, Build: 6099, Patch: 109},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: false,
		},
		{
			name: "versions differ in minor",
			version1: ChromeVersion{Major: 120, Minor: 1, Build: 6099, Patch: 109},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: false,
		},
		{
			name: "versions differ in build",
			version1: ChromeVersion{Major: 120, Minor: 0, Build: 6100, Patch: 109},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: false,
		},
		{
			name: "versions differ in patch",
			version1: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 110},
			version2: ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
			expected: false,
		},
		{
			name: "versions with metadata are equal",
			version1: ChromeVersion{
				Major: 120, Minor: 0, Build: 6099, Patch: 109,
				Channel: "Stable", Platform: "Linux", Date: time.Now(),
			},
			version2: ChromeVersion{
				Major: 120, Minor: 0, Build: 6099, Patch: 109,
				Channel: "Beta", Platform: "Windows", Date: time.Now().Add(-time.Hour),
			},
			expected: true, // Equal only compares version numbers, not metadata
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.version1.Equal(tt.version2)
			if result != tt.expected {
				t.Errorf("Equal() = %v, want %v", result, tt.expected)
			}
		})
	}
}