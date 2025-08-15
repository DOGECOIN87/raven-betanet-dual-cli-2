package tlsgen

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ChromeVersion represents a Chrome browser version
type ChromeVersion struct {
	Major    int       `json:"major"`
	Minor    int       `json:"minor"`
	Build    int       `json:"build"`
	Patch    int       `json:"patch"`
	Channel  string    `json:"channel"`
	Platform string    `json:"platform"`
	Date     time.Time `json:"date"`
}

// String returns the version as a string (e.g., "120.0.6099.109")
func (v ChromeVersion) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", v.Major, v.Minor, v.Build, v.Patch)
}

// ShortString returns the version as a short string (e.g., "120.0.6099")
func (v ChromeVersion) ShortString() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Build)
}

// IsNewer returns true if this version is newer than the other version
func (v ChromeVersion) IsNewer(other ChromeVersion) bool {
	if v.Major != other.Major {
		return v.Major > other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor > other.Minor
	}
	if v.Build != other.Build {
		return v.Build > other.Build
	}
	return v.Patch > other.Patch
}

// IsOlder returns true if this version is older than the other version
func (v ChromeVersion) IsOlder(other ChromeVersion) bool {
	return other.IsNewer(v)
}

// Equal returns true if this version equals the other version
func (v ChromeVersion) Equal(other ChromeVersion) bool {
	return v.Major == other.Major &&
		v.Minor == other.Minor &&
		v.Build == other.Build &&
		v.Patch == other.Patch
}

// IsStable returns true if this is a stable channel release
func (v ChromeVersion) IsStable() bool {
	return strings.ToLower(v.Channel) == "stable"
}

// ParseVersion parses a version string into a ChromeVersion
func ParseVersion(versionStr string) (*ChromeVersion, error) {
	// Remove any prefix like "v" or whitespace
	versionStr = strings.TrimSpace(versionStr)
	versionStr = strings.TrimPrefix(versionStr, "v")
	versionStr = strings.TrimPrefix(versionStr, "V")

	// Regular expression to match version patterns
	// Supports: "120.0.6099.109", "120.0.6099", "120.0", "120"
	versionRegex := regexp.MustCompile(`^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?`)
	matches := versionRegex.FindStringSubmatch(versionStr)

	if len(matches) < 2 {
		return nil, fmt.Errorf("invalid version format: %s", versionStr)
	}

	version := &ChromeVersion{}

	// Parse major version (required)
	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return nil, fmt.Errorf("invalid major version: %s", matches[1])
	}
	version.Major = major

	// Parse minor version (optional, default to 0)
	if len(matches) > 2 && matches[2] != "" {
		minor, err := strconv.Atoi(matches[2])
		if err != nil {
			return nil, fmt.Errorf("invalid minor version: %s", matches[2])
		}
		version.Minor = minor
	}

	// Parse build version (optional, default to 0)
	if len(matches) > 3 && matches[3] != "" {
		build, err := strconv.Atoi(matches[3])
		if err != nil {
			return nil, fmt.Errorf("invalid build version: %s", matches[3])
		}
		version.Build = build
	}

	// Parse patch version (optional, default to 0)
	if len(matches) > 4 && matches[4] != "" {
		patch, err := strconv.Atoi(matches[4])
		if err != nil {
			return nil, fmt.Errorf("invalid patch version: %s", matches[4])
		}
		version.Patch = patch
	}

	return version, nil
}

// GetMajorMinor returns the major.minor version as a string
func (v ChromeVersion) GetMajorMinor() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// GetMajorMinorBuild returns the major.minor.build version as a string
func (v ChromeVersion) GetMajorMinorBuild() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Build)
}

// IsSupported returns true if this Chrome version is supported by uTLS
func (v ChromeVersion) IsSupported() bool {
	// uTLS supports Chrome 70 and above
	return v.Major >= 70
}

// GetUTLSFingerprint returns the appropriate uTLS fingerprint identifier for this Chrome version
func (v ChromeVersion) GetUTLSFingerprint() string {
	switch {
	case v.Major >= 133:
		return "HelloChrome_133"
	case v.Major >= 131:
		return "HelloChrome_131"
	case v.Major >= 120:
		return "HelloChrome_120"
	case v.Major >= 115:
		return "HelloChrome_115_PQ"
	case v.Major >= 106:
		return "HelloChrome_106_Shuffle"
	case v.Major >= 102:
		return "HelloChrome_102"
	case v.Major >= 100:
		return "HelloChrome_100"
	case v.Major >= 96:
		return "HelloChrome_96"
	case v.Major >= 87:
		return "HelloChrome_87"
	case v.Major >= 83:
		return "HelloChrome_83"
	case v.Major >= 72:
		return "HelloChrome_72"
	case v.Major >= 70:
		return "HelloChrome_70"
	default:
		// Fallback to Chrome 100 for unsupported versions
		return "HelloChrome_100"
	}
}

// HasPostQuantumSupport returns true if this Chrome version supports post-quantum cryptography
func (v ChromeVersion) HasPostQuantumSupport() bool {
	return v.Major >= 115
}

// HasExtensionShuffling returns true if this Chrome version uses extension shuffling
func (v ChromeVersion) HasExtensionShuffling() bool {
	return v.Major >= 106 && v.Major < 115
}

// GetExpectedJA3Hash returns the expected JA3 hash for this Chrome version
// This is a simplified implementation - real implementation would have a database of known hashes
func (v ChromeVersion) GetExpectedJA3Hash() string {
	// These are example hashes - real implementation would maintain a database
	// of known Chrome JA3 fingerprints for different versions
	switch {
	case v.Major >= 120:
		return "cd08e31494f9531f560d64c695473da9" // Example hash for Chrome 120+
	case v.Major >= 115:
		return "b32309a26951912be7dba376398abc3b" // Example hash for Chrome 115-119
	case v.Major >= 106:
		return "a0e9f5d64349fb13191bc781f81f42e1" // Example hash for Chrome 106-114
	case v.Major >= 100:
		return "72a589da586844d7f0818ce684948eea" // Example hash for Chrome 100-105
	case v.Major >= 87:
		return "4a244b25d3b8c7c5e8b1c6d2f9e3a7b8" // Example hash for Chrome 87-99
	case v.Major >= 83:
		return "5c3d2e1f4a5b6c7d8e9f0a1b2c3d4e5f" // Example hash for Chrome 83-86
	case v.Major >= 72:
		return "6d4e3f2a5b6c7d8e9f0a1b2c3d4e5f6a" // Example hash for Chrome 72-82
	default:
		return "7e5f4a3b6c7d8e9f0a1b2c3d4e5f6a7b" // Fallback hash
	}
}

// GetTLSVersions returns the TLS versions supported by this Chrome version
func (v ChromeVersion) GetTLSVersions() []string {
	versions := []string{"TLS 1.2", "TLS 1.3"}
	
	// Chrome 70+ supports TLS 1.3
	if v.Major >= 70 {
		return versions
	}
	
	// Older versions only support up to TLS 1.2
	return []string{"TLS 1.2"}
}

// GetCipherSuites returns the cipher suites supported by this Chrome version
func (v ChromeVersion) GetCipherSuites() []string {
	// This is a simplified list - real implementation would have version-specific cipher suites
	suites := []string{
		"TLS_AES_128_GCM_SHA256",
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	}
	
	return suites
}

// GetSupportedGroups returns the supported elliptic curve groups for this Chrome version
func (v ChromeVersion) GetSupportedGroups() []string {
	groups := []string{
		"X25519",
		"secp256r1",
		"secp384r1",
	}
	
	// Chrome 115+ includes post-quantum key exchange
	if v.HasPostQuantumSupport() {
		groups = append([]string{"X25519Kyber768Draft00"}, groups...)
	}
	
	return groups
}

// GetSignatureAlgorithms returns the supported signature algorithms for this Chrome version
func (v ChromeVersion) GetSignatureAlgorithms() []string {
	return []string{
		"ecdsa_secp256r1_sha256",
		"rsa_pss_rsae_sha256",
		"rsa_pkcs1_sha256",
		"ecdsa_secp384r1_sha384",
		"rsa_pss_rsae_sha384",
		"rsa_pkcs1_sha384",
		"rsa_pss_rsae_sha512",
		"rsa_pkcs1_sha512",
	}
}

// GetALPNProtocols returns the ALPN protocols supported by this Chrome version
func (v ChromeVersion) GetALPNProtocols() []string {
	return []string{
		"h2",
		"http/1.1",
	}
}

// IsVersionInRange checks if this version is within the specified range
func (v ChromeVersion) IsVersionInRange(min, max ChromeVersion) bool {
	return !v.IsOlder(min) && !v.IsNewer(max)
}

// GetVersionDistance returns the "distance" between two versions
// Useful for finding the closest version match
func (v ChromeVersion) GetVersionDistance(other ChromeVersion) int {
	majorDiff := abs(v.Major - other.Major)
	minorDiff := abs(v.Minor - other.Minor)
	buildDiff := abs(v.Build - other.Build)
	patchDiff := abs(v.Patch - other.Patch)
	
	// Weight major version differences more heavily
	return majorDiff*1000000 + minorDiff*10000 + buildDiff*100 + patchDiff
}

// abs returns the absolute value of an integer
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// Clone creates a copy of the ChromeVersion
func (v ChromeVersion) Clone() ChromeVersion {
	return ChromeVersion{
		Major:    v.Major,
		Minor:    v.Minor,
		Build:    v.Build,
		Patch:    v.Patch,
		Channel:  v.Channel,
		Platform: v.Platform,
		Date:     v.Date,
	}
}

// Validate checks if the version is valid
func (v ChromeVersion) Validate() error {
	if v.Major < 0 {
		return fmt.Errorf("major version cannot be negative: %d", v.Major)
	}
	if v.Minor < 0 {
		return fmt.Errorf("minor version cannot be negative: %d", v.Minor)
	}
	if v.Build < 0 {
		return fmt.Errorf("build version cannot be negative: %d", v.Build)
	}
	if v.Patch < 0 {
		return fmt.Errorf("patch version cannot be negative: %d", v.Patch)
	}
	
	// Chrome versions should be reasonable
	if v.Major < 1 || v.Major > 999 {
		return fmt.Errorf("major version out of reasonable range: %d", v.Major)
	}
	
	return nil
}