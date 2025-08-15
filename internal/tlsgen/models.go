package tlsgen

import (
	"time"
)

// ChromeVersionManager defines the interface for managing Chrome versions
type ChromeVersionManager interface {
	// GetLatestStable returns the latest stable Chrome version
	GetLatestStable() (*ChromeVersion, error)
	
	// GetStableN2 returns the stable N-2 Chrome version
	GetStableN2() (*ChromeVersion, error)
	
	// GetVersion returns a specific Chrome version
	GetVersion(version string) (*ChromeVersion, error)
	
	// UpdateVersions fetches the latest version information
	UpdateVersions() error
	
	// ListCachedVersions returns all cached Chrome versions
	ListCachedVersions() ([]*ChromeVersion, error)
}

// HandshakeGenerator defines the interface for generating TLS handshakes
type HandshakeGenerator interface {
	// GenerateClientHello creates a ClientHello for the specified Chrome version
	GenerateClientHello(version *ChromeVersion) ([]byte, error)
	
	// GenerateForVersion creates a ClientHello for a specific version string
	GenerateForVersion(version string) ([]byte, error)
	
	// ValidateClientHello verifies that a ClientHello matches expected Chrome behavior
	ValidateClientHello(clientHello []byte, expectedVersion *ChromeVersion) error
}

// JA3CalculatorInterface defines the interface for calculating JA3 fingerprints
// This avoids conflict with the existing JA3Calculator struct
type JA3CalculatorInterface interface {
	// Calculate computes the JA3 fingerprint from a TLS connection
	Calculate(serverName string, port int) (*JA3Result, error)
	
	// CalculateFromClientHello computes JA3 from a ClientHello blob
	CalculateFromClientHello(clientHello []byte) (*JA3Result, error)
	
	// Compare compares two JA3 results for equality
	Compare(result1, result2 *JA3Result) bool
}

// VersionCache defines the interface for caching Chrome version data
type VersionCache interface {
	// Store saves a Chrome version to the cache
	Store(version *ChromeVersion) error
	
	// Get retrieves a Chrome version from the cache
	Get(version string) (*ChromeVersion, error)
	
	// List returns all cached versions
	List() ([]*ChromeVersion, error)
	
	// Clear removes all cached versions
	Clear() error
	
	// IsExpired checks if the cache is expired
	IsExpired() bool
}

// ExtendedChromeVersion represents additional Chrome version data for TLS characteristics
// This extends the existing ChromeVersion struct with TLS-specific fields
type ExtendedChromeVersion struct {
	JA3String   string    `json:"ja3_string"`
	JA3Hash     string    `json:"ja3_hash"`
	ClientHello []byte    `json:"client_hello,omitempty"`
	Cached      time.Time `json:"cached"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// JA3Result contains the result of a JA3 fingerprint calculation
type JA3Result struct {
	String     string        `json:"ja3_string"`
	Hash       string        `json:"ja3_hash"`
	ServerName string        `json:"server_name"`
	Port       int           `json:"port"`
	Duration   time.Duration `json:"duration"`
	TLSVersion uint16        `json:"tls_version"`
	CipherSuite uint16       `json:"cipher_suite"`
	Timestamp  time.Time     `json:"timestamp"`
	Error      string        `json:"error,omitempty"`
}

// ChromeTemplate represents a cached Chrome TLS template
type ChromeTemplate struct {
	Version     string            `json:"version"`
	Channel     string            `json:"channel"`
	ClientHello []byte            `json:"client_hello"`
	JA3String   string            `json:"ja3_string"`
	JA3Hash     string            `json:"ja3_hash"`
	Generated   time.Time         `json:"generated"`
	Metadata    map[string]string `json:"metadata"`
}

// VersionInfo represents Chrome version information from the API
type VersionInfo struct {
	OS       string `json:"os"`
	Channel  string `json:"channel"`
	Version  string `json:"version"`
	Current  bool   `json:"current_version"`
	Previous bool   `json:"previous_version"`
}

// APIResponse represents the response from the Chrome version API
type APIResponse struct {
	Versions []VersionInfo `json:"versions"`
	Updated  time.Time     `json:"updated"`
}

// TLSConfig contains configuration for TLS connections
type TLSConfig struct {
	ServerName         string        `json:"server_name"`
	Port               int           `json:"port"`
	Timeout            time.Duration `json:"timeout"`
	InsecureSkipVerify bool          `json:"insecure_skip_verify"`
	MinVersion         uint16        `json:"min_version"`
	MaxVersion         uint16        `json:"max_version"`
}

// ConnectionResult contains the result of a TLS connection attempt
type ConnectionResult struct {
	Success        bool          `json:"success"`
	JA3Result      *JA3Result    `json:"ja3_result,omitempty"`
	Error          string        `json:"error,omitempty"`
	Duration       time.Duration `json:"duration"`
	ServerCerts    []string      `json:"server_certs,omitempty"`
	TLSVersion     uint16        `json:"tls_version"`
	CipherSuite    uint16        `json:"cipher_suite"`
	ServerName     string        `json:"server_name"`
	ConnectedAt    time.Time     `json:"connected_at"`
}