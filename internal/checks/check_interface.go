package checks

import (
	"time"
)

// ComplianceCheck defines the interface that all compliance checks must implement
type ComplianceCheck interface {
	// ID returns the unique identifier for this check (e.g., "check-1-file-signature")
	ID() string
	
	// Description returns a detailed description of what this check validates
	Description() string
	
	// Execute runs the compliance check against the specified binary
	Execute(binaryPath string) CheckResult
}

// CheckStatus represents the possible outcomes of a compliance check
type CheckStatus string

const (
	StatusPass  CheckStatus = "pass"
	StatusFail  CheckStatus = "fail"
	StatusSkip  CheckStatus = "skip"
	StatusError CheckStatus = "error"
)

// CheckResult contains the outcome of a compliance check execution
type CheckResult struct {
	ID          string                 `json:"id"`           // For compatibility with existing code
	CheckID     int                    `json:"check_id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`  // For compatibility with existing code
	Status      string                 `json:"status"`       // Using string for compatibility with existing code
	Message     string                 `json:"message"`
	Details     interface{}            `json:"details,omitempty"`
	Duration    time.Duration          `json:"duration"`
	Error       error                  `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"` // For compatibility with existing code
}

// ExtendedBinaryInfo contains additional extracted information about a binary file
// This extends the existing BinaryInfo struct with additional fields needed for compliance checks
type ExtendedBinaryInfo struct {
	Dependencies []string          `json:"dependencies"`
	Metadata     map[string]string `json:"metadata"`
	FileSize     int64             `json:"file_size"`
	FilePath     string            `json:"file_path"`
}

// SectionInfo contains information about a binary section
type SectionInfo struct {
	Name    string `json:"name"`
	Size    uint64 `json:"size"`
	Offset  uint64 `json:"offset"`
	Address uint64 `json:"address"`
	Type    string `json:"type"`
}

// CryptoInfo contains cryptographic information extracted from a binary
type CryptoInfo struct {
	Certificates []CertificateInfo `json:"certificates"`
	Signatures   []SignatureInfo   `json:"signatures"`
	Hashes       map[string]string `json:"hashes"`
	Encryption   EncryptionInfo    `json:"encryption"`
}

// CertificateInfo contains information about an embedded certificate
type CertificateInfo struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	SerialNumber string   `json:"serial_number"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	IsValid     bool      `json:"is_valid"`
	Algorithm   string    `json:"algorithm"`
}

// SignatureInfo contains information about a digital signature
type SignatureInfo struct {
	Algorithm   string    `json:"algorithm"`
	SignedBy    string    `json:"signed_by"`
	Timestamp   time.Time `json:"timestamp"`
	IsValid     bool      `json:"is_valid"`
	Certificate string    `json:"certificate,omitempty"`
}

// EncryptionInfo contains information about encryption used in the binary
type EncryptionInfo struct {
	Algorithms []string          `json:"algorithms"`
	KeySizes   map[string]int    `json:"key_sizes"`
	Standards  []string          `json:"standards"`
	Details    map[string]string `json:"details"`
}

// SecurityFlags contains security-related flags and features
type SecurityFlags struct {
	NX       bool `json:"nx"`        // No-Execute bit
	RELRO    bool `json:"relro"`     // Relocation Read-Only
	PIE      bool `json:"pie"`       // Position Independent Executable
	DEP      bool `json:"dep"`       // Data Execution Prevention (Windows)
	ASLR     bool `json:"aslr"`      // Address Space Layout Randomization
	StackGuard bool `json:"stack_guard"` // Stack protection
}

// VersionInfo contains version metadata extracted from the binary
type VersionInfo struct {
	Version     string            `json:"version"`
	BuildDate   time.Time         `json:"build_date,omitempty"`
	BuildNumber string            `json:"build_number,omitempty"`
	Metadata    map[string]string `json:"metadata"`
}

// LicenseInfo contains license compliance information
type LicenseInfo struct {
	DetectedLicenses []string          `json:"detected_licenses"`
	LicenseFiles     []string          `json:"license_files"`
	Confidence       float64           `json:"confidence"`
	Details          map[string]string `json:"details"`
}

// CheckRegistry manages a collection of compliance checks
type CheckRegistry struct {
	checks map[string]ComplianceCheck
}

// NewCheckRegistry creates a new check registry
func NewCheckRegistry() *CheckRegistry {
	return &CheckRegistry{
		checks: make(map[string]ComplianceCheck),
	}
}

// Register adds a compliance check to the registry
func (r *CheckRegistry) Register(check ComplianceCheck) error {
	r.checks[check.ID()] = check
	return nil
}

// Get retrieves a check by ID
func (r *CheckRegistry) Get(id string) (ComplianceCheck, bool) {
	check, exists := r.checks[id]
	return check, exists
}

// List returns all registered checks
func (r *CheckRegistry) List() []ComplianceCheck {
	checks := make([]ComplianceCheck, 0, len(r.checks))
	for _, check := range r.checks {
		checks = append(checks, check)
	}
	return checks
}

// CheckRunner executes compliance checks
type CheckRunner struct {
	registry *CheckRegistry
}

// NewCheckRunner creates a new check runner
func NewCheckRunner(registry *CheckRegistry) *CheckRunner {
	return &CheckRunner{
		registry: registry,
	}
}

// CheckReport contains the results of running multiple checks
type CheckReport struct {
	BinaryPath   string        `json:"binary_path"`
	Results      []CheckResult `json:"results"`
	Summary      CheckSummary  `json:"summary"`
	TotalChecks  int           `json:"total_checks"`  // For compatibility with existing tests
	PassedChecks int           `json:"passed_checks"` // For compatibility with existing tests
	FailedChecks int           `json:"failed_checks"` // For compatibility with existing tests
}

// CheckSummary contains summary statistics for a check report
type CheckSummary struct {
	Total  int `json:"total"`
	Passed int `json:"passed"`
	Failed int `json:"failed"`
	Errors int `json:"errors"`
}

// RunAll executes all registered checks against a binary
func (r *CheckRunner) RunAll(binaryPath string) (*CheckReport, error) {
	checks := r.registry.List()
	results := make([]CheckResult, 0, len(checks))
	
	for _, check := range checks {
		result := check.Execute(binaryPath)
		results = append(results, result)
	}
	
	summary := r.calculateSummary(results)
	
	return &CheckReport{
		BinaryPath:   binaryPath,
		Results:      results,
		Summary:      summary,
		TotalChecks:  summary.Total,
		PassedChecks: summary.Passed,
		FailedChecks: summary.Failed,
	}, nil
}

// RunSelected executes specific checks by ID against a binary
func (r *CheckRunner) RunSelected(binaryPath string, checkIDs []string) (*CheckReport, error) {
	results := make([]CheckResult, 0, len(checkIDs))
	
	for _, id := range checkIDs {
		check, exists := r.registry.Get(id)
		if !exists {
			continue // Skip unknown checks
		}
		
		result := check.Execute(binaryPath)
		results = append(results, result)
	}
	
	summary := r.calculateSummary(results)
	
	return &CheckReport{
		BinaryPath:   binaryPath,
		Results:      results,
		Summary:      summary,
		TotalChecks:  summary.Total,
		PassedChecks: summary.Passed,
		FailedChecks: summary.Failed,
	}, nil
}

// calculateSummary calculates summary statistics from check results
func (r *CheckRunner) calculateSummary(results []CheckResult) CheckSummary {
	summary := CheckSummary{Total: len(results)}
	
	for _, result := range results {
		switch result.Status {
		case "pass":
			summary.Passed++
		case "fail":
			summary.Failed++
		case "error":
			summary.Errors++
		}
	}
	
	return summary
}