package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"
)

// ComplianceCheck defines the interface for all compliance checks
type ComplianceCheck interface {
	ID() string
	Description() string
	Execute(binaryPath string) CheckResult
}

// CheckResult represents the result of a compliance check
type CheckResult struct {
	ID          string                 `json:"check_id"`
	Description string                 `json:"description"`
	Status      string                 `json:"status"` // "pass" | "fail"
	Details     string                 `json:"details"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Duration    time.Duration          `json:"duration,omitempty"`
}

// ComplianceReport represents the complete report of all compliance checks
type ComplianceReport struct {
	Timestamp    time.Time     `json:"timestamp"`
	BinaryPath   string        `json:"binary_path"`
	BinaryHash   string        `json:"binary_hash"`
	TotalChecks  int           `json:"total_checks"`
	PassedChecks int           `json:"passed_checks"`
	FailedChecks int           `json:"failed_checks"`
	Results      []CheckResult `json:"results"`
	SBOMPath     string        `json:"sbom_path,omitempty"`
	Duration     time.Duration `json:"duration,omitempty"`
}

// CheckRegistry manages all available compliance checks
type CheckRegistry struct {
	checks map[string]ComplianceCheck
	mu     sync.RWMutex
}

// NewCheckRegistry creates a new check registry
func NewCheckRegistry() *CheckRegistry {
	return &CheckRegistry{
		checks: make(map[string]ComplianceCheck),
	}
}

// Register adds a compliance check to the registry
func (r *CheckRegistry) Register(check ComplianceCheck) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if check == nil {
		return fmt.Errorf("check cannot be nil")
	}
	
	id := check.ID()
	if id == "" {
		return fmt.Errorf("check ID cannot be empty")
	}
	
	if _, exists := r.checks[id]; exists {
		return fmt.Errorf("check with ID %s already registered", id)
	}
	
	r.checks[id] = check
	return nil
}

// Get retrieves a compliance check by ID
func (r *CheckRegistry) Get(id string) (ComplianceCheck, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	check, exists := r.checks[id]
	return check, exists
}

// List returns all registered check IDs in sorted order
func (r *CheckRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	ids := make([]string, 0, len(r.checks))
	for id := range r.checks {
		ids = append(ids, id)
	}
	
	sort.Strings(ids)
	return ids
}

// GetAll returns all registered checks
func (r *CheckRegistry) GetAll() []ComplianceCheck {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	checks := make([]ComplianceCheck, 0, len(r.checks))
	for _, check := range r.checks {
		checks = append(checks, check)
	}
	
	return checks
}

// Count returns the number of registered checks
func (r *CheckRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	return len(r.checks)
}

// CheckRunner executes compliance checks and generates reports
type CheckRunner struct {
	registry *CheckRegistry
}

// NewCheckRunner creates a new check runner
func NewCheckRunner(registry *CheckRegistry) *CheckRunner {
	return &CheckRunner{
		registry: registry,
	}
}

// RunAll executes all registered checks against a binary
func (r *CheckRunner) RunAll(binaryPath string) (*ComplianceReport, error) {
	return r.RunSelected(binaryPath, nil)
}

// RunSelected executes selected checks against a binary
func (r *CheckRunner) RunSelected(binaryPath string, checkIDs []string) (*ComplianceReport, error) {
	startTime := time.Now()
	
	// Validate binary path
	if err := validateBinaryPath(binaryPath); err != nil {
		return nil, fmt.Errorf("invalid binary path: %w", err)
	}
	
	// Calculate binary hash
	binaryHash, err := calculateFileHash(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate binary hash: %w", err)
	}
	
	// Determine which checks to run
	var checksToRun []ComplianceCheck
	if len(checkIDs) == 0 {
		// Run all checks
		checksToRun = r.registry.GetAll()
	} else {
		// Run selected checks
		for _, id := range checkIDs {
			check, exists := r.registry.Get(id)
			if !exists {
				return nil, fmt.Errorf("check with ID %s not found", id)
			}
			checksToRun = append(checksToRun, check)
		}
	}
	
	if len(checksToRun) == 0 {
		return nil, fmt.Errorf("no checks to run")
	}
	
	// Execute checks
	results := make([]CheckResult, len(checksToRun))
	for i, check := range checksToRun {
		checkStart := time.Now()
		result := check.Execute(binaryPath)
		result.Duration = time.Since(checkStart)
		results[i] = result
	}
	
	// Sort results by check ID for consistent output
	sort.Slice(results, func(i, j int) bool {
		return results[i].ID < results[j].ID
	})
	
	// Count passed/failed checks
	passedCount := 0
	failedCount := 0
	for _, result := range results {
		if result.Status == "pass" {
			passedCount++
		} else {
			failedCount++
		}
	}
	
	report := &ComplianceReport{
		Timestamp:    startTime,
		BinaryPath:   binaryPath,
		BinaryHash:   binaryHash,
		TotalChecks:  len(results),
		PassedChecks: passedCount,
		FailedChecks: failedCount,
		Results:      results,
		Duration:     time.Since(startTime),
	}
	
	return report, nil
}

// validateBinaryPath validates that the binary path exists and is readable
func validateBinaryPath(path string) error {
	if path == "" {
		return fmt.Errorf("binary path cannot be empty")
	}
	
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("binary file does not exist: %s", path)
		}
		return fmt.Errorf("cannot access binary file: %w", err)
	}
	
	if info.IsDir() {
		return fmt.Errorf("path is a directory, not a file: %s", path)
	}
	
	// Check if file is readable
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot read binary file: %w", err)
	}
	file.Close()
	
	return nil
}

// calculateFileHash calculates the SHA256 hash of a file
func calculateFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// IsReportPassing returns true if all checks in the report passed
func (r *ComplianceReport) IsReportPassing() bool {
	return r.FailedChecks == 0
}