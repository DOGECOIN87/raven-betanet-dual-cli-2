package checks

import (
	"os"
	"testing"
	"time"
)

// MockCheck implements ComplianceCheck for testing
type MockCheck struct {
	id          string
	description string
	result      CheckResult
}

func (m *MockCheck) ID() string {
	return m.id
}

func (m *MockCheck) Description() string {
	return m.description
}

func (m *MockCheck) Execute(binaryPath string) CheckResult {
	// Set the ID and description in the result
	m.result.ID = m.id
	m.result.Description = m.description
	return m.result
}

func TestNewCheckRegistry(t *testing.T) {
	registry := NewCheckRegistry()
	if registry == nil {
		t.Fatal("NewCheckRegistry() returned nil")
	}
	if registry.Count() != 0 {
		t.Errorf("Expected empty registry, got count: %d", registry.Count())
	}
}

func TestCheckRegistry_Register(t *testing.T) {
	registry := NewCheckRegistry()
	
	check := &MockCheck{
		id:          "test-check-1",
		description: "Test check 1",
		result:      CheckResult{Status: "pass", Details: "Test passed"},
	}
	
	err := registry.Register(check)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	
	if registry.Count() != 1 {
		t.Errorf("Expected count=1, got: %d", registry.Count())
	}
}

func TestCheckRegistry_RegisterNil(t *testing.T) {
	registry := NewCheckRegistry()
	
	err := registry.Register(nil)
	if err == nil {
		t.Error("Expected error when registering nil check, got nil")
	}
}

func TestCheckRegistry_RegisterEmptyID(t *testing.T) {
	registry := NewCheckRegistry()
	
	check := &MockCheck{
		id:          "",
		description: "Test check",
	}
	
	err := registry.Register(check)
	if err == nil {
		t.Error("Expected error when registering check with empty ID, got nil")
	}
}

func TestCheckRegistry_RegisterDuplicate(t *testing.T) {
	registry := NewCheckRegistry()
	
	check1 := &MockCheck{
		id:          "duplicate-id",
		description: "Test check 1",
	}
	check2 := &MockCheck{
		id:          "duplicate-id",
		description: "Test check 2",
	}
	
	err := registry.Register(check1)
	if err != nil {
		t.Fatalf("First Register() error = %v", err)
	}
	
	err = registry.Register(check2)
	if err == nil {
		t.Error("Expected error when registering duplicate ID, got nil")
	}
}

func TestCheckRegistry_Get(t *testing.T) {
	registry := NewCheckRegistry()
	
	check := &MockCheck{
		id:          "test-check",
		description: "Test check",
	}
	
	registry.Register(check)
	
	retrieved, exists := registry.Get("test-check")
	if !exists {
		t.Error("Expected check to exist, got false")
	}
	if retrieved.ID() != "test-check" {
		t.Errorf("Expected ID=test-check, got: %s", retrieved.ID())
	}
	
	_, exists = registry.Get("non-existent")
	if exists {
		t.Error("Expected non-existent check to not exist, got true")
	}
}

func TestCheckRegistry_List(t *testing.T) {
	registry := NewCheckRegistry()
	
	checks := []*MockCheck{
		{id: "check-c", description: "Check C"},
		{id: "check-a", description: "Check A"},
		{id: "check-b", description: "Check B"},
	}
	
	for _, check := range checks {
		registry.Register(check)
	}
	
	ids := registry.List()
	expected := []string{"check-a", "check-b", "check-c"}
	
	if len(ids) != len(expected) {
		t.Errorf("Expected %d IDs, got: %d", len(expected), len(ids))
	}
	
	for i, id := range ids {
		if id != expected[i] {
			t.Errorf("Expected ID[%d]=%s, got: %s", i, expected[i], id)
		}
	}
}

func TestCheckRegistry_GetAll(t *testing.T) {
	registry := NewCheckRegistry()
	
	checks := []*MockCheck{
		{id: "check-1", description: "Check 1"},
		{id: "check-2", description: "Check 2"},
	}
	
	for _, check := range checks {
		registry.Register(check)
	}
	
	allChecks := registry.GetAll()
	if len(allChecks) != 2 {
		t.Errorf("Expected 2 checks, got: %d", len(allChecks))
	}
}

func TestNewCheckRunner(t *testing.T) {
	registry := NewCheckRegistry()
	runner := NewCheckRunner(registry)
	
	if runner == nil {
		t.Fatal("NewCheckRunner() returned nil")
	}
	if runner.registry != registry {
		t.Error("CheckRunner registry not set correctly")
	}
}

func TestCheckRunner_RunAll(t *testing.T) {
	// Create a temporary test file
	tempFile := createTempFile(t, "test binary content")
	defer os.Remove(tempFile)
	
	registry := NewCheckRegistry()
	
	// Register test checks
	passingCheck := &MockCheck{
		id:          "passing-check",
		description: "A check that passes",
		result:      CheckResult{Status: "pass", Details: "Check passed successfully"},
	}
	failingCheck := &MockCheck{
		id:          "failing-check",
		description: "A check that fails",
		result:      CheckResult{Status: "fail", Details: "Check failed"},
	}
	
	registry.Register(passingCheck)
	registry.Register(failingCheck)
	
	runner := NewCheckRunner(registry)
	report, err := runner.RunAll(tempFile)
	
	if err != nil {
		t.Fatalf("RunAll() error = %v", err)
	}
	
	if report == nil {
		t.Fatal("RunAll() returned nil report")
	}
	
	if report.TotalChecks != 2 {
		t.Errorf("Expected TotalChecks=2, got: %d", report.TotalChecks)
	}
	if report.PassedChecks != 1 {
		t.Errorf("Expected PassedChecks=1, got: %d", report.PassedChecks)
	}
	if report.FailedChecks != 1 {
		t.Errorf("Expected FailedChecks=1, got: %d", report.FailedChecks)
	}
	if report.BinaryPath != tempFile {
		t.Errorf("Expected BinaryPath=%s, got: %s", tempFile, report.BinaryPath)
	}
	if report.BinaryHash == "" {
		t.Error("Expected BinaryHash to be set")
	}
	if len(report.Results) != 2 {
		t.Errorf("Expected 2 results, got: %d", len(report.Results))
	}
}

func TestCheckRunner_RunSelected(t *testing.T) {
	// Create a temporary test file
	tempFile := createTempFile(t, "test binary content")
	defer os.Remove(tempFile)
	
	registry := NewCheckRegistry()
	
	// Register test checks
	check1 := &MockCheck{
		id:          "check-1",
		description: "Check 1",
		result:      CheckResult{Status: "pass", Details: "Check 1 passed"},
	}
	check2 := &MockCheck{
		id:          "check-2",
		description: "Check 2",
		result:      CheckResult{Status: "fail", Details: "Check 2 failed"},
	}
	
	registry.Register(check1)
	registry.Register(check2)
	
	runner := NewCheckRunner(registry)
	
	// Run only check-1
	report, err := runner.RunSelected(tempFile, []string{"check-1"})
	
	if err != nil {
		t.Fatalf("RunSelected() error = %v", err)
	}
	
	if report.TotalChecks != 1 {
		t.Errorf("Expected TotalChecks=1, got: %d", report.TotalChecks)
	}
	if report.PassedChecks != 1 {
		t.Errorf("Expected PassedChecks=1, got: %d", report.PassedChecks)
	}
	if report.FailedChecks != 0 {
		t.Errorf("Expected FailedChecks=0, got: %d", report.FailedChecks)
	}
	if len(report.Results) != 1 {
		t.Errorf("Expected 1 result, got: %d", len(report.Results))
	}
	if report.Results[0].ID != "check-1" {
		t.Errorf("Expected result ID=check-1, got: %s", report.Results[0].ID)
	}
}

func TestCheckRunner_RunSelectedNonExistent(t *testing.T) {
	tempFile := createTempFile(t, "test binary content")
	defer os.Remove(tempFile)
	
	registry := NewCheckRegistry()
	runner := NewCheckRunner(registry)
	
	_, err := runner.RunSelected(tempFile, []string{"non-existent-check"})
	if err == nil {
		t.Error("Expected error for non-existent check, got nil")
	}
}

func TestCheckRunner_RunInvalidBinaryPath(t *testing.T) {
	registry := NewCheckRegistry()
	runner := NewCheckRunner(registry)
	
	_, err := runner.RunAll("/non/existent/file")
	if err == nil {
		t.Error("Expected error for non-existent file, got nil")
	}
}

func TestCheckRunner_RunEmptyRegistry(t *testing.T) {
	tempFile := createTempFile(t, "test binary content")
	defer os.Remove(tempFile)
	
	registry := NewCheckRegistry()
	runner := NewCheckRunner(registry)
	
	_, err := runner.RunAll(tempFile)
	if err == nil {
		t.Error("Expected error for empty registry, got nil")
	}
}

func TestValidateBinaryPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		setup   func() string
		cleanup func(string)
		wantErr bool
	}{
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
		},
		{
			name:    "non-existent file",
			path:    "/non/existent/file",
			wantErr: true,
		},
		{
			name: "directory instead of file",
			setup: func() string {
				return t.TempDir()
			},
			wantErr: true,
		},
		{
			name: "valid file",
			setup: func() string {
				return createTempFile(t, "test content")
			},
			cleanup: func(path string) {
				os.Remove(path)
			},
			wantErr: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.path
			if tt.setup != nil {
				path = tt.setup()
			}
			if tt.cleanup != nil {
				defer tt.cleanup(path)
			}
			
			err := validateBinaryPath(path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateBinaryPath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCalculateFileHash(t *testing.T) {
	content := "test file content for hashing"
	tempFile := createTempFile(t, content)
	defer os.Remove(tempFile)
	
	hash1, err := calculateFileHash(tempFile)
	if err != nil {
		t.Fatalf("calculateFileHash() error = %v", err)
	}
	
	if hash1 == "" {
		t.Error("Expected non-empty hash")
	}
	
	// Hash should be consistent
	hash2, err := calculateFileHash(tempFile)
	if err != nil {
		t.Fatalf("calculateFileHash() second call error = %v", err)
	}
	
	if hash1 != hash2 {
		t.Errorf("Hash inconsistent: %s != %s", hash1, hash2)
	}
	
	// Hash should be different for different content
	tempFile2 := createTempFile(t, "different content")
	defer os.Remove(tempFile2)
	
	hash3, err := calculateFileHash(tempFile2)
	if err != nil {
		t.Fatalf("calculateFileHash() third call error = %v", err)
	}
	
	if hash1 == hash3 {
		t.Error("Expected different hashes for different content")
	}
}

func TestComplianceReport_IsReportPassing(t *testing.T) {
	tests := []struct {
		name         string
		failedChecks int
		want         bool
	}{
		{
			name:         "all checks passed",
			failedChecks: 0,
			want:         true,
		},
		{
			name:         "some checks failed",
			failedChecks: 1,
			want:         false,
		},
		{
			name:         "many checks failed",
			failedChecks: 5,
			want:         false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &ComplianceReport{
				FailedChecks: tt.failedChecks,
			}
			
			got := report.IsReportPassing()
			if got != tt.want {
				t.Errorf("IsReportPassing() = %v, want %v", got, tt.want)
			}
		})
	}
}

// SlowMockCheck implements ComplianceCheck with a delay for testing duration
type SlowMockCheck struct {
	id          string
	description string
	result      CheckResult
	delay       time.Duration
}

func (s *SlowMockCheck) ID() string {
	return s.id
}

func (s *SlowMockCheck) Description() string {
	return s.description
}

func (s *SlowMockCheck) Execute(binaryPath string) CheckResult {
	time.Sleep(s.delay)
	s.result.ID = s.id
	s.result.Description = s.description
	return s.result
}

func TestCheckResultDuration(t *testing.T) {
	tempFile := createTempFile(t, "test content")
	defer os.Remove(tempFile)
	
	registry := NewCheckRegistry()
	
	// Create a check that takes some time
	slowCheck := &SlowMockCheck{
		id:          "slow-check",
		description: "A slow check",
		result:      CheckResult{Status: "pass", Details: "Slow check completed"},
		delay:       10 * time.Millisecond,
	}
	
	registry.Register(slowCheck)
	runner := NewCheckRunner(registry)
	
	report, err := runner.RunAll(tempFile)
	if err != nil {
		t.Fatalf("RunAll() error = %v", err)
	}
	
	if len(report.Results) != 1 {
		t.Fatalf("Expected 1 result, got: %d", len(report.Results))
	}
	
	result := report.Results[0]
	if result.Duration == 0 {
		t.Error("Expected non-zero duration for check execution")
	}
	if result.Duration < 10*time.Millisecond {
		t.Errorf("Expected duration >= 10ms, got: %v", result.Duration)
	}
}

// Helper function to create a temporary file with content
func createTempFile(t *testing.T, content string) string {
	tempFile, err := os.CreateTemp("", "test-binary-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	
	if _, err := tempFile.WriteString(content); err != nil {
		tempFile.Close()
		os.Remove(tempFile.Name())
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	
	tempFile.Close()
	return tempFile.Name()
}