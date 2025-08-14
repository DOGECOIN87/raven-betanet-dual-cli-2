package testutils

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestRunner provides utilities for integration tests with cleanup
type TestRunner struct {
	t           *testing.T
	tempDirs    []string
	tempFiles   []string
	cleanupFunc []func() error
}

// NewTestRunner creates a new test runner with cleanup capabilities
func NewTestRunner(t *testing.T) *TestRunner {
	runner := &TestRunner{
		t:           t,
		tempDirs:    make([]string, 0),
		tempFiles:   make([]string, 0),
		cleanupFunc: make([]func() error, 0),
	}

	// Register cleanup function
	t.Cleanup(func() {
		runner.Cleanup()
	})

	return runner
}

// CreateTempDir creates a temporary directory and registers it for cleanup
func (tr *TestRunner) CreateTempDir(prefix string) string {
	dir, err := os.MkdirTemp("", prefix)
	require.NoError(tr.t, err, "Failed to create temp directory")
	
	tr.tempDirs = append(tr.tempDirs, dir)
	return dir
}

// CreateTempFile creates a temporary file and registers it for cleanup
func (tr *TestRunner) CreateTempFile(dir, pattern string) *os.File {
	file, err := os.CreateTemp(dir, pattern)
	require.NoError(tr.t, err, "Failed to create temp file")
	
	tr.tempFiles = append(tr.tempFiles, file.Name())
	return file
}

// WriteTestFile writes content to a file in the temp directory
func (tr *TestRunner) WriteTestFile(dir, filename, content string) string {
	filePath := filepath.Join(dir, filename)
	err := os.WriteFile(filePath, []byte(content), 0644)
	require.NoError(tr.t, err, "Failed to write test file")
	
	tr.tempFiles = append(tr.tempFiles, filePath)
	return filePath
}

// AddCleanupFunc adds a custom cleanup function
func (tr *TestRunner) AddCleanupFunc(fn func() error) {
	tr.cleanupFunc = append(tr.cleanupFunc, fn)
}

// Cleanup removes all temporary files and directories
func (tr *TestRunner) Cleanup() {
	// Run custom cleanup functions first
	for _, fn := range tr.cleanupFunc {
		if err := fn(); err != nil {
			tr.t.Logf("Cleanup function failed: %v", err)
		}
	}

	// Remove temporary files
	for _, file := range tr.tempFiles {
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			tr.t.Logf("Failed to remove temp file %s: %v", file, err)
		}
	}

	// Remove temporary directories
	for _, dir := range tr.tempDirs {
		if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
			tr.t.Logf("Failed to remove temp dir %s: %v", dir, err)
		}
	}
}

// TestTimeout represents test timeout configuration
type TestTimeout struct {
	Short  time.Duration
	Medium time.Duration
	Long   time.Duration
}

// DefaultTimeouts provides default timeout values for tests
var DefaultTimeouts = TestTimeout{
	Short:  5 * time.Second,
	Medium: 30 * time.Second,
	Long:   2 * time.Minute,
}

// WithTimeout runs a test function with a timeout
func WithTimeout(t *testing.T, timeout time.Duration, fn func()) {
	done := make(chan bool, 1)
	
	go func() {
		fn()
		done <- true
	}()
	
	select {
	case <-done:
		// Test completed successfully
	case <-time.After(timeout):
		t.Fatalf("Test timed out after %v", timeout)
	}
}

// AssertGoldenFile compares output with a golden file
func AssertGoldenFile(t *testing.T, goldenPath string, actual []byte) {
	if os.Getenv("UPDATE_GOLDEN") == "true" {
		// Update golden file
		err := os.MkdirAll(filepath.Dir(goldenPath), 0755)
		require.NoError(t, err, "Failed to create golden file directory")
		
		err = os.WriteFile(goldenPath, actual, 0644)
		require.NoError(t, err, "Failed to update golden file")
		
		t.Logf("Updated golden file: %s", goldenPath)
		return
	}
	
	// Compare with existing golden file
	expected, err := os.ReadFile(goldenPath)
	if os.IsNotExist(err) {
		t.Fatalf("Golden file does not exist: %s. Run with UPDATE_GOLDEN=true to create it.", goldenPath)
	}
	require.NoError(t, err, "Failed to read golden file")
	
	require.Equal(t, string(expected), string(actual), 
		fmt.Sprintf("Output differs from golden file %s", goldenPath))
}

// CLIResult represents the result of a CLI command execution
type CLIResult struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
	Error    error
	Duration time.Duration
}

// RunCLICommand executes a CLI command and returns detailed results
func (tr *TestRunner) RunCLICommand(command string, args ...string) *CLIResult {
	return tr.RunCLICommandWithTimeout(DefaultTimeouts.Medium, command, args...)
}

// RunCLICommandWithTimeout executes a CLI command with a specific timeout
func (tr *TestRunner) RunCLICommandWithTimeout(timeout time.Duration, command string, args ...string) *CLIResult {
	start := time.Now()
	
	cmd := exec.Command(command, args...)
	
	// Capture both stdout and stderr separately
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	result := &CLIResult{
		Duration: time.Since(start),
	}
	
	// Run command with timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()
	
	select {
	case err := <-done:
		result.Error = err
		result.Stdout = stdout.Bytes()
		result.Stderr = stderr.Bytes()
		
		if err != nil {
			if exitError, ok := err.(*exec.ExitError); ok {
				result.ExitCode = exitError.ExitCode()
			} else {
				result.ExitCode = -1
			}
		} else {
			result.ExitCode = 0
		}
		
	case <-time.After(timeout):
		cmd.Process.Kill()
		result.Error = fmt.Errorf("command timed out after %v", timeout)
		result.ExitCode = -1
		result.Stdout = stdout.Bytes()
		result.Stderr = stderr.Bytes()
	}
	
	result.Duration = time.Since(start)
	return result
}

// BuildBinary builds a Go binary for testing
func (tr *TestRunner) BuildBinary(packagePath, outputName string) string {
	tempDir := tr.CreateTempDir(fmt.Sprintf("%s-build-", outputName))
	binaryPath := filepath.Join(tempDir, outputName)
	
	result := tr.RunCLICommand("go", "build", "-o", binaryPath, packagePath)
	require.Equal(tr.t, 0, result.ExitCode, 
		"Failed to build %s: stdout=%s, stderr=%s", packagePath, result.Stdout, result.Stderr)
	
	// Verify binary exists and is executable
	require.FileExists(tr.t, binaryPath, "Built binary should exist")
	
	return binaryPath
}

// AssertCLISuccess asserts that a CLI command succeeded
func AssertCLISuccess(t *testing.T, result *CLIResult, msgAndArgs ...interface{}) {
	require.Equal(t, 0, result.ExitCode, 
		append([]interface{}{"CLI command should succeed. stdout=%s, stderr=%s, error=%v"}, 
			result.Stdout, result.Stderr, result.Error)...)
}

// AssertCLIFailure asserts that a CLI command failed with expected exit code
func AssertCLIFailure(t *testing.T, result *CLIResult, expectedExitCode int, msgAndArgs ...interface{}) {
	require.Equal(t, expectedExitCode, result.ExitCode,
		append([]interface{}{"CLI command should fail with exit code %d. stdout=%s, stderr=%s, error=%v"}, 
			expectedExitCode, result.Stdout, result.Stderr, result.Error)...)
}