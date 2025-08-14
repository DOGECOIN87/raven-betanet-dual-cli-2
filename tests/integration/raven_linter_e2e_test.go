package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testutils "github.com/raven-betanet/dual-cli/tests/utils"
	"github.com/raven-betanet/dual-cli/internal/checks"
)

// TestRavenLinterE2E tests the complete raven-linter CLI workflow
func TestRavenLinterE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping end-to-end tests in short mode")
	}

	runner := testutils.NewTestRunner(t)
	projectRoot := getProjectRoot(t)
	
	// Build the raven-linter binary for testing
	binaryPath := buildRavenLinter(t, runner)
	
	t.Run("Full workflow with valid binary", func(t *testing.T) {
		testValidBinaryWorkflow(t, runner, binaryPath, projectRoot)
	})
	
	t.Run("Full workflow with invalid binary", func(t *testing.T) {
		testInvalidBinaryWorkflow(t, runner, binaryPath, projectRoot)
	})
	
	t.Run("SBOM generation workflow", func(t *testing.T) {
		testSBOMGenerationWorkflow(t, runner, binaryPath, projectRoot)
	})
	
	t.Run("Error scenarios", func(t *testing.T) {
		testErrorScenarios(t, runner, binaryPath, projectRoot)
	})
	
	t.Run("Performance with large binary", func(t *testing.T) {
		testPerformanceWithLargeBinary(t, runner, binaryPath, projectRoot)
	})
}

// buildRavenLinter builds the raven-linter binary for testing
func buildRavenLinter(t *testing.T, runner *testutils.TestRunner) string {
	tempDir := runner.CreateTempDir("raven-linter-build-")
	binaryPath := filepath.Join(tempDir, "raven-linter")
	
	// Build the binary
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/raven-linter")
	cmd.Dir = getProjectRoot(t)
	
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to build raven-linter: %s", string(output))
	
	// Verify binary exists and is executable
	assert.FileExists(t, binaryPath)
	
	// Test that binary runs
	cmd = exec.Command(binaryPath, "--version")
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to run raven-linter --version: %s", string(output))
	
	return binaryPath
}

// testValidBinaryWorkflow tests the complete workflow with a valid binary
func testValidBinaryWorkflow(t *testing.T, runner *testutils.TestRunner, binaryPath, projectRoot string) {
	validBinary := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/valid_elf_binary")
	tempDir := runner.CreateTempDir("valid-binary-test-")
	
	t.Run("JSON output format", func(t *testing.T) {
		// Run raven-linter check with JSON output
		cmd := exec.Command(binaryPath, "check", validBinary, "--format", "json")
		cmd.Dir = tempDir
		
		output, err := cmd.Output()
		require.NoError(t, err, "raven-linter check should succeed for valid binary")
		
		// Parse JSON output
		var report checks.ComplianceReport
		err = json.Unmarshal(output, &report)
		require.NoError(t, err, "Output should be valid JSON")
		
		// Validate report structure
		assert.Equal(t, validBinary, report.BinaryPath)
		assert.NotEmpty(t, report.BinaryHash)
		assert.NotZero(t, report.Timestamp)
		assert.Equal(t, 11, report.TotalChecks, "Should run all 11 compliance checks")
		assert.Equal(t, report.TotalChecks, report.PassedChecks, "All checks should pass for valid binary")
		assert.Equal(t, 0, report.FailedChecks)
		assert.Len(t, report.Results, 11, "Should have results for all 11 checks")
		
		// Validate individual check results
		for _, result := range report.Results {
			assert.NotEmpty(t, result.ID, "Check ID should not be empty")
			assert.NotEmpty(t, result.Description, "Check description should not be empty")
			assert.Equal(t, "pass", result.Status, "All checks should pass for valid binary")
			assert.NotEmpty(t, result.Details, "Check details should not be empty")
		}
		
		// Compare with golden file
		goldenPath := filepath.Join(projectRoot, "tests/golden/compliance_results/valid_elf_all_pass.json")
		testutils.AssertGoldenFile(t, goldenPath, output)
	})
	
	t.Run("Text output format", func(t *testing.T) {
		// Run raven-linter check with text output
		cmd := exec.Command(binaryPath, "check", validBinary, "--format", "text")
		cmd.Dir = tempDir
		
		output, err := cmd.Output()
		require.NoError(t, err, "raven-linter check should succeed for valid binary")
		
		outputStr := string(output)
		
		// Validate text output contains expected elements
		assert.Contains(t, outputStr, "Raven Betanet 1.1 Compliance Report")
		assert.Contains(t, outputStr, "Summary: 11/11 checks passed")
		assert.Contains(t, outputStr, "✓ PASS")
		assert.NotContains(t, outputStr, "✗ FAIL")
		assert.NotContains(t, outputStr, "Failed Checks Details")
		
		// Validate that all check IDs are present
		expectedCheckIDs := []string{
			"check-001", "check-002", "check-003", "check-004",
			"check-005", "check-006", "check-007", "check-008",
			"check-009", "check-010", "check-011",
		}
		
		for _, checkID := range expectedCheckIDs {
			assert.Contains(t, outputStr, checkID, "Text output should contain check ID: %s", checkID)
		}
	})
	
	t.Run("Verbose output", func(t *testing.T) {
		// Run raven-linter check with verbose output
		cmd := exec.Command(binaryPath, "check", validBinary, "--format", "text", "--verbose")
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "raven-linter check should succeed for valid binary")
		
		outputStr := string(output)
		
		// Verbose output should contain debug information
		assert.Contains(t, outputStr, "Running compliance checks")
		assert.Contains(t, outputStr, "Registered")
		assert.Contains(t, outputStr, "compliance checks")
	})
}

// testInvalidBinaryWorkflow tests the workflow with an invalid binary
func testInvalidBinaryWorkflow(t *testing.T, runner *testutils.TestRunner, binaryPath, projectRoot string) {
	invalidBinary := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/invalid_elf_binary")
	tempDir := runner.CreateTempDir("invalid-binary-test-")
	
	t.Run("JSON output with failures", func(t *testing.T) {
		// Run raven-linter check with JSON output (should fail)
		cmd := exec.Command(binaryPath, "check", invalidBinary, "--format", "json")
		cmd.Dir = tempDir
		
		output, err := cmd.Output()
		// Command should exit with non-zero status due to failed checks
		var exitError *exec.ExitError
		require.ErrorAs(t, err, &exitError)
		assert.Equal(t, 1, exitError.ExitCode(), "Should exit with code 1 for failed checks")
		
		// Parse JSON output
		var report checks.ComplianceReport
		err = json.Unmarshal(output, &report)
		require.NoError(t, err, "Output should be valid JSON even with failures")
		
		// Validate report structure
		assert.Equal(t, invalidBinary, report.BinaryPath)
		assert.NotEmpty(t, report.BinaryHash)
		assert.Equal(t, 11, report.TotalChecks)
		assert.Greater(t, report.FailedChecks, 0, "Should have some failed checks")
		assert.Equal(t, report.TotalChecks, report.PassedChecks+report.FailedChecks)
		
		// Validate that we have both pass and fail results
		hasPass := false
		hasFail := false
		for _, result := range report.Results {
			if result.Status == "pass" {
				hasPass = true
			}
			if result.Status == "fail" {
				hasFail = true
			}
		}
		assert.True(t, hasFail, "Should have at least one failed check")
		
		// Compare with golden file
		goldenPath := filepath.Join(projectRoot, "tests/golden/compliance_results/invalid_elf_partial_fail.json")
		testutils.AssertGoldenFile(t, goldenPath, output)
	})
	
	t.Run("Text output with failure details", func(t *testing.T) {
		// Run raven-linter check with text output
		cmd := exec.Command(binaryPath, "check", invalidBinary, "--format", "text")
		cmd.Dir = tempDir
		
		output, err := cmd.Output()
		// Command should exit with non-zero status
		var exitError *exec.ExitError
		require.ErrorAs(t, err, &exitError)
		assert.Equal(t, 1, exitError.ExitCode())
		
		outputStr := string(output)
		
		// Validate text output contains failure information
		assert.Contains(t, outputStr, "Raven Betanet 1.1 Compliance Report")
		assert.Contains(t, outputStr, "✗ FAIL")
		assert.Contains(t, outputStr, "Failed Checks Details")
		
		// Should show summary with some failures
		assert.Regexp(t, `Summary: \d+/11 checks passed`, outputStr)
	})
}

// testSBOMGenerationWorkflow tests SBOM generation functionality
func testSBOMGenerationWorkflow(t *testing.T, runner *testutils.TestRunner, binaryPath, projectRoot string) {
	validBinary := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/valid_elf_binary")
	tempDir := runner.CreateTempDir("sbom-test-")
	
	t.Run("CycloneDX SBOM generation", func(t *testing.T) {
		sbomPath := filepath.Join(tempDir, "cyclonedx_sbom.json")
		
		// Run raven-linter with SBOM generation
		cmd := exec.Command(binaryPath, "check", validBinary, 
			"--format", "json", 
			"--sbom", 
			"--sbom-format", "cyclonedx", 
			"--sbom-output", sbomPath)
		cmd.Dir = tempDir
		
		output, err := cmd.Output()
		require.NoError(t, err, "raven-linter check with SBOM should succeed")
		
		// Verify SBOM file was created
		assert.FileExists(t, sbomPath, "SBOM file should be created")
		
		// Parse compliance report
		var report checks.ComplianceReport
		err = json.Unmarshal(output, &report)
		require.NoError(t, err, "Output should be valid JSON")
		
		// Verify SBOM path is included in report
		assert.Equal(t, sbomPath, report.SBOMPath, "Report should include SBOM path")
		
		// Validate SBOM file content
		sbomData, err := os.ReadFile(sbomPath)
		require.NoError(t, err, "Should be able to read SBOM file")
		
		var sbomJSON map[string]interface{}
		err = json.Unmarshal(sbomData, &sbomJSON)
		require.NoError(t, err, "SBOM should be valid JSON")
		
		// Validate CycloneDX structure
		assert.Equal(t, "CycloneDX", sbomJSON["bomFormat"])
		assert.NotEmpty(t, sbomJSON["specVersion"])
		assert.NotEmpty(t, sbomJSON["components"])
		
		// Compare with golden file
		goldenPath := filepath.Join(projectRoot, "tests/golden/sbom_outputs/valid_elf_cyclonedx.json")
		testutils.AssertGoldenFile(t, goldenPath, sbomData)
	})
	
	t.Run("SPDX SBOM generation", func(t *testing.T) {
		sbomPath := filepath.Join(tempDir, "spdx_sbom.json")
		
		// Run raven-linter with SPDX SBOM generation
		cmd := exec.Command(binaryPath, "check", validBinary, 
			"--format", "json", 
			"--sbom", 
			"--sbom-format", "spdx", 
			"--sbom-output", sbomPath)
		cmd.Dir = tempDir
		
		output, err := cmd.Output()
		require.NoError(t, err, "raven-linter check with SPDX SBOM should succeed")
		
		// Verify SBOM file was created
		assert.FileExists(t, sbomPath, "SPDX SBOM file should be created")
		
		// Validate SBOM file content
		sbomData, err := os.ReadFile(sbomPath)
		require.NoError(t, err, "Should be able to read SPDX SBOM file")
		
		var sbomJSON map[string]interface{}
		err = json.Unmarshal(sbomData, &sbomJSON)
		require.NoError(t, err, "SPDX SBOM should be valid JSON")
		
		// Validate SPDX structure
		assert.NotEmpty(t, sbomJSON["spdxVersion"])
		assert.NotEmpty(t, sbomJSON["packages"])
		
		// Compare with golden file
		goldenPath := filepath.Join(projectRoot, "tests/golden/sbom_outputs/valid_elf_spdx.json")
		testutils.AssertGoldenFile(t, goldenPath, sbomData)
	})
	
	t.Run("Default SBOM output path", func(t *testing.T) {
		// Run raven-linter with default SBOM output path
		cmd := exec.Command(binaryPath, "check", validBinary, "--sbom")
		cmd.Dir = tempDir
		
		output, err := cmd.Output()
		require.NoError(t, err, "raven-linter check with default SBOM should succeed")
		
		// Verify default SBOM file was created
		defaultSBOMPath := filepath.Join(tempDir, "sbom.json")
		assert.FileExists(t, defaultSBOMPath, "Default SBOM file should be created")
		
		// Parse compliance report
		var report checks.ComplianceReport
		err = json.Unmarshal(output, &report)
		require.NoError(t, err, "Output should be valid JSON")
		
		// Verify SBOM path is included in report
		expectedPath, _ := filepath.Abs(defaultSBOMPath)
		assert.Equal(t, expectedPath, report.SBOMPath, "Report should include absolute SBOM path")
	})
}

// testErrorScenarios tests various error conditions
func testErrorScenarios(t *testing.T, runner *testutils.TestRunner, binaryPath, projectRoot string) {
	tempDir := runner.CreateTempDir("error-test-")
	
	t.Run("Non-existent binary", func(t *testing.T) {
		nonExistentBinary := filepath.Join(tempDir, "does-not-exist")
		
		cmd := exec.Command(binaryPath, "check", nonExistentBinary)
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.Error(t, err, "Should fail for non-existent binary")
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "Error", "Should contain error message")
	})
	
	t.Run("Invalid output format", func(t *testing.T) {
		validBinary := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/valid_elf_binary")
		
		cmd := exec.Command(binaryPath, "check", validBinary, "--format", "invalid")
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.Error(t, err, "Should fail for invalid output format")
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "invalid output format", "Should contain format error message")
	})
	
	t.Run("Invalid SBOM format", func(t *testing.T) {
		validBinary := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/valid_elf_binary")
		
		cmd := exec.Command(binaryPath, "check", validBinary, "--sbom", "--sbom-format", "invalid")
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.Error(t, err, "Should fail for invalid SBOM format")
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "invalid SBOM format", "Should contain SBOM format error message")
	})
	
	t.Run("Missing required arguments", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "check")
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.Error(t, err, "Should fail when binary path is missing")
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "Error", "Should contain error message")
	})
	
	t.Run("Help output", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "--help")
		cmd.Dir = tempDir
		
		output, err := cmd.Output()
		require.NoError(t, err, "Help should work")
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "raven-linter", "Help should contain tool name")
		assert.Contains(t, outputStr, "check", "Help should contain check command")
		assert.Contains(t, outputStr, "Examples:", "Help should contain examples")
	})
	
	t.Run("Version output", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "--version")
		cmd.Dir = tempDir
		
		output, err := cmd.Output()
		require.NoError(t, err, "Version should work")
		
		outputStr := string(output)
		assert.Regexp(t, `\d+\.\d+\.\d+|dev`, outputStr, "Version should contain version number or 'dev'")
	})
	
	t.Run("Corrupted binary handling", func(t *testing.T) {
		corruptedBinary := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/corrupted_binary")
		
		cmd := exec.Command(binaryPath, "check", corruptedBinary, "--format", "json")
		cmd.Dir = tempDir
		
		output, err := cmd.Output()
		// Should handle corrupted binary gracefully
		var exitError *exec.ExitError
		if err != nil {
			require.ErrorAs(t, err, &exitError, "Should be an exit error")
		}
		
		// Should still produce valid JSON output even for corrupted binary
		var report checks.ComplianceReport
		jsonErr := json.Unmarshal(output, &report)
		require.NoError(t, jsonErr, "Should produce valid JSON even for corrupted binary")
		
		// Should have attempted all checks
		assert.Equal(t, 11, report.TotalChecks, "Should attempt all checks even for corrupted binary")
	})
}

// testPerformanceWithLargeBinary tests performance with large binaries
func testPerformanceWithLargeBinary(t *testing.T, runner *testutils.TestRunner, binaryPath, projectRoot string) {
	largeBinary := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/large_binary")
	tempDir := runner.CreateTempDir("performance-test-")
	
	// Skip if large binary doesn't exist
	if _, err := os.Stat(largeBinary); os.IsNotExist(err) {
		t.Skip("Large binary fixture not available, skipping performance test")
	}
	
	t.Run("Large binary processing time", func(t *testing.T) {
		start := time.Now()
		
		cmd := exec.Command(binaryPath, "check", largeBinary, "--format", "json")
		cmd.Dir = tempDir
		
		// Set a reasonable timeout for large binary processing
		testutils.WithTimeout(t, testutils.DefaultTimeouts.Long, func() {
			output, err := cmd.Output()
			
			duration := time.Since(start)
			t.Logf("Large binary processing took: %v", duration)
			
			// Should complete within reasonable time (2 minutes)
			assert.Less(t, duration, 2*time.Minute, "Large binary processing should complete within 2 minutes")
			
			if err != nil {
				// Log error but don't fail test - large binary might legitimately fail some checks
				t.Logf("Large binary check completed with error (expected): %v", err)
			}
			
			// Should still produce valid JSON output
			var report checks.ComplianceReport
			jsonErr := json.Unmarshal(output, &report)
			require.NoError(t, jsonErr, "Should produce valid JSON for large binary")
			
			// Should have attempted all checks
			assert.Equal(t, 11, report.TotalChecks, "Should attempt all checks for large binary")
			
			// Should have reasonable performance characteristics
			assert.NotZero(t, report.Duration, "Report should include duration")
			assert.Less(t, report.Duration, 2*time.Minute, "Reported duration should be reasonable")
		})
	})
	
	t.Run("Large binary with SBOM generation", func(t *testing.T) {
		sbomPath := filepath.Join(tempDir, "large_binary_sbom.json")
		start := time.Now()
		
		cmd := exec.Command(binaryPath, "check", largeBinary, 
			"--format", "json", 
			"--sbom", 
			"--sbom-output", sbomPath)
		cmd.Dir = tempDir
		
		// Set extended timeout for SBOM generation with large binary
		testutils.WithTimeout(t, 3*time.Minute, func() {
			output, err := cmd.Output()
			
			duration := time.Since(start)
			t.Logf("Large binary with SBOM processing took: %v", duration)
			
			// Should complete within extended time
			assert.Less(t, duration, 3*time.Minute, "Large binary with SBOM should complete within 3 minutes")
			
			if err != nil {
				t.Logf("Large binary with SBOM completed with error (may be expected): %v", err)
			}
			
			// Should produce valid JSON output
			var report checks.ComplianceReport
			jsonErr := json.Unmarshal(output, &report)
			require.NoError(t, jsonErr, "Should produce valid JSON for large binary with SBOM")
			
			// SBOM file should be created (even if some checks fail)
			if report.SBOMPath != "" {
				assert.FileExists(t, sbomPath, "SBOM file should be created for large binary")
				
				// SBOM should be valid JSON
				sbomData, readErr := os.ReadFile(sbomPath)
				require.NoError(t, readErr, "Should be able to read large binary SBOM")
				
				var sbomJSON map[string]interface{}
				sbomErr := json.Unmarshal(sbomData, &sbomJSON)
				require.NoError(t, sbomErr, "Large binary SBOM should be valid JSON")
			}
		})
	})
	
	t.Run("Memory usage with large binary", func(t *testing.T) {
		// This is a basic test - in a real scenario you might want to use
		// more sophisticated memory profiling tools
		cmd := exec.Command(binaryPath, "check", largeBinary, "--format", "json", "--verbose")
		cmd.Dir = tempDir
		
		// Monitor the process (basic approach)
		testutils.WithTimeout(t, testutils.DefaultTimeouts.Long, func() {
			output, err := cmd.CombinedOutput()
			
			if err != nil {
				t.Logf("Large binary check with memory monitoring completed with error: %v", err)
			}
			
			// Basic validation that the process completed
			assert.NotEmpty(t, output, "Should produce output even for large binary")
			
			// Log output size for analysis
			t.Logf("Large binary output size: %d bytes", len(output))
		})
	})
}