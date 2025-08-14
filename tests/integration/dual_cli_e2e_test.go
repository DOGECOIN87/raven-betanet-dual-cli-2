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

// TestDualCLIIntegration tests the integration between both CLI tools
func TestDualCLIIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	runner := testutils.NewTestRunner(t)
	projectRoot := getProjectRoot(t)
	
	// Build both CLI tools
	ravenLinterPath := buildRavenLinter(t, runner)
	chromeUtlsGenPath := buildChromeUtlsGen(t, runner)
	
	t.Run("Full dual CLI workflow", func(t *testing.T) {
		testFullDualWorkflow(t, runner, ravenLinterPath, chromeUtlsGenPath, projectRoot)
	})
	
	t.Run("Parallel execution", func(t *testing.T) {
		testParallelExecution(t, runner, ravenLinterPath, chromeUtlsGenPath, projectRoot)
	})
	
	t.Run("CI/CD simulation", func(t *testing.T) {
		testCICDSimulation(t, runner, ravenLinterPath, chromeUtlsGenPath, projectRoot)
	})
	
	t.Run("Performance comparison", func(t *testing.T) {
		testPerformanceComparison(t, runner, ravenLinterPath, chromeUtlsGenPath, projectRoot)
	})
}

// testFullDualWorkflow tests a complete workflow using both tools
func testFullDualWorkflow(t *testing.T, runner *testutils.TestRunner, ravenLinterPath, chromeUtlsGenPath, projectRoot string) {
	tempDir := runner.CreateTempDir("dual-workflow-")
	validBinary := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/valid_elf_binary")
	
	t.Run("Generate ClientHello and analyze binary", func(t *testing.T) {
		// Step 1: Generate ClientHello using chrome-utls-gen
		clientHelloPath := filepath.Join(tempDir, "workflow_clienthello.bin")
		
		cmd := exec.Command(chromeUtlsGenPath, "generate", "--output", clientHelloPath)
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "ClientHello generation should succeed: %s", string(output))
		assert.FileExists(t, clientHelloPath, "ClientHello file should be created")
		
		// Step 2: Analyze the original binary with raven-linter
		complianceReportPath := filepath.Join(tempDir, "compliance_report.json")
		sbomPath := filepath.Join(tempDir, "workflow_sbom.json")
		
		cmd = exec.Command(ravenLinterPath, "check", validBinary,
			"--format", "json",
			"--sbom",
			"--sbom-output", sbomPath)
		cmd.Dir = tempDir
		
		output, err = cmd.Output()
		require.NoError(t, err, "Compliance check should succeed")
		
		// Write compliance report to file for analysis
		err = os.WriteFile(complianceReportPath, output, 0644)
		require.NoError(t, err, "Should write compliance report")
		
		// Step 3: Verify both outputs are valid
		var report checks.ComplianceReport
		err = json.Unmarshal(output, &report)
		require.NoError(t, err, "Compliance report should be valid JSON")
		
		assert.Equal(t, 11, report.TotalChecks, "Should run all compliance checks")
		assert.FileExists(t, sbomPath, "SBOM should be generated")
		assert.NotEmpty(t, report.SBOMPath, "Report should reference SBOM path")
		
		// Step 4: Validate file sizes and content
		clientHelloInfo, err := os.Stat(clientHelloPath)
		require.NoError(t, err, "Should stat ClientHello file")
		
		sbomInfo, err := os.Stat(sbomPath)
		require.NoError(t, err, "Should stat SBOM file")
		
		assert.Greater(t, clientHelloInfo.Size(), int64(100), "ClientHello should have reasonable size")
		assert.Greater(t, sbomInfo.Size(), int64(100), "SBOM should have reasonable size")
		
		t.Logf("Workflow completed successfully:")
		t.Logf("  ClientHello: %s (%d bytes)", clientHelloPath, clientHelloInfo.Size())
		t.Logf("  Compliance Report: %s", complianceReportPath)
		t.Logf("  SBOM: %s (%d bytes)", sbomPath, sbomInfo.Size())
		t.Logf("  Compliance Status: %d/%d checks passed", report.PassedChecks, report.TotalChecks)
	})
	
	t.Run("Cross-tool validation", func(t *testing.T) {
		// Generate ClientHello with specific Chrome version
		clientHelloPath := filepath.Join(tempDir, "chrome120_clienthello.bin")
		chromeVersion := "120.0.6099.109"
		
		cmd := exec.Command(chromeUtlsGenPath, "generate", 
			"--version", chromeVersion,
			"--output", clientHelloPath)
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Chrome 120 ClientHello generation should succeed: %s", string(output))
		
		// Now analyze the generated ClientHello with raven-linter
		cmd = exec.Command(ravenLinterPath, "check", clientHelloPath, "--format", "json")
		cmd.Dir = tempDir
		
		output, err = cmd.Output()
		// The generated ClientHello might not pass all compliance checks (expected)
		// but we should get a valid report
		
		var report checks.ComplianceReport
		jsonErr := json.Unmarshal(output, &report)
		require.NoError(t, jsonErr, "Should get valid JSON report for ClientHello analysis")
		
		assert.Equal(t, clientHelloPath, report.BinaryPath, "Report should reference ClientHello file")
		assert.Equal(t, 11, report.TotalChecks, "Should attempt all compliance checks")
		
		t.Logf("ClientHello compliance analysis:")
		t.Logf("  File: %s", clientHelloPath)
		t.Logf("  Chrome Version: %s", chromeVersion)
		t.Logf("  Compliance: %d/%d checks passed", report.PassedChecks, report.TotalChecks)
		
		// Log which checks passed/failed for ClientHello
		for _, result := range report.Results {
			status := "PASS"
			if result.Status != "pass" {
				status = "FAIL"
			}
			t.Logf("    %s: %s - %s", result.ID, status, result.Description)
		}
	})
}

// testParallelExecution tests running both tools in parallel
func testParallelExecution(t *testing.T, runner *testutils.TestRunner, ravenLinterPath, chromeUtlsGenPath, projectRoot string) {
	tempDir := runner.CreateTempDir("parallel-test-")
	validBinary := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/valid_elf_binary")
	
	t.Run("Concurrent operations", func(t *testing.T) {
		// Prepare output paths
		clientHelloPath := filepath.Join(tempDir, "parallel_clienthello.bin")
		sbomPath := filepath.Join(tempDir, "parallel_sbom.json")
		
		// Channel to collect results
		type result struct {
			name     string
			duration time.Duration
			err      error
			output   []byte
		}
		results := make(chan result, 2)
		
		// Start chrome-utls-gen in goroutine
		go func() {
			start := time.Now()
			cmd := exec.Command(chromeUtlsGenPath, "generate", "--output", clientHelloPath)
			cmd.Dir = tempDir
			output, err := cmd.CombinedOutput()
			results <- result{
				name:     "chrome-utls-gen",
				duration: time.Since(start),
				err:      err,
				output:   output,
			}
		}()
		
		// Start raven-linter in goroutine
		go func() {
			start := time.Now()
			cmd := exec.Command(ravenLinterPath, "check", validBinary,
				"--format", "json",
				"--sbom",
				"--sbom-output", sbomPath)
			cmd.Dir = tempDir
			output, err := cmd.Output()
			results <- result{
				name:     "raven-linter",
				duration: time.Since(start),
				err:      err,
				output:   output,
			}
		}()
		
		// Collect results with timeout
		var chromeResult, ravenResult result
		timeout := time.After(testutils.DefaultTimeouts.Long)
		
		for i := 0; i < 2; i++ {
			select {
			case res := <-results:
				if res.name == "chrome-utls-gen" {
					chromeResult = res
				} else {
					ravenResult = res
				}
			case <-timeout:
				t.Fatal("Parallel execution timed out")
			}
		}
		
		// Verify both operations succeeded
		require.NoError(t, chromeResult.err, "chrome-utls-gen should succeed: %s", string(chromeResult.output))
		require.NoError(t, ravenResult.err, "raven-linter should succeed: %s", string(ravenResult.output))
		
		// Verify outputs were created
		assert.FileExists(t, clientHelloPath, "ClientHello should be created")
		assert.FileExists(t, sbomPath, "SBOM should be created")
		
		// Verify raven-linter output
		var report checks.ComplianceReport
		err := json.Unmarshal(ravenResult.output, &report)
		require.NoError(t, err, "Compliance report should be valid JSON")
		
		t.Logf("Parallel execution completed:")
		t.Logf("  chrome-utls-gen: %v", chromeResult.duration)
		t.Logf("  raven-linter: %v", ravenResult.duration)
		t.Logf("  Total time saved by parallelization: %v", 
			(chromeResult.duration + ravenResult.duration) - maxDuration(chromeResult.duration, ravenResult.duration))
	})
}

// testCICDSimulation simulates a CI/CD pipeline using both tools
func testCICDSimulation(t *testing.T, runner *testutils.TestRunner, ravenLinterPath, chromeUtlsGenPath, projectRoot string) {
	tempDir := runner.CreateTempDir("cicd-simulation-")
	validBinary := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/valid_elf_binary")
	invalidBinary := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/invalid_elf_binary")
	
	t.Run("CI pipeline simulation", func(t *testing.T) {
		// Simulate a CI pipeline that:
		// 1. Generates TLS templates
		// 2. Runs compliance checks
		// 3. Generates SBOMs
		// 4. Produces artifacts
		
		artifactsDir := filepath.Join(tempDir, "artifacts")
		err := os.MkdirAll(artifactsDir, 0755)
		require.NoError(t, err, "Should create artifacts directory")
		
		// Step 1: Generate TLS templates (chrome-utls-gen update)
		templateCacheDir := filepath.Join(tempDir, "tls_templates")
		
		t.Logf("CI Step 1: Updating TLS templates...")
		cmd := exec.Command(chromeUtlsGenPath, "update", 
			"--cache", templateCacheDir,
			"--dry-run") // Use dry-run to avoid network dependencies
		cmd.Dir = tempDir
		
		testutils.WithTimeout(t, testutils.DefaultTimeouts.Medium, func() {
			output, err := cmd.CombinedOutput()
			if err != nil && strings.Contains(string(output), "network") {
				t.Skip("Skipping CI simulation due to network issues")
			}
			require.NoError(t, err, "TLS template update should succeed: %s", string(output))
		})
		
		// Step 2: Generate ClientHello for testing
		clientHelloPath := filepath.Join(artifactsDir, "clienthello.bin")
		
		t.Logf("CI Step 2: Generating ClientHello...")
		cmd = exec.Command(chromeUtlsGenPath, "generate", 
			"--output", clientHelloPath,
			"--cache", templateCacheDir)
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "ClientHello generation should succeed: %s", string(output))
		
		// Step 3: Run compliance checks on valid binary
		validReportPath := filepath.Join(artifactsDir, "valid_compliance_report.json")
		validSBOMPath := filepath.Join(artifactsDir, "valid_sbom.json")
		
		t.Logf("CI Step 3: Running compliance checks on valid binary...")
		cmd = exec.Command(ravenLinterPath, "check", validBinary,
			"--format", "json",
			"--sbom",
			"--sbom-output", validSBOMPath)
		cmd.Dir = tempDir
		
		output, err = cmd.Output()
		require.NoError(t, err, "Valid binary compliance check should succeed")
		
		err = os.WriteFile(validReportPath, output, 0644)
		require.NoError(t, err, "Should write valid compliance report")
		
		// Step 4: Run compliance checks on invalid binary (should fail)
		invalidReportPath := filepath.Join(artifactsDir, "invalid_compliance_report.json")
		
		t.Logf("CI Step 4: Running compliance checks on invalid binary...")
		cmd = exec.Command(ravenLinterPath, "check", invalidBinary, "--format", "json")
		cmd.Dir = tempDir
		
		output, err = cmd.Output()
		// Should fail but still produce report
		var exitError *exec.ExitError
		if err != nil {
			require.ErrorAs(t, err, &exitError, "Should be an exit error")
			assert.Equal(t, 1, exitError.ExitCode(), "Should exit with code 1")
		}
		
		err = os.WriteFile(invalidReportPath, output, 0644)
		require.NoError(t, err, "Should write invalid compliance report")
		
		// Step 5: Verify all artifacts were created
		expectedArtifacts := []string{
			clientHelloPath,
			validReportPath,
			validSBOMPath,
			invalidReportPath,
		}
		
		for _, artifact := range expectedArtifacts {
			assert.FileExists(t, artifact, "CI artifact should exist: %s", artifact)
		}
		
		// Step 6: Validate artifact contents
		var validReport, invalidReport checks.ComplianceReport
		
		validReportData, err := os.ReadFile(validReportPath)
		require.NoError(t, err, "Should read valid report")
		err = json.Unmarshal(validReportData, &validReport)
		require.NoError(t, err, "Valid report should be valid JSON")
		
		invalidReportData, err := os.ReadFile(invalidReportPath)
		require.NoError(t, err, "Should read invalid report")
		err = json.Unmarshal(invalidReportData, &invalidReport)
		require.NoError(t, err, "Invalid report should be valid JSON")
		
		// Verify CI results
		assert.Equal(t, validReport.TotalChecks, validReport.PassedChecks, 
			"Valid binary should pass all checks")
		assert.Greater(t, invalidReport.FailedChecks, 0, 
			"Invalid binary should fail some checks")
		
		t.Logf("CI Pipeline completed successfully:")
		t.Logf("  Artifacts created: %d", len(expectedArtifacts))
		t.Logf("  Valid binary: %d/%d checks passed", validReport.PassedChecks, validReport.TotalChecks)
		t.Logf("  Invalid binary: %d/%d checks passed", invalidReport.PassedChecks, invalidReport.TotalChecks)
		
		// Step 7: Generate CI summary
		summaryPath := filepath.Join(artifactsDir, "ci_summary.json")
		summary := map[string]interface{}{
			"pipeline_status": "completed",
			"artifacts_count": len(expectedArtifacts),
			"valid_binary_compliance": map[string]int{
				"total":  validReport.TotalChecks,
				"passed": validReport.PassedChecks,
				"failed": validReport.FailedChecks,
			},
			"invalid_binary_compliance": map[string]int{
				"total":  invalidReport.TotalChecks,
				"passed": invalidReport.PassedChecks,
				"failed": invalidReport.FailedChecks,
			},
			"artifacts": expectedArtifacts,
		}
		
		summaryData, err := json.MarshalIndent(summary, "", "  ")
		require.NoError(t, err, "Should marshal CI summary")
		
		err = os.WriteFile(summaryPath, summaryData, 0644)
		require.NoError(t, err, "Should write CI summary")
		
		t.Logf("CI Summary written to: %s", summaryPath)
	})
}

// testPerformanceComparison tests performance characteristics of both tools
func testPerformanceComparison(t *testing.T, runner *testutils.TestRunner, ravenLinterPath, chromeUtlsGenPath, projectRoot string) {
	tempDir := runner.CreateTempDir("performance-test-")
	validBinary := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/valid_elf_binary")
	
	t.Run("Performance benchmarking", func(t *testing.T) {
		// Benchmark chrome-utls-gen generate
		clientHelloPath := filepath.Join(tempDir, "perf_clienthello.bin")
		
		start := time.Now()
		cmd := exec.Command(chromeUtlsGenPath, "generate", "--output", clientHelloPath)
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		chromeGenDuration := time.Since(start)
		require.NoError(t, err, "Chrome generation should succeed: %s", string(output))
		
		// Benchmark raven-linter check
		start = time.Now()
		cmd = exec.Command(ravenLinterPath, "check", validBinary, "--format", "json")
		cmd.Dir = tempDir
		
		output, err = cmd.Output()
		ravenCheckDuration := time.Since(start)
		require.NoError(t, err, "Raven check should succeed")
		
		// Benchmark raven-linter with SBOM
		sbomPath := filepath.Join(tempDir, "perf_sbom.json")
		start = time.Now()
		cmd = exec.Command(ravenLinterPath, "check", validBinary, 
			"--format", "json", 
			"--sbom", 
			"--sbom-output", sbomPath)
		cmd.Dir = tempDir
		
		output, err = cmd.Output()
		ravenSBOMDuration := time.Since(start)
		require.NoError(t, err, "Raven check with SBOM should succeed")
		
		// Log performance results
		t.Logf("Performance Benchmarks:")
		t.Logf("  chrome-utls-gen generate: %v", chromeGenDuration)
		t.Logf("  raven-linter check: %v", ravenCheckDuration)
		t.Logf("  raven-linter check + SBOM: %v", ravenSBOMDuration)
		t.Logf("  SBOM overhead: %v", ravenSBOMDuration-ravenCheckDuration)
		
		// Performance assertions (reasonable bounds)
		assert.Less(t, chromeGenDuration, 30*time.Second, "Chrome generation should be fast")
		assert.Less(t, ravenCheckDuration, 60*time.Second, "Raven check should be reasonable")
		assert.Less(t, ravenSBOMDuration, 90*time.Second, "Raven check with SBOM should be reasonable")
		
		// SBOM overhead should be reasonable
		sbomOverhead := ravenSBOMDuration - ravenCheckDuration
		assert.Less(t, sbomOverhead, 30*time.Second, "SBOM generation overhead should be reasonable")
	})
	
	t.Run("Memory usage estimation", func(t *testing.T) {
		// This is a basic test - in production you'd use more sophisticated profiling
		
		// Test with verbose output to get more detailed logging
		cmd := exec.Command(ravenLinterPath, "check", validBinary, "--format", "json", "--verbose")
		cmd.Dir = tempDir
		
		start := time.Now()
		output, err := cmd.CombinedOutput()
		duration := time.Since(start)
		
		require.NoError(t, err, "Verbose check should succeed")
		
		// Basic metrics
		outputSize := len(output)
		
		t.Logf("Resource Usage Estimation:")
		t.Logf("  Execution time: %v", duration)
		t.Logf("  Output size: %d bytes", outputSize)
		t.Logf("  Average throughput: %.2f KB/s", float64(outputSize)/duration.Seconds()/1024)
		
		// Basic assertions
		assert.Greater(t, outputSize, 1000, "Verbose output should be substantial")
		assert.Less(t, duration, 2*time.Minute, "Should complete in reasonable time")
	})
}

// Helper function to get the maximum of two durations
func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}