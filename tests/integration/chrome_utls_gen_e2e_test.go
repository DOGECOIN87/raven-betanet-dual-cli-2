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
)

// TestChromeUtlsGenE2E tests the complete chrome-utls-gen CLI workflow
func TestChromeUtlsGenE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping end-to-end tests in short mode")
	}

	runner := testutils.NewTestRunner(t)
	projectRoot := getProjectRoot(t)
	
	// Build the chrome-utls-gen binary for testing
	binaryPath := buildChromeUtlsGen(t, runner)
	
	t.Run("Generate command workflow", func(t *testing.T) {
		testGenerateWorkflow(t, runner, binaryPath, projectRoot)
	})
	
	t.Run("JA3 test command workflow", func(t *testing.T) {
		testJA3TestWorkflow(t, runner, binaryPath, projectRoot)
	})
	
	t.Run("Update command workflow", func(t *testing.T) {
		testUpdateWorkflow(t, runner, binaryPath, projectRoot)
	})
	
	t.Run("Error scenarios", func(t *testing.T) {
		testChromeUtlsGenErrorScenarios(t, runner, binaryPath, projectRoot)
	})
	
	t.Run("Template caching", func(t *testing.T) {
		testTemplateCaching(t, runner, binaryPath, projectRoot)
	})
}

// buildChromeUtlsGen builds the chrome-utls-gen binary for testing
func buildChromeUtlsGen(t *testing.T, runner *testutils.TestRunner) string {
	tempDir := runner.CreateTempDir("chrome-utls-gen-build-")
	binaryPath := filepath.Join(tempDir, "chrome-utls-gen")
	
	// Build the binary
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/chrome-utls-gen")
	cmd.Dir = getProjectRoot(t)
	
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to build chrome-utls-gen: %s", string(output))
	
	// Verify binary exists and is executable
	assert.FileExists(t, binaryPath)
	
	// Test that binary runs
	cmd = exec.Command(binaryPath, "--version")
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to run chrome-utls-gen --version: %s", string(output))
	
	return binaryPath
}

// testGenerateWorkflow tests the generate command functionality
func testGenerateWorkflow(t *testing.T, runner *testutils.TestRunner, binaryPath, projectRoot string) {
	tempDir := runner.CreateTempDir("generate-test-")
	
	t.Run("Default ClientHello generation", func(t *testing.T) {
		outputFile := filepath.Join(tempDir, "clienthello.bin")
		
		// Run chrome-utls-gen generate
		cmd := exec.Command(binaryPath, "generate", "--output", outputFile)
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Generate command should succeed: %s", string(output))
		
		// Verify output file was created
		assert.FileExists(t, outputFile, "ClientHello binary should be created")
		
		// Verify file has reasonable size (ClientHello should be a few hundred bytes)
		fileInfo, err := os.Stat(outputFile)
		require.NoError(t, err, "Should be able to stat output file")
		assert.Greater(t, fileInfo.Size(), int64(100), "ClientHello should be at least 100 bytes")
		assert.Less(t, fileInfo.Size(), int64(2048), "ClientHello should be less than 2KB")
		
		// Verify output contains expected information
		outputStr := string(output)
		assert.Contains(t, outputStr, "Generated ClientHello for Chrome", "Should show generation success")
		assert.Contains(t, outputStr, "JA3 Hash:", "Should show JA3 hash")
		assert.Contains(t, outputStr, "JA3 String:", "Should show JA3 string")
		assert.Contains(t, outputStr, outputFile, "Should show output file path")
	})
	
	t.Run("Specific Chrome version generation", func(t *testing.T) {
		outputFile := filepath.Join(tempDir, "chrome120.bin")
		
		// Run chrome-utls-gen generate with specific version
		cmd := exec.Command(binaryPath, "generate", 
			"--version", "120.0.6099.109", 
			"--output", outputFile)
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Generate with specific version should succeed: %s", string(output))
		
		// Verify output file was created
		assert.FileExists(t, outputFile, "Chrome 120 ClientHello should be created")
		
		// Verify output mentions the specific version
		outputStr := string(output)
		assert.Contains(t, outputStr, "120.0.6099.109", "Should mention the specific Chrome version")
	})
	
	t.Run("Template caching", func(t *testing.T) {
		outputFile := filepath.Join(tempDir, "cached_clienthello.bin")
		cacheDir := filepath.Join(tempDir, "templates")
		
		// Run chrome-utls-gen generate with caching
		cmd := exec.Command(binaryPath, "generate", 
			"--output", outputFile,
			"--cache", cacheDir)
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Generate with caching should succeed: %s", string(output))
		
		// Verify output file was created
		assert.FileExists(t, outputFile, "ClientHello with caching should be created")
		
		// Verify cache directory was created
		assert.DirExists(t, cacheDir, "Cache directory should be created")
		
		// Verify cache contains template files
		cacheFiles, err := os.ReadDir(cacheDir)
		require.NoError(t, err, "Should be able to read cache directory")
		assert.Greater(t, len(cacheFiles), 0, "Cache should contain template files")
		
		// Verify at least one cache file is a JSON template
		foundJSONTemplate := false
		for _, file := range cacheFiles {
			if strings.HasSuffix(file.Name(), ".json") && strings.HasPrefix(file.Name(), "chrome_") {
				foundJSONTemplate = true
				
				// Verify the JSON template is valid
				templatePath := filepath.Join(cacheDir, file.Name())
				templateData, readErr := os.ReadFile(templatePath)
				require.NoError(t, readErr, "Should be able to read template file")
				
				var templateJSON map[string]interface{}
				jsonErr := json.Unmarshal(templateData, &templateJSON)
				require.NoError(t, jsonErr, "Template should be valid JSON")
				
				// Verify template structure
				assert.NotEmpty(t, templateJSON["version"], "Template should have version")
				assert.NotEmpty(t, templateJSON["ja3Hash"], "Template should have JA3 hash")
				assert.NotEmpty(t, templateJSON["ja3String"], "Template should have JA3 string")
				assert.NotEmpty(t, templateJSON["bytes"], "Template should have bytes")
				break
			}
		}
		assert.True(t, foundJSONTemplate, "Should find at least one JSON template in cache")
	})
	
	t.Run("Verbose output", func(t *testing.T) {
		outputFile := filepath.Join(tempDir, "verbose_clienthello.bin")
		
		// Run chrome-utls-gen generate with verbose output
		cmd := exec.Command(binaryPath, "generate", 
			"--output", outputFile,
			"--verbose")
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Generate with verbose should succeed: %s", string(output))
		
		// Verbose output should contain debug information
		outputStr := string(output)
		assert.Contains(t, outputStr, "Starting ClientHello generation", "Should show verbose logging")
	})
}

// testJA3TestWorkflow tests the ja3-test command functionality
func testJA3TestWorkflow(t *testing.T, runner *testutils.TestRunner, binaryPath, projectRoot string) {
	tempDir := runner.CreateTempDir("ja3-test-")
	
	t.Run("JA3 test against public server", func(t *testing.T) {
		// Use a reliable public server for testing
		target := "example.com:443"
		
		// Run chrome-utls-gen ja3-test
		cmd := exec.Command(binaryPath, "ja3-test", "--target", target, "--timeout", "30s")
		cmd.Dir = tempDir
		
		// Use timeout wrapper for network operations
		testutils.WithTimeout(t, testutils.DefaultTimeouts.Medium, func() {
			output, err := cmd.CombinedOutput()
			
			outputStr := string(output)
			
			if err != nil {
				// Network tests can fail due to connectivity issues
				// Log the error but don't fail the test if it's network-related
				t.Logf("JA3 test failed (may be network-related): %v", err)
				t.Logf("Output: %s", outputStr)
				
				// If it's a clear network error, skip the test
				if strings.Contains(outputStr, "connection") || 
				   strings.Contains(outputStr, "timeout") ||
				   strings.Contains(outputStr, "network") {
					t.Skip("Skipping JA3 test due to network connectivity issues")
				}
				
				// Otherwise, it might be a legitimate test failure
				require.NoError(t, err, "JA3 test should succeed: %s", outputStr)
			}
			
			// Verify output contains expected elements
			assert.Contains(t, outputStr, "JA3 Fingerprint Test Results", "Should show test results header")
			assert.Contains(t, outputStr, target, "Should show target server")
			assert.Contains(t, outputStr, "Chrome Version:", "Should show Chrome version")
			
			// Should show either success or failure status
			hasConnectionStatus := strings.Contains(outputStr, "Connection Status: SUCCESS") ||
								  strings.Contains(outputStr, "Connection Status: FAILED")
			assert.True(t, hasConnectionStatus, "Should show connection status")
			
			// If successful, should show JA3 information
			if strings.Contains(outputStr, "SUCCESS") {
				assert.Contains(t, outputStr, "JA3 String:", "Should show JA3 string on success")
				assert.Contains(t, outputStr, "JA3 Hash:", "Should show JA3 hash on success")
				assert.Contains(t, outputStr, "Test Summary:", "Should show test summary")
			}
		})
	})
	
	t.Run("JA3 test with specific Chrome version", func(t *testing.T) {
		target := "example.com:443"
		chromeVersion := "120.0.6099.109"
		
		cmd := exec.Command(binaryPath, "ja3-test", 
			"--target", target,
			"--version", chromeVersion,
			"--timeout", "30s")
		cmd.Dir = tempDir
		
		testutils.WithTimeout(t, testutils.DefaultTimeouts.Medium, func() {
			output, err := cmd.CombinedOutput()
			outputStr := string(output)
			
			if err != nil {
				// Handle network-related failures gracefully
				if strings.Contains(outputStr, "connection") || 
				   strings.Contains(outputStr, "timeout") ||
				   strings.Contains(outputStr, "network") {
					t.Skip("Skipping JA3 test with specific version due to network issues")
				}
				require.NoError(t, err, "JA3 test with specific version should succeed: %s", outputStr)
			}
			
			// Should mention the specific Chrome version
			assert.Contains(t, outputStr, chromeVersion, "Should use specified Chrome version")
		})
	})
	
	t.Run("JA3 test with expected hash verification", func(t *testing.T) {
		target := "example.com:443"
		// Use a known JA3 hash for Chrome (this is an example - in real tests you'd use actual known hashes)
		expectedJA3 := "cd08e31494f9531f560d64c695473da9"
		
		cmd := exec.Command(binaryPath, "ja3-test", 
			"--target", target,
			"--expected", expectedJA3,
			"--timeout", "30s")
		cmd.Dir = tempDir
		
		testutils.WithTimeout(t, testutils.DefaultTimeouts.Medium, func() {
			output, err := cmd.CombinedOutput()
			outputStr := string(output)
			
			// This test might fail if the expected hash doesn't match
			// That's okay - we're testing the verification functionality
			if err != nil && (strings.Contains(outputStr, "connection") || 
							  strings.Contains(outputStr, "timeout") ||
							  strings.Contains(outputStr, "network")) {
				t.Skip("Skipping JA3 verification test due to network issues")
			}
			
			// Should show verification section regardless of success/failure
			assert.Contains(t, outputStr, "JA3 Verification:", "Should show JA3 verification section")
			assert.Contains(t, outputStr, expectedJA3, "Should show expected JA3 hash")
			
			// Should show either MATCH or MISMATCH
			hasVerificationResult := strings.Contains(outputStr, "MATCH") || 
									strings.Contains(outputStr, "MISMATCH")
			assert.True(t, hasVerificationResult, "Should show verification result")
		})
	})
	
	t.Run("JA3 test with short timeout", func(t *testing.T) {
		target := "example.com:443"
		
		cmd := exec.Command(binaryPath, "ja3-test", 
			"--target", target,
			"--timeout", "1s") // Very short timeout
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		outputStr := string(output)
		
		// With a 1-second timeout, this will likely fail
		if err != nil {
			// Should handle timeout gracefully
			assert.Contains(t, outputStr, "timeout", "Should mention timeout in error")
		}
		
		// Should still produce structured output
		assert.Contains(t, outputStr, "JA3 Fingerprint Test Results", "Should show results header even on timeout")
	})
}

// testUpdateWorkflow tests the update command functionality
func testUpdateWorkflow(t *testing.T, runner *testutils.TestRunner, binaryPath, projectRoot string) {
	tempDir := runner.CreateTempDir("update-test-")
	cacheDir := filepath.Join(tempDir, "templates")
	
	t.Run("Update dry run", func(t *testing.T) {
		// Run chrome-utls-gen update with dry run
		cmd := exec.Command(binaryPath, "update", 
			"--cache", cacheDir,
			"--dry-run")
		cmd.Dir = tempDir
		
		// Network operation - use timeout
		testutils.WithTimeout(t, testutils.DefaultTimeouts.Long, func() {
			output, err := cmd.CombinedOutput()
			outputStr := string(output)
			
			if err != nil {
				// Handle network-related failures
				if strings.Contains(outputStr, "failed to fetch") ||
				   strings.Contains(outputStr, "network") ||
				   strings.Contains(outputStr, "timeout") {
					t.Skip("Skipping update dry run test due to network issues")
				}
				require.NoError(t, err, "Update dry run should succeed: %s", outputStr)
			}
			
			// Verify dry run output
			assert.Contains(t, outputStr, "Chrome Version Update Status", "Should show update status")
			assert.Contains(t, outputStr, "Dry Run: true", "Should indicate dry run mode")
			assert.Contains(t, outputStr, "DRY RUN", "Should show dry run results")
			
			// Should not create actual files in dry run
			if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
				// Cache directory should not be created in dry run
				t.Logf("Cache directory correctly not created in dry run")
			}
		})
	})
	
	t.Run("Actual update", func(t *testing.T) {
		// Run chrome-utls-gen update
		cmd := exec.Command(binaryPath, "update", 
			"--cache", cacheDir)
		cmd.Dir = tempDir
		
		testutils.WithTimeout(t, testutils.DefaultTimeouts.Long, func() {
			output, err := cmd.CombinedOutput()
			outputStr := string(output)
			
			if err != nil {
				// Handle network-related failures
				if strings.Contains(outputStr, "failed to fetch") ||
				   strings.Contains(outputStr, "network") ||
				   strings.Contains(outputStr, "timeout") {
					t.Skip("Skipping actual update test due to network issues")
				}
				require.NoError(t, err, "Update should succeed: %s", outputStr)
			}
			
			// Verify update output
			assert.Contains(t, outputStr, "Chrome Version Update Status", "Should show update status")
			assert.Contains(t, outputStr, "Update process completed", "Should show completion")
			
			// Verify cache directory was created
			assert.DirExists(t, cacheDir, "Cache directory should be created")
			
			// Verify templates were generated
			cacheFiles, readErr := os.ReadDir(cacheDir)
			require.NoError(t, readErr, "Should be able to read cache directory")
			
			// Should have at least some template files
			jsonTemplates := 0
			for _, file := range cacheFiles {
				if strings.HasSuffix(file.Name(), ".json") && strings.HasPrefix(file.Name(), "chrome_") {
					jsonTemplates++
				}
			}
			assert.Greater(t, jsonTemplates, 0, "Should have generated at least one template")
		})
	})
	
	t.Run("Force update", func(t *testing.T) {
		forceCache := filepath.Join(tempDir, "force_templates")
		
		// Run chrome-utls-gen update with force
		cmd := exec.Command(binaryPath, "update", 
			"--cache", forceCache,
			"--force")
		cmd.Dir = tempDir
		
		testutils.WithTimeout(t, testutils.DefaultTimeouts.Long, func() {
			output, err := cmd.CombinedOutput()
			outputStr := string(output)
			
			if err != nil {
				if strings.Contains(outputStr, "failed to fetch") ||
				   strings.Contains(outputStr, "network") ||
				   strings.Contains(outputStr, "timeout") {
					t.Skip("Skipping force update test due to network issues")
				}
				require.NoError(t, err, "Force update should succeed: %s", outputStr)
			}
			
			// Verify force update output
			assert.Contains(t, outputStr, "Force Update: true", "Should indicate force update")
			assert.Contains(t, outputStr, "Update process completed", "Should complete successfully")
		})
	})
	
	t.Run("Update with existing cache", func(t *testing.T) {
		existingCache := filepath.Join(tempDir, "existing_templates")
		
		// Create existing cache directory with a dummy file
		err := os.MkdirAll(existingCache, 0755)
		require.NoError(t, err, "Should create existing cache directory")
		
		dummyTemplate := filepath.Join(existingCache, "chrome_120.0.6099.109.json")
		dummyData := `{"version":"120.0.6099.109","ja3Hash":"dummy","ja3String":"dummy","bytes":"dummy"}`
		err = os.WriteFile(dummyTemplate, []byte(dummyData), 0644)
		require.NoError(t, err, "Should create dummy template")
		
		// Run update
		cmd := exec.Command(binaryPath, "update", 
			"--cache", existingCache)
		cmd.Dir = tempDir
		
		testutils.WithTimeout(t, testutils.DefaultTimeouts.Long, func() {
			output, err := cmd.CombinedOutput()
			outputStr := string(output)
			
			if err != nil {
				if strings.Contains(outputStr, "failed to fetch") ||
				   strings.Contains(outputStr, "network") ||
				   strings.Contains(outputStr, "timeout") {
					t.Skip("Skipping existing cache update test due to network issues")
				}
				require.NoError(t, err, "Update with existing cache should succeed: %s", outputStr)
			}
			
			// Should handle existing cache gracefully
			assert.Contains(t, outputStr, "Update process completed", "Should complete with existing cache")
		})
	})
}

// testChromeUtlsGenErrorScenarios tests various error conditions
func testChromeUtlsGenErrorScenarios(t *testing.T, runner *testutils.TestRunner, binaryPath, projectRoot string) {
	tempDir := runner.CreateTempDir("error-test-")
	
	t.Run("Generate with invalid output path", func(t *testing.T) {
		// Try to write to a directory that doesn't exist and can't be created
		invalidPath := "/root/nonexistent/clienthello.bin"
		
		cmd := exec.Command(binaryPath, "generate", "--output", invalidPath)
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.Error(t, err, "Should fail with invalid output path")
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "Error", "Should contain error message")
	})
	
	t.Run("Generate with invalid Chrome version", func(t *testing.T) {
		outputFile := filepath.Join(tempDir, "invalid_version.bin")
		
		cmd := exec.Command(binaryPath, "generate", 
			"--version", "invalid.version.format",
			"--output", outputFile)
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.Error(t, err, "Should fail with invalid Chrome version")
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "invalid Chrome version", "Should mention invalid version")
	})
	
	t.Run("JA3 test without target", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "ja3-test")
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.Error(t, err, "Should fail without target")
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "required", "Should mention required target")
	})
	
	t.Run("JA3 test with invalid target", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "ja3-test", "--target", "invalid-target-format")
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.Error(t, err, "Should fail with invalid target")
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "Error", "Should contain error message")
	})
	
	t.Run("JA3 test with invalid timeout", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "ja3-test", 
			"--target", "example.com:443",
			"--timeout", "invalid-timeout")
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.Error(t, err, "Should fail with invalid timeout")
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "invalid timeout", "Should mention invalid timeout")
	})
	
	t.Run("Help output", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "--help")
		cmd.Dir = tempDir
		
		output, err := cmd.Output()
		require.NoError(t, err, "Help should work")
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "chrome-utls-gen", "Help should contain tool name")
		assert.Contains(t, outputStr, "generate", "Help should contain generate command")
		assert.Contains(t, outputStr, "ja3-test", "Help should contain ja3-test command")
		assert.Contains(t, outputStr, "update", "Help should contain update command")
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
	
	t.Run("Invalid command", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "invalid-command")
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.Error(t, err, "Should fail with invalid command")
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "Error", "Should contain error message")
	})
	
	t.Run("Update with invalid cache path", func(t *testing.T) {
		// Try to use a cache path that can't be created
		invalidCache := "/root/nonexistent/cache"
		
		cmd := exec.Command(binaryPath, "update", "--cache", invalidCache, "--dry-run")
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		
		if err != nil {
			outputStr := string(output)
			// Should handle invalid cache path gracefully
			assert.Contains(t, outputStr, "Error", "Should contain error message for invalid cache path")
		}
	})
}

// testTemplateCaching tests template caching functionality
func testTemplateCaching(t *testing.T, runner *testutils.TestRunner, binaryPath, projectRoot string) {
	tempDir := runner.CreateTempDir("caching-test-")
	cacheDir := filepath.Join(tempDir, "template_cache")
	
	t.Run("Template cache creation", func(t *testing.T) {
		outputFile := filepath.Join(tempDir, "cached_test.bin")
		
		// Generate with caching
		cmd := exec.Command(binaryPath, "generate", 
			"--output", outputFile,
			"--cache", cacheDir)
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Generate with caching should succeed: %s", string(output))
		
		// Verify cache directory structure
		assert.DirExists(t, cacheDir, "Cache directory should be created")
		
		// Verify cache contains valid templates
		cacheFiles, err := os.ReadDir(cacheDir)
		require.NoError(t, err, "Should be able to read cache directory")
		
		foundValidTemplate := false
		for _, file := range cacheFiles {
			if strings.HasSuffix(file.Name(), ".json") {
				templatePath := filepath.Join(cacheDir, file.Name())
				templateData, readErr := os.ReadFile(templatePath)
				require.NoError(t, readErr, "Should be able to read template file")
				
				var template map[string]interface{}
				jsonErr := json.Unmarshal(templateData, &template)
				require.NoError(t, jsonErr, "Template should be valid JSON")
				
				// Verify required fields
				requiredFields := []string{"version", "ja3Hash", "ja3String", "bytes", "generatedAt"}
				for _, field := range requiredFields {
					assert.Contains(t, template, field, "Template should contain field: %s", field)
					assert.NotEmpty(t, template[field], "Template field should not be empty: %s", field)
				}
				
				foundValidTemplate = true
				break
			}
		}
		assert.True(t, foundValidTemplate, "Should find at least one valid template in cache")
	})
	
	t.Run("Template cache reuse", func(t *testing.T) {
		// Generate first time (should create cache)
		outputFile1 := filepath.Join(tempDir, "reuse_test1.bin")
		cmd1 := exec.Command(binaryPath, "generate", 
			"--output", outputFile1,
			"--cache", cacheDir)
		cmd1.Dir = tempDir
		
		start1 := time.Now()
		output1, err := cmd1.CombinedOutput()
		duration1 := time.Since(start1)
		require.NoError(t, err, "First generate should succeed: %s", string(output1))
		
		// Generate second time (should potentially reuse cache)
		outputFile2 := filepath.Join(tempDir, "reuse_test2.bin")
		cmd2 := exec.Command(binaryPath, "generate", 
			"--output", outputFile2,
			"--cache", cacheDir)
		cmd2.Dir = tempDir
		
		start2 := time.Now()
		output2, err := cmd2.CombinedOutput()
		duration2 := time.Since(start2)
		require.NoError(t, err, "Second generate should succeed: %s", string(output2))
		
		// Both files should exist and be similar
		assert.FileExists(t, outputFile1, "First output file should exist")
		assert.FileExists(t, outputFile2, "Second output file should exist")
		
		// Files should have similar sizes (same Chrome version)
		info1, err := os.Stat(outputFile1)
		require.NoError(t, err, "Should stat first file")
		info2, err := os.Stat(outputFile2)
		require.NoError(t, err, "Should stat second file")
		
		sizeDiff := info1.Size() - info2.Size()
		if sizeDiff < 0 {
			sizeDiff = -sizeDiff
		}
		assert.Less(t, sizeDiff, int64(100), "Generated files should have similar sizes")
		
		t.Logf("First generation took: %v, Second generation took: %v", duration1, duration2)
	})
	
	t.Run("Cache with different Chrome versions", func(t *testing.T) {
		versionCacheDir := filepath.Join(tempDir, "version_cache")
		
		// Generate for Chrome 120
		output120 := filepath.Join(tempDir, "chrome120_cached.bin")
		cmd120 := exec.Command(binaryPath, "generate", 
			"--version", "120.0.6099.109",
			"--output", output120,
			"--cache", versionCacheDir)
		cmd120.Dir = tempDir
		
		output, err := cmd120.CombinedOutput()
		require.NoError(t, err, "Chrome 120 generate should succeed: %s", string(output))
		
		// Generate for Chrome 119 (if supported)
		output119 := filepath.Join(tempDir, "chrome119_cached.bin")
		cmd119 := exec.Command(binaryPath, "generate", 
			"--version", "119.0.6045.105",
			"--output", output119,
			"--cache", versionCacheDir)
		cmd119.Dir = tempDir
		
		output, err = cmd119.CombinedOutput()
		if err != nil {
			// Some versions might not be supported, that's okay
			t.Logf("Chrome 119 generation failed (may not be supported): %v", err)
		} else {
			// If successful, verify both files exist
			assert.FileExists(t, output120, "Chrome 120 file should exist")
			assert.FileExists(t, output119, "Chrome 119 file should exist")
			
			// Verify cache contains templates for different versions
			cacheFiles, readErr := os.ReadDir(versionCacheDir)
			require.NoError(t, readErr, "Should read version cache directory")
			
			chrome120Template := false
			chrome119Template := false
			for _, file := range cacheFiles {
				if strings.Contains(file.Name(), "120.0.6099.109") {
					chrome120Template = true
				}
				if strings.Contains(file.Name(), "119.0.6045.105") {
					chrome119Template = true
				}
			}
			assert.True(t, chrome120Template, "Should have Chrome 120 template in cache")
			assert.True(t, chrome119Template, "Should have Chrome 119 template in cache")
		}
	})
}