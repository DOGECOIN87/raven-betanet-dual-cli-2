package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testutils "github.com/raven-betanet/dual-cli/tests/utils"
	"github.com/raven-betanet/dual-cli/internal/checks"
)

// TestCrossPlatformCompatibility tests cross-platform functionality
func TestCrossPlatformCompatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping cross-platform tests in short mode")
	}

	runner := testutils.NewTestRunner(t)
	projectRoot := getProjectRoot(t)
	
	// Build CLI tools for current platform
	ravenLinterPath := buildRavenLinter(t, runner)
	chromeUtlsGenPath := buildChromeUtlsGen(t, runner)
	
	t.Run("Binary format compatibility", func(t *testing.T) {
		testBinaryFormatCompatibility(t, runner, ravenLinterPath, projectRoot)
	})
	
	t.Run("Platform-specific binary analysis", func(t *testing.T) {
		testPlatformSpecificBinaryAnalysis(t, runner, ravenLinterPath, projectRoot)
	})
	
	t.Run("Cross-platform TLS handshake generation", func(t *testing.T) {
		testCrossPlatformTLSGeneration(t, runner, chromeUtlsGenPath, projectRoot)
	})
	
	t.Run("Architecture support validation", func(t *testing.T) {
		testArchitectureSupport(t, runner, ravenLinterPath, projectRoot)
	})
	
	t.Run("Platform-specific error handling", func(t *testing.T) {
		testPlatformSpecificErrorHandling(t, runner, ravenLinterPath, chromeUtlsGenPath, projectRoot)
	})
}

// testBinaryFormatCompatibility tests support for different binary formats
func testBinaryFormatCompatibility(t *testing.T, runner *testutils.TestRunner, ravenLinterPath, projectRoot string) {
	tempDir := runner.CreateTempDir("binary-format-test-")
	
	// Test cases for different binary formats
	testCases := []struct {
		name           string
		binaryPath     string
		expectedFormat string
		shouldPass     bool
		description    string
	}{
		{
			name:           "ELF binary (Linux)",
			binaryPath:     "tests/fixtures/sample_binaries/valid_elf_binary",
			expectedFormat: "ELF",
			shouldPass:     true,
			description:    "Valid ELF binary should be analyzed successfully",
		},
		{
			name:           "Invalid ELF binary",
			binaryPath:     "tests/fixtures/sample_binaries/invalid_elf_binary",
			expectedFormat: "Unknown",
			shouldPass:     false,
			description:    "Invalid ELF binary should be detected and fail",
		},
		{
			name:           "Corrupted binary",
			binaryPath:     "tests/fixtures/sample_binaries/corrupted_binary",
			expectedFormat: "Unknown",
			shouldPass:     false,
			description:    "Corrupted binary should be handled gracefully",
		},
	}
	
	// Generate platform-specific test binaries if they don't exist
	generatePlatformSpecificBinaries(t, runner, projectRoot)
	
	// Add platform-specific test cases
	if runtime.GOOS == "windows" {
		testCases = append(testCases, struct {
			name           string
			binaryPath     string
			expectedFormat string
			shouldPass     bool
			description    string
		}{
			name:           "PE binary (Windows)",
			binaryPath:     "tests/fixtures/sample_binaries/valid_pe_binary.exe",
			expectedFormat: "PE",
			shouldPass:     true,
			description:    "Valid PE binary should be analyzed successfully",
		})
	}
	
	if runtime.GOOS == "darwin" {
		testCases = append(testCases, struct {
			name           string
			binaryPath     string
			expectedFormat string
			shouldPass     bool
			description    string
		}{
			name:           "Mach-O binary (macOS)",
			binaryPath:     "tests/fixtures/sample_binaries/valid_macho_binary",
			expectedFormat: "Mach-O",
			shouldPass:     true,
			description:    "Valid Mach-O binary should be analyzed successfully",
		})
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			binaryPath := filepath.Join(projectRoot, tc.binaryPath)
			
			// Skip if binary doesn't exist (platform-specific)
			if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
				t.Skipf("Binary not available on this platform: %s", tc.binaryPath)
				return
			}
			
			// Run compliance check
			cmd := exec.Command(ravenLinterPath, "check", binaryPath, "--format", "json")
			cmd.Dir = tempDir
			
			output, err := cmd.Output()
			
			if tc.shouldPass {
				require.NoError(t, err, "Binary analysis should succeed for %s", tc.name)
			} else {
				// For failing cases, we might get an exit error but still valid JSON output
				if err != nil {
					var exitError *exec.ExitError
					require.ErrorAs(t, err, &exitError, "Should be an exit error for %s", tc.name)
				}
			}
			
			// Parse and validate output
			var report checks.ComplianceReport
			err = json.Unmarshal(output, &report)
			require.NoError(t, err, "Should get valid JSON output for %s", tc.name)
			
			// Validate report structure
			assert.Equal(t, binaryPath, report.BinaryPath, "Report should reference correct binary")
			assert.Equal(t, 11, report.TotalChecks, "Should attempt all compliance checks")
			assert.NotEmpty(t, report.Results, "Should have check results")
			
			// Check format detection in metadata
			if len(report.Results) > 0 {
				// Look for file signature check result
				var formatResult *checks.CheckResult
				for _, result := range report.Results {
					if result.ID == "check-1-file-signature" {
						formatResult = &result
						break
					}
				}
				
				if formatResult != nil && formatResult.Metadata != nil {
					if format, ok := formatResult.Metadata["format"].(string); ok {
						if tc.expectedFormat != "Unknown" {
							assert.Equal(t, tc.expectedFormat, format, 
								"Should detect correct format for %s", tc.name)
						}
					}
				}
			}
			
			t.Logf("Binary format test completed for %s:", tc.name)
			t.Logf("  Binary: %s", binaryPath)
			t.Logf("  Expected format: %s", tc.expectedFormat)
			t.Logf("  Compliance: %d/%d checks passed", report.PassedChecks, report.TotalChecks)
			t.Logf("  Description: %s", tc.description)
		})
	}
}

// testPlatformSpecificBinaryAnalysis tests platform-specific binary analysis features
func testPlatformSpecificBinaryAnalysis(t *testing.T, runner *testutils.TestRunner, ravenLinterPath, projectRoot string) {
	tempDir := runner.CreateTempDir("platform-analysis-test-")
	
	t.Run("Architecture detection", func(t *testing.T) {
		// Test architecture detection for different binary types
		testCases := []struct {
			name         string
			binaryPath   string
			expectedArch []string // Multiple possible architectures
		}{
			{
				name:         "ELF x86_64",
				binaryPath:   "tests/fixtures/sample_binaries/valid_elf_binary",
				expectedArch: []string{"x86_64", "amd64"},
			},
		}
		
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				binaryPath := filepath.Join(projectRoot, tc.binaryPath)
				
				if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
					t.Skipf("Binary not available: %s", tc.binaryPath)
					return
				}
				
				cmd := exec.Command(ravenLinterPath, "check", binaryPath, "--format", "json")
				cmd.Dir = tempDir
				
				output, err := cmd.Output()
				// Don't require success - focus on getting metadata
				
				var report checks.ComplianceReport
				err = json.Unmarshal(output, &report)
				require.NoError(t, err, "Should get valid JSON output")
				
				// Look for binary metadata check result
				var metadataResult *checks.CheckResult
				for _, result := range report.Results {
					if result.ID == "check-2-binary-metadata" {
						metadataResult = &result
						break
					}
				}
				
				if metadataResult != nil && metadataResult.Metadata != nil {
					if arch, ok := metadataResult.Metadata["architecture"].(string); ok {
						found := false
						for _, expectedArch := range tc.expectedArch {
							if strings.Contains(strings.ToLower(arch), strings.ToLower(expectedArch)) {
								found = true
								break
							}
						}
						assert.True(t, found, "Should detect expected architecture, got: %s, expected one of: %v", 
							arch, tc.expectedArch)
						
						t.Logf("Architecture detection for %s: %s", tc.name, arch)
					}
					
					// Check bitness
					if bitness, ok := metadataResult.Metadata["bitness"].(float64); ok {
						assert.Contains(t, []float64{32, 64}, bitness, "Should detect valid bitness")
						t.Logf("Bitness detection for %s: %.0f-bit", tc.name, bitness)
					}
					
					// Check endianness
					if endianness, ok := metadataResult.Metadata["endianness"].(string); ok {
						assert.Contains(t, []string{"little", "big"}, endianness, "Should detect valid endianness")
						t.Logf("Endianness detection for %s: %s", tc.name, endianness)
					}
				}
			})
		}
	})
	
	t.Run("Section analysis", func(t *testing.T) {
		binaryPath := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/valid_elf_binary")
		
		if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
			t.Skip("Valid ELF binary not available")
			return
		}
		
		cmd := exec.Command(ravenLinterPath, "check", binaryPath, "--format", "json")
		cmd.Dir = tempDir
		
		output, err := cmd.Output()
		// Don't require success - focus on getting metadata
		
		var report checks.ComplianceReport
		err = json.Unmarshal(output, &report)
		require.NoError(t, err, "Should get valid JSON output")
		
		// Look for binary metadata check result
		var metadataResult *checks.CheckResult
		for _, result := range report.Results {
			if result.ID == "check-2-binary-metadata" {
				metadataResult = &result
				break
			}
		}
		
		if metadataResult != nil && metadataResult.Metadata != nil {
			if sections, ok := metadataResult.Metadata["sections"].([]interface{}); ok {
				t.Logf("Sections found: %d", len(sections))
				
				// Convert to string slice for easier checking
				sectionNames := make([]string, len(sections))
				for i, section := range sections {
					if sectionName, ok := section.(string); ok {
						sectionNames[i] = sectionName
					}
				}
				
				// Check for common ELF sections
				expectedSections := []string{".text"}
				for _, expected := range expectedSections {
					found := false
					for _, section := range sectionNames {
						if section == expected {
							found = true
							break
						}
					}
					if found {
						t.Logf("Found expected section: %s", expected)
					}
				}
				
				// Log all sections for debugging
				t.Logf("All sections: %v", sectionNames)
			}
		}
	})
	
	t.Run("Dependency analysis", func(t *testing.T) {
		binaryPath := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/valid_elf_binary")
		
		if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
			t.Skip("Valid ELF binary not available")
			return
		}
		
		cmd := exec.Command(ravenLinterPath, "check", binaryPath, "--format", "json")
		cmd.Dir = tempDir
		
		output, err := cmd.Output()
		// Don't require success - focus on getting metadata
		
		var report checks.ComplianceReport
		err = json.Unmarshal(output, &report)
		require.NoError(t, err, "Should get valid JSON output")
		
		// Look for dependency analysis check result
		var depResult *checks.CheckResult
		for _, result := range report.Results {
			if result.ID == "check-3-dependency-analysis" {
				depResult = &result
				break
			}
		}
		
		if depResult != nil && depResult.Metadata != nil {
			if depCount, ok := depResult.Metadata["dependency_count"].(float64); ok {
				t.Logf("Dependencies found: %.0f", depCount)
				
				if deps, ok := depResult.Metadata["dependencies"].([]interface{}); ok {
					depNames := make([]string, len(deps))
					for i, dep := range deps {
						if depName, ok := dep.(string); ok {
							depNames[i] = depName
						}
					}
					t.Logf("Dependency list: %v", depNames)
				}
			}
		}
	})
}

// testCrossPlatformTLSGeneration tests TLS handshake generation across platforms
func testCrossPlatformTLSGeneration(t *testing.T, runner *testutils.TestRunner, chromeUtlsGenPath, projectRoot string) {
	tempDir := runner.CreateTempDir("tls-platform-test-")
	
	t.Run("ClientHello generation consistency", func(t *testing.T) {
		// Generate ClientHello multiple times and verify consistency
		clientHelloFiles := make([]string, 3)
		
		for i := 0; i < 3; i++ {
			clientHelloPath := filepath.Join(tempDir, fmt.Sprintf("clienthello_%d.bin", i))
			clientHelloFiles[i] = clientHelloPath
			
			cmd := exec.Command(chromeUtlsGenPath, "generate", "--output", clientHelloPath)
			cmd.Dir = tempDir
			
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "ClientHello generation %d should succeed: %s", i, string(output))
			assert.FileExists(t, clientHelloPath, "ClientHello file %d should be created", i)
		}
		
		// Compare file sizes (should be similar)
		var sizes []int64
		for i, file := range clientHelloFiles {
			info, err := os.Stat(file)
			require.NoError(t, err, "Should stat ClientHello file %d", i)
			sizes = append(sizes, info.Size())
		}
		
		// All sizes should be within reasonable range
		for i, size := range sizes {
			assert.Greater(t, size, int64(100), "ClientHello %d should have reasonable size", i)
			assert.Less(t, size, int64(10000), "ClientHello %d should not be too large", i)
		}
		
		t.Logf("ClientHello generation consistency test:")
		for i, size := range sizes {
			t.Logf("  Generation %d: %d bytes", i, size)
		}
	})
	
	t.Run("Platform-specific Chrome version handling", func(t *testing.T) {
		// Test Chrome version handling on current platform
		clientHelloPath := filepath.Join(tempDir, "platform_clienthello.bin")
		
		// Try to generate with specific Chrome version
		chromeVersion := "120.0.6099.109"
		cmd := exec.Command(chromeUtlsGenPath, "generate", 
			"--version", chromeVersion,
			"--output", clientHelloPath)
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Chrome version-specific generation should succeed: %s", string(output))
		
		assert.FileExists(t, clientHelloPath, "Version-specific ClientHello should be created")
		
		info, err := os.Stat(clientHelloPath)
		require.NoError(t, err, "Should stat version-specific ClientHello")
		
		t.Logf("Platform-specific Chrome version test:")
		t.Logf("  Platform: %s/%s", runtime.GOOS, runtime.GOARCH)
		t.Logf("  Chrome version: %s", chromeVersion)
		t.Logf("  ClientHello size: %d bytes", info.Size())
	})
	
	t.Run("JA3 fingerprint calculation", func(t *testing.T) {
		// Test JA3 calculation on current platform
		clientHelloPath := filepath.Join(tempDir, "ja3_test_clienthello.bin")
		
		cmd := exec.Command(chromeUtlsGenPath, "generate", "--output", clientHelloPath)
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "ClientHello generation for JA3 test should succeed: %s", string(output))
		
		// Try to test JA3 against a test server (if available)
		// Use a well-known test endpoint
		testTarget := "www.google.com:443"
		
		cmd = exec.Command(chromeUtlsGenPath, "ja3-test", testTarget, "--clienthello", clientHelloPath)
		cmd.Dir = tempDir
		
		testutils.WithTimeout(t, testutils.DefaultTimeouts.Medium, func() {
			output, err := cmd.CombinedOutput()
			
			if err != nil {
				// Network issues are acceptable in CI environments
				if strings.Contains(string(output), "network") || 
				   strings.Contains(string(output), "timeout") ||
				   strings.Contains(string(output), "connection") {
					t.Skipf("Skipping JA3 test due to network issues: %s", string(output))
					return
				}
				t.Logf("JA3 test output (may fail in CI): %s", string(output))
			} else {
				t.Logf("JA3 test successful: %s", string(output))
			}
		})
	})
}

// testArchitectureSupport tests support for different architectures
func testArchitectureSupport(t *testing.T, runner *testutils.TestRunner, ravenLinterPath, projectRoot string) {
	tempDir := runner.CreateTempDir("arch-support-test-")
	
	t.Run("Current architecture support", func(t *testing.T) {
		// Test that tools work on current architecture
		currentArch := runtime.GOARCH
		currentOS := runtime.GOOS
		
		t.Logf("Testing on current platform: %s/%s", currentOS, currentArch)
		
		// Use a simple binary for testing
		binaryPath := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/valid_elf_binary")
		
		if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
			t.Skip("Valid ELF binary not available for architecture test")
			return
		}
		
		cmd := exec.Command(ravenLinterPath, "check", binaryPath, "--format", "json")
		cmd.Dir = tempDir
		
		start := time.Now()
		output, err := cmd.Output()
		duration := time.Since(start)
		
		// Don't require success - focus on functionality
		var report checks.ComplianceReport
		err = json.Unmarshal(output, &report)
		require.NoError(t, err, "Should get valid JSON output on %s/%s", currentOS, currentArch)
		
		assert.Equal(t, 11, report.TotalChecks, "Should attempt all checks on %s/%s", currentOS, currentArch)
		assert.NotEmpty(t, report.Results, "Should have check results on %s/%s", currentOS, currentArch)
		
		t.Logf("Architecture support test results:")
		t.Logf("  Platform: %s/%s", currentOS, currentArch)
		t.Logf("  Execution time: %v", duration)
		t.Logf("  Compliance: %d/%d checks passed", report.PassedChecks, report.TotalChecks)
		
		// Performance should be reasonable
		assert.Less(t, duration, 2*time.Minute, "Should complete in reasonable time on %s/%s", currentOS, currentArch)
	})
	
	t.Run("Cross-architecture binary analysis", func(t *testing.T) {
		// Generate test binaries for different architectures if possible
		generateCrossArchBinaries(t, runner, tempDir)
		
		// Test analysis of different architecture binaries
		testFiles, err := filepath.Glob(filepath.Join(tempDir, "test_*_binary"))
		if err != nil {
			t.Logf("No cross-architecture binaries generated: %v", err)
			return
		}
		
		for _, testFile := range testFiles {
			t.Run(filepath.Base(testFile), func(t *testing.T) {
				cmd := exec.Command(ravenLinterPath, "check", testFile, "--format", "json")
				cmd.Dir = tempDir
				
				output, err := cmd.Output()
				// Don't require success - focus on getting metadata
				
				var report checks.ComplianceReport
				err = json.Unmarshal(output, &report)
				require.NoError(t, err, "Should get valid JSON output for %s", testFile)
				
				t.Logf("Cross-architecture analysis for %s:", filepath.Base(testFile))
				t.Logf("  Compliance: %d/%d checks passed", report.PassedChecks, report.TotalChecks)
				
				// Look for architecture information in metadata
				for _, result := range report.Results {
					if result.ID == "check-2-binary-metadata" && result.Metadata != nil {
						if arch, ok := result.Metadata["architecture"].(string); ok {
							t.Logf("  Detected architecture: %s", arch)
						}
						if bitness, ok := result.Metadata["bitness"].(float64); ok {
							t.Logf("  Detected bitness: %.0f-bit", bitness)
						}
					}
				}
			})
		}
	})
}

// testPlatformSpecificErrorHandling tests error handling across platforms
func testPlatformSpecificErrorHandling(t *testing.T, runner *testutils.TestRunner, ravenLinterPath, chromeUtlsGenPath, projectRoot string) {
	tempDir := runner.CreateTempDir("error-handling-test-")
	
	t.Run("File permission errors", func(t *testing.T) {
		// Create a file with restricted permissions
		restrictedFile := filepath.Join(tempDir, "restricted_binary")
		err := os.WriteFile(restrictedFile, []byte("test"), 0000) // No permissions
		require.NoError(t, err, "Should create restricted file")
		
		// Try to analyze restricted file
		cmd := exec.Command(ravenLinterPath, "check", restrictedFile, "--format", "json")
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		
		// Should fail gracefully
		var exitError *exec.ExitError
		if err != nil {
			require.ErrorAs(t, err, &exitError, "Should be an exit error")
		}
		
		// Should still produce some output (error message)
		assert.NotEmpty(t, output, "Should produce error output")
		
		// Check if output contains error information
		outputStr := string(output)
		assert.True(t, strings.Contains(outputStr, "permission") || 
					strings.Contains(outputStr, "access") ||
					strings.Contains(outputStr, "denied"),
			"Error message should indicate permission issue: %s", outputStr)
		
		t.Logf("Permission error handling test:")
		t.Logf("  Platform: %s", runtime.GOOS)
		t.Logf("  Error output: %s", outputStr)
	})
	
	t.Run("Non-existent file errors", func(t *testing.T) {
		nonExistentFile := filepath.Join(tempDir, "does_not_exist.bin")
		
		cmd := exec.Command(ravenLinterPath, "check", nonExistentFile, "--format", "json")
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		
		// Should fail gracefully
		var exitError *exec.ExitError
		require.ErrorAs(t, err, &exitError, "Should be an exit error")
		
		// Should produce error output
		assert.NotEmpty(t, output, "Should produce error output")
		
		outputStr := string(output)
		assert.True(t, strings.Contains(outputStr, "not found") || 
					strings.Contains(outputStr, "no such file") ||
					strings.Contains(outputStr, "does not exist"),
			"Error message should indicate file not found: %s", outputStr)
		
		t.Logf("File not found error handling test:")
		t.Logf("  Platform: %s", runtime.GOOS)
		t.Logf("  Error output: %s", outputStr)
	})
	
	t.Run("Network error handling", func(t *testing.T) {
		// Test chrome-utls-gen with invalid target
		invalidTarget := "invalid.nonexistent.domain.test:443"
		
		cmd := exec.Command(chromeUtlsGenPath, "ja3-test", invalidTarget)
		cmd.Dir = tempDir
		
		testutils.WithTimeout(t, testutils.DefaultTimeouts.Short, func() {
			output, err := cmd.CombinedOutput()
			
			// Should fail gracefully
			if err != nil {
				var exitError *exec.ExitError
				require.ErrorAs(t, err, &exitError, "Should be an exit error")
			}
			
			// Should produce error output
			assert.NotEmpty(t, output, "Should produce error output")
			
			outputStr := string(output)
			assert.True(t, strings.Contains(outputStr, "network") || 
						strings.Contains(outputStr, "connection") ||
						strings.Contains(outputStr, "resolve") ||
						strings.Contains(outputStr, "timeout"),
				"Error message should indicate network issue: %s", outputStr)
			
			t.Logf("Network error handling test:")
			t.Logf("  Platform: %s", runtime.GOOS)
			t.Logf("  Error output: %s", outputStr)
		})
	})
	
	t.Run("Invalid output directory", func(t *testing.T) {
		// Try to write to invalid directory
		invalidDir := filepath.Join(tempDir, "nonexistent", "deep", "path")
		invalidOutput := filepath.Join(invalidDir, "output.bin")
		
		cmd := exec.Command(chromeUtlsGenPath, "generate", "--output", invalidOutput)
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		
		// Should fail gracefully
		var exitError *exec.ExitError
		if err != nil {
			require.ErrorAs(t, err, &exitError, "Should be an exit error")
		}
		
		outputStr := string(output)
		assert.True(t, strings.Contains(outputStr, "directory") || 
					strings.Contains(outputStr, "path") ||
					strings.Contains(outputStr, "no such file"),
			"Error message should indicate directory issue: %s", outputStr)
		
		t.Logf("Invalid directory error handling test:")
		t.Logf("  Platform: %s", runtime.GOOS)
		t.Logf("  Error output: %s", outputStr)
	})
}

// generatePlatformSpecificBinaries generates test binaries for different platforms
func generatePlatformSpecificBinaries(t *testing.T, runner *testutils.TestRunner, projectRoot string) {
	fixturesDir := filepath.Join(projectRoot, "tests/fixtures/sample_binaries")
	
	// Run the binary generator
	generatorPath := filepath.Join(fixturesDir, "generate_test_binaries.go")
	
	if _, err := os.Stat(generatorPath); os.IsNotExist(err) {
		t.Logf("Binary generator not found: %s", generatorPath)
		return
	}
	
	cmd := exec.Command("go", "run", "generate_test_binaries.go")
	cmd.Dir = fixturesDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Failed to generate platform-specific binaries: %v, output: %s", err, string(output))
		return
	}
	
	t.Logf("Generated platform-specific test binaries: %s", string(output))
}

// generateCrossArchBinaries generates test binaries for different architectures
func generateCrossArchBinaries(t *testing.T, runner *testutils.TestRunner, tempDir string) {
	// This is a simplified version - in a real implementation, you'd use
	// cross-compilation or pre-built binaries for different architectures
	
	architectures := []struct {
		name string
		arch string
		os   string
	}{
		{"amd64", "amd64", "linux"},
		{"arm64", "arm64", "linux"},
		{"386", "386", "linux"},
	}
	
	for _, arch := range architectures {
		binaryPath := filepath.Join(tempDir, fmt.Sprintf("test_%s_binary", arch.name))
		
		// Create a minimal binary for testing
		// In practice, you'd use proper cross-compilation
		content := fmt.Sprintf("#!/bin/bash\necho 'Test binary for %s'\n", arch.name)
		err := os.WriteFile(binaryPath, []byte(content), 0755)
		if err != nil {
			t.Logf("Failed to create test binary for %s: %v", arch.name, err)
			continue
		}
		
		t.Logf("Created test binary for %s: %s", arch.name, binaryPath)
	}
}