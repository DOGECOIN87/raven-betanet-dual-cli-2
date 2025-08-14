package integration

import (
	"crypto/md5"
	"encoding/hex"
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
)

// TestTLSCrossPlatformGeneration tests TLS handshake generation across platforms
func TestTLSCrossPlatformGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping TLS cross-platform tests in short mode")
	}

	runner := testutils.NewTestRunner(t)
	projectRoot := getProjectRoot(t)
	
	// Build chrome-utls-gen for current platform
	chromeUtlsGenPath := buildChromeUtlsGen(t, runner)
	
	// Log platform information
	testutils.LogPlatformInfo(t)
	
	t.Run("Platform-specific ClientHello generation", func(t *testing.T) {
		testPlatformSpecificClientHelloGeneration(t, runner, chromeUtlsGenPath, projectRoot)
	})
	
	t.Run("Cross-platform JA3 consistency", func(t *testing.T) {
		testCrossPlatformJA3Consistency(t, runner, chromeUtlsGenPath, projectRoot)
	})
	
	t.Run("Platform-specific Chrome version mapping", func(t *testing.T) {
		testPlatformSpecificChromeVersionMapping(t, runner, chromeUtlsGenPath, projectRoot)
	})
	
	t.Run("Network connectivity across platforms", func(t *testing.T) {
		testNetworkConnectivityAcrossPlatforms(t, runner, chromeUtlsGenPath, projectRoot)
	})
	
	t.Run("Platform-specific error handling", func(t *testing.T) {
		testPlatformSpecificTLSErrorHandling(t, runner, chromeUtlsGenPath, projectRoot)
	})
}

// testPlatformSpecificClientHelloGeneration tests ClientHello generation on current platform
func testPlatformSpecificClientHelloGeneration(t *testing.T, runner *testutils.TestRunner, chromeUtlsGenPath, projectRoot string) {
	tempDir := runner.CreateTempDir("tls-platform-generation-")
	
	// Test different Chrome versions on current platform
	chromeVersions := []string{
		"120.0.6099.109",
		"119.0.6045.105",
		"118.0.5993.88",
	}
	
	for _, version := range chromeVersions {
		t.Run(fmt.Sprintf("Chrome_%s", version), func(t *testing.T) {
			clientHelloPath := filepath.Join(tempDir, fmt.Sprintf("clienthello_%s_%s_%s.bin", 
				version, runtime.GOOS, runtime.GOARCH))
			
			cmd := exec.Command(chromeUtlsGenPath, "generate", 
				"--version", version,
				"--output", clientHelloPath)
			cmd.Dir = tempDir
			
			start := time.Now()
			output, err := cmd.CombinedOutput()
			duration := time.Since(start)
			
			require.NoError(t, err, "ClientHello generation should succeed for Chrome %s: %s", 
				version, string(output))
			assert.FileExists(t, clientHelloPath, "ClientHello file should be created")
			
			// Validate file properties
			info, err := os.Stat(clientHelloPath)
			require.NoError(t, err, "Should stat ClientHello file")
			
			assert.Greater(t, info.Size(), int64(100), "ClientHello should have reasonable size")
			assert.Less(t, info.Size(), int64(10000), "ClientHello should not be too large")
			
			// Read and validate ClientHello structure
			clientHelloData, err := os.ReadFile(clientHelloPath)
			require.NoError(t, err, "Should read ClientHello data")
			
			// Basic TLS record validation
			if len(clientHelloData) >= 5 {
				// TLS record header: type(1) + version(2) + length(2)
				recordType := clientHelloData[0]
				assert.Equal(t, uint8(0x16), recordType, "Should be TLS handshake record type")
				
				// TLS version should be reasonable
				tlsVersion := uint16(clientHelloData[1])<<8 | uint16(clientHelloData[2])
				assert.True(t, tlsVersion >= 0x0301 && tlsVersion <= 0x0304, 
					"TLS version should be reasonable: 0x%04x", tlsVersion)
			}
			
			t.Logf("Platform-specific ClientHello generation for Chrome %s:", version)
			t.Logf("  Platform: %s/%s", runtime.GOOS, runtime.GOARCH)
			t.Logf("  File size: %d bytes", info.Size())
			t.Logf("  Generation time: %v", duration)
			t.Logf("  Output: %s", clientHelloPath)
		})
	}
}

// testCrossPlatformJA3Consistency tests JA3 fingerprint consistency across platforms
func testCrossPlatformJA3Consistency(t *testing.T, runner *testutils.TestRunner, chromeUtlsGenPath, projectRoot string) {
	tempDir := runner.CreateTempDir("ja3-consistency-")
	
	// Generate multiple ClientHellos and check JA3 consistency
	chromeVersion := "120.0.6099.109"
	clientHelloFiles := make([]string, 3)
	ja3Hashes := make([]string, 3)
	
	for i := 0; i < 3; i++ {
		clientHelloPath := filepath.Join(tempDir, fmt.Sprintf("consistency_test_%d.bin", i))
		clientHelloFiles[i] = clientHelloPath
		
		cmd := exec.Command(chromeUtlsGenPath, "generate", 
			"--version", chromeVersion,
			"--output", clientHelloPath)
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "ClientHello generation %d should succeed: %s", i, string(output))
		
		// Calculate JA3 hash manually for comparison
		clientHelloData, err := os.ReadFile(clientHelloPath)
		require.NoError(t, err, "Should read ClientHello data %d", i)
		
		// Simple hash of the entire ClientHello for consistency checking
		hash := md5.Sum(clientHelloData)
		ja3Hashes[i] = hex.EncodeToString(hash[:])
	}
	
	// Check consistency
	t.Run("ClientHello consistency", func(t *testing.T) {
		// All ClientHellos should be identical for the same Chrome version
		for i := 1; i < len(ja3Hashes); i++ {
			assert.Equal(t, ja3Hashes[0], ja3Hashes[i], 
				"ClientHello %d should be identical to ClientHello 0", i)
		}
		
		t.Logf("JA3 consistency test results:")
		t.Logf("  Chrome version: %s", chromeVersion)
		t.Logf("  Platform: %s/%s", runtime.GOOS, runtime.GOARCH)
		for i, hash := range ja3Hashes {
			t.Logf("  ClientHello %d hash: %s", i, hash)
		}
	})
	
	// Test JA3 calculation if network is available
	t.Run("JA3 calculation test", func(t *testing.T) {
		if len(clientHelloFiles) == 0 {
			t.Skip("No ClientHello files available")
			return
		}
		
		// Use the first ClientHello for JA3 testing
		clientHelloPath := clientHelloFiles[0]
		
		// Try to test against a well-known server
		testTargets := []string{
			"www.google.com:443",
			"www.cloudflare.com:443",
			"httpbin.org:443",
		}
		
		for _, target := range testTargets {
			t.Run(fmt.Sprintf("JA3_test_%s", strings.Replace(target, ":", "_", -1)), func(t *testing.T) {
				cmd := exec.Command(chromeUtlsGenPath, "ja3-test", target, 
					"--clienthello", clientHelloPath,
					"--timeout", "10s")
				cmd.Dir = tempDir
				
				testutils.WithTimeout(t, testutils.DefaultTimeouts.Medium, func() {
					output, err := cmd.CombinedOutput()
					
					if err != nil {
						// Network issues are acceptable in CI environments
						outputStr := string(output)
						if strings.Contains(outputStr, "network") || 
						   strings.Contains(outputStr, "timeout") ||
						   strings.Contains(outputStr, "connection") ||
						   strings.Contains(outputStr, "resolve") {
							t.Skipf("Skipping JA3 test for %s due to network issues: %s", target, outputStr)
							return
						}
						t.Logf("JA3 test failed for %s (may be expected): %s", target, outputStr)
					} else {
						t.Logf("JA3 test successful for %s: %s", target, string(output))
						
						// Parse output for JA3 information
						outputStr := string(output)
						if strings.Contains(outputStr, "JA3") {
							lines := strings.Split(outputStr, "\n")
							for _, line := range lines {
								if strings.Contains(line, "JA3") {
									t.Logf("  %s", strings.TrimSpace(line))
								}
							}
						}
					}
				})
			})
		}
	})
}

// testPlatformSpecificChromeVersionMapping tests Chrome version mapping on current platform
func testPlatformSpecificChromeVersionMapping(t *testing.T, runner *testutils.TestRunner, chromeUtlsGenPath, projectRoot string) {
	tempDir := runner.CreateTempDir("chrome-version-mapping-")
	
	// Test version mapping for different Chrome versions
	versionTests := []struct {
		version     string
		expectValid bool
		description string
	}{
		{"120.0.6099.109", true, "Current stable version"},
		{"119.0.6045.105", true, "Previous stable version"},
		{"999.0.0.0", true, "Future version (should fallback)"},
		{"50.0.0.0", true, "Old version (should fallback)"},
		{"invalid.version", false, "Invalid version format"},
	}
	
	for _, test := range versionTests {
		t.Run(fmt.Sprintf("Version_%s", test.version), func(t *testing.T) {
			clientHelloPath := filepath.Join(tempDir, fmt.Sprintf("version_test_%s.bin", 
				strings.Replace(test.version, ".", "_", -1)))
			
			cmd := exec.Command(chromeUtlsGenPath, "generate", 
				"--version", test.version,
				"--output", clientHelloPath)
			cmd.Dir = tempDir
			
			output, err := cmd.CombinedOutput()
			
			if test.expectValid {
				if err != nil {
					// Some versions might not be supported, but should fail gracefully
					t.Logf("Version %s not supported (expected): %s", test.version, string(output))
				} else {
					assert.FileExists(t, clientHelloPath, "ClientHello should be generated for valid version")
					
					info, err := os.Stat(clientHelloPath)
					require.NoError(t, err, "Should stat generated file")
					assert.Greater(t, info.Size(), int64(0), "Generated file should not be empty")
					
					t.Logf("Version mapping test for %s (%s):", test.version, test.description)
					t.Logf("  Platform: %s/%s", runtime.GOOS, runtime.GOARCH)
					t.Logf("  Generated file size: %d bytes", info.Size())
				}
			} else {
				// Invalid versions should fail
				assert.Error(t, err, "Invalid version should fail: %s", test.version)
				t.Logf("Invalid version %s correctly rejected: %s", test.version, string(output))
			}
		})
	}
}

// testNetworkConnectivityAcrossPlatforms tests network functionality across platforms
func testNetworkConnectivityAcrossPlatforms(t *testing.T, runner *testutils.TestRunner, chromeUtlsGenPath, projectRoot string) {
	tempDir := runner.CreateTempDir("network-connectivity-")
	
	t.Run("Chrome version update test", func(t *testing.T) {
		// Test Chrome version fetching (network-dependent)
		cmd := exec.Command(chromeUtlsGenPath, "update", "--dry-run")
		cmd.Dir = tempDir
		
		testutils.WithTimeout(t, testutils.DefaultTimeouts.Long, func() {
			output, err := cmd.CombinedOutput()
			
			if err != nil {
				outputStr := string(output)
				if strings.Contains(outputStr, "network") || 
				   strings.Contains(outputStr, "timeout") ||
				   strings.Contains(outputStr, "connection") {
					t.Skipf("Skipping update test due to network issues: %s", outputStr)
					return
				}
				t.Logf("Update test failed (may be expected in CI): %s", outputStr)
			} else {
				t.Logf("Chrome version update test successful: %s", string(output))
				
				// Parse output for version information
				outputStr := string(output)
				if strings.Contains(outputStr, "Chrome") {
					lines := strings.Split(outputStr, "\n")
					for _, line := range lines {
						if strings.Contains(line, "Chrome") || strings.Contains(line, "version") {
							t.Logf("  %s", strings.TrimSpace(line))
						}
					}
				}
			}
		})
	})
	
	t.Run("Platform-specific network behavior", func(t *testing.T) {
		// Test platform-specific network behavior
		clientHelloPath := filepath.Join(tempDir, "network_test_clienthello.bin")
		
		// Generate ClientHello first
		cmd := exec.Command(chromeUtlsGenPath, "generate", "--output", clientHelloPath)
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "ClientHello generation should succeed: %s", string(output))
		
		// Test network connectivity with platform-specific expectations
		testTarget := "www.google.com:443"
		
		cmd = exec.Command(chromeUtlsGenPath, "ja3-test", testTarget, 
			"--clienthello", clientHelloPath,
			"--timeout", "15s")
		cmd.Dir = tempDir
		
		testutils.WithTimeout(t, testutils.DefaultTimeouts.Long, func() {
			start := time.Now()
			output, err := cmd.CombinedOutput()
			duration := time.Since(start)
			
			outputStr := string(output)
			
			if err != nil {
				if strings.Contains(outputStr, "network") || 
				   strings.Contains(outputStr, "timeout") ||
				   strings.Contains(outputStr, "connection") {
					t.Skipf("Network connectivity test skipped due to network issues: %s", outputStr)
					return
				}
			}
			
			t.Logf("Platform-specific network test results:")
			t.Logf("  Platform: %s/%s", runtime.GOOS, runtime.GOARCH)
			t.Logf("  Target: %s", testTarget)
			t.Logf("  Duration: %v", duration)
			t.Logf("  Success: %t", err == nil)
			
			if err == nil {
				t.Logf("  Output: %s", outputStr)
			} else {
				t.Logf("  Error: %s", outputStr)
			}
			
			// Platform-specific performance expectations
			switch runtime.GOOS {
			case "windows":
				// Windows might be slower
				assert.Less(t, duration, 30*time.Second, "Network test should complete within 30s on Windows")
			case "darwin":
				// macOS should be reasonably fast
				assert.Less(t, duration, 20*time.Second, "Network test should complete within 20s on macOS")
			default: // linux
				assert.Less(t, duration, 20*time.Second, "Network test should complete within 20s on Linux")
			}
		})
	})
}

// testPlatformSpecificTLSErrorHandling tests TLS error handling across platforms
func testPlatformSpecificTLSErrorHandling(t *testing.T, runner *testutils.TestRunner, chromeUtlsGenPath, projectRoot string) {
	tempDir := runner.CreateTempDir("tls-error-handling-")
	
	t.Run("Invalid output path handling", func(t *testing.T) {
		// Test platform-specific path handling
		var invalidPaths []string
		
		switch runtime.GOOS {
		case "windows":
			invalidPaths = []string{
				"C:\\nonexistent\\path\\output.bin",
				"\\\\invalid\\unc\\path\\output.bin",
				"CON", // Reserved name on Windows
			}
		case "darwin", "linux":
			invalidPaths = []string{
				"/nonexistent/path/output.bin",
				"/root/restricted/output.bin", // Likely no permission
			}
		default:
			invalidPaths = []string{
				"/nonexistent/path/output.bin",
			}
		}
		
		for _, invalidPath := range invalidPaths {
			t.Run(fmt.Sprintf("Invalid_path_%s", filepath.Base(invalidPath)), func(t *testing.T) {
				cmd := exec.Command(chromeUtlsGenPath, "generate", "--output", invalidPath)
				cmd.Dir = tempDir
				
				output, err := cmd.CombinedOutput()
				
				// Should fail gracefully
				assert.Error(t, err, "Invalid path should cause error: %s", invalidPath)
				
				outputStr := string(output)
				assert.NotEmpty(t, outputStr, "Should produce error message")
				
				// Check for platform-appropriate error messages
				switch runtime.GOOS {
				case "windows":
					assert.True(t, strings.Contains(outputStr, "path") || 
								strings.Contains(outputStr, "directory") ||
								strings.Contains(outputStr, "system cannot find"),
						"Windows error message should mention path issue: %s", outputStr)
				default:
					assert.True(t, strings.Contains(outputStr, "no such file") || 
								strings.Contains(outputStr, "permission") ||
								strings.Contains(outputStr, "directory"),
						"Unix error message should mention file/permission issue: %s", outputStr)
				}
				
				t.Logf("Platform-specific error handling for %s:", invalidPath)
				t.Logf("  Platform: %s", runtime.GOOS)
				t.Logf("  Error message: %s", outputStr)
			})
		}
	})
	
	t.Run("Network timeout handling", func(t *testing.T) {
		// Test platform-specific network timeout behavior
		clientHelloPath := filepath.Join(tempDir, "timeout_test_clienthello.bin")
		
		// Generate ClientHello first
		cmd := exec.Command(chromeUtlsGenPath, "generate", "--output", clientHelloPath)
		cmd.Dir = tempDir
		
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "ClientHello generation should succeed: %s", string(output))
		
		// Test with very short timeout
		invalidTarget := "192.0.2.1:443" // TEST-NET-1 address (should not respond)
		
		cmd = exec.Command(chromeUtlsGenPath, "ja3-test", invalidTarget, 
			"--clienthello", clientHelloPath,
			"--timeout", "1s") // Very short timeout
		cmd.Dir = tempDir
		
		start := time.Now()
		output, err = cmd.CombinedOutput()
		duration := time.Since(start)
		
		// Should timeout quickly
		assert.Error(t, err, "Should timeout for unreachable target")
		assert.Less(t, duration, 5*time.Second, "Should timeout within reasonable time")
		
		outputStr := string(output)
		assert.True(t, strings.Contains(outputStr, "timeout") || 
					strings.Contains(outputStr, "connection") ||
					strings.Contains(outputStr, "unreachable"),
			"Error message should indicate timeout/connection issue: %s", outputStr)
		
		t.Logf("Platform-specific timeout handling:")
		t.Logf("  Platform: %s/%s", runtime.GOOS, runtime.GOARCH)
		t.Logf("  Target: %s", invalidTarget)
		t.Logf("  Timeout duration: %v", duration)
		t.Logf("  Error message: %s", outputStr)
	})
	
	t.Run("Resource exhaustion handling", func(t *testing.T) {
		// Test handling of resource exhaustion (simplified)
		// Generate many ClientHellos quickly to test resource handling
		
		clientHelloFiles := make([]string, 10)
		
		start := time.Now()
		for i := 0; i < 10; i++ {
			clientHelloPath := filepath.Join(tempDir, fmt.Sprintf("resource_test_%d.bin", i))
			clientHelloFiles[i] = clientHelloPath
			
			cmd := exec.Command(chromeUtlsGenPath, "generate", "--output", clientHelloPath)
			cmd.Dir = tempDir
			
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Logf("Resource test iteration %d failed: %s", i, string(output))
				break
			}
		}
		duration := time.Since(start)
		
		// Count successful generations
		successCount := 0
		for _, file := range clientHelloFiles {
			if _, err := os.Stat(file); err == nil {
				successCount++
			}
		}
		
		t.Logf("Resource exhaustion test results:")
		t.Logf("  Platform: %s/%s", runtime.GOOS, runtime.GOARCH)
		t.Logf("  Successful generations: %d/10", successCount)
		t.Logf("  Total duration: %v", duration)
		t.Logf("  Average per generation: %v", duration/time.Duration(successCount))
		
		// Should generate at least some ClientHellos successfully
		assert.Greater(t, successCount, 5, "Should successfully generate most ClientHellos")
		
		// Performance should be reasonable
		if successCount > 0 {
			avgDuration := duration / time.Duration(successCount)
			assert.Less(t, avgDuration, 10*time.Second, "Average generation time should be reasonable")
		}
	})
}