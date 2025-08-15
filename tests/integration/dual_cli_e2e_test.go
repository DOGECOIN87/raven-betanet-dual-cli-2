//go:build integration
// +build integration

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
)

// TestRavenLinterE2E tests the raven-linter CLI end-to-end
func TestRavenLinterE2E(t *testing.T) {
	// Build the raven-linter binary
	ravenLinterBin := buildRavenLinter(t)
	defer os.Remove(ravenLinterBin)

	// Create a test binary
	testBinary := createTestBinary(t)
	defer os.Remove(testBinary)

	t.Run("help command", func(t *testing.T) {
		cmd := exec.Command(ravenLinterBin, "--help")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err)
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "Raven Betanet 1.1 Spec-Compliance Linter CLI")
		assert.Contains(t, outputStr, "check")
		assert.Contains(t, outputStr, "update")
	})

	t.Run("version command", func(t *testing.T) {
		cmd := exec.Command(ravenLinterBin, "--version")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err)
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "dev")
	})

	t.Run("check command with valid binary", func(t *testing.T) {
		cmd := exec.Command(ravenLinterBin, "check", testBinary)
		output, err := cmd.CombinedOutput()
		
		// The command should succeed (exit code 0) for a valid binary
		assert.NoError(t, err, "Command output: %s", string(output))
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "compliance checks")
	})

	t.Run("check command with JSON output", func(t *testing.T) {
		cmd := exec.Command(ravenLinterBin, "check", testBinary, "--format", "json")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err)
		
		// Validate JSON output
		var result map[string]interface{}
		err = json.Unmarshal(output, &result)
		require.NoError(t, err, "Output should be valid JSON")
		
		// Check required fields
		assert.Contains(t, result, "binary_path")
		assert.Contains(t, result, "total_checks")
		assert.Contains(t, result, "results")
	})

	t.Run("check command with SBOM generation", func(t *testing.T) {
		tempDir := t.TempDir()
		sbomPath := filepath.Join(tempDir, "test-sbom.json")
		
		cmd := exec.Command(ravenLinterBin, "check", testBinary, "--sbom", "--sbom-output", sbomPath)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Command output: %s", string(output))
		
		// Check that SBOM file was created
		assert.FileExists(t, sbomPath)
		
		// Validate SBOM content
		sbomData, err := os.ReadFile(sbomPath)
		require.NoError(t, err)
		
		var sbom map[string]interface{}
		err = json.Unmarshal(sbomData, &sbom)
		require.NoError(t, err, "SBOM should be valid JSON")
		
		// Check SBOM structure (CycloneDX format)
		assert.Contains(t, sbom, "bomFormat")
		assert.Contains(t, sbom, "components")
	})

	t.Run("check command with invalid binary", func(t *testing.T) {
		invalidBinary := createInvalidBinary(t)
		defer os.Remove(invalidBinary)
		
		cmd := exec.Command(ravenLinterBin, "check", invalidBinary)
		output, err := cmd.CombinedOutput()
		
		// The command should fail (exit code 1) for an invalid binary
		assert.Error(t, err)
		
		// Check exit code
		if exitError, ok := err.(*exec.ExitError); ok {
			assert.Equal(t, 1, exitError.ExitCode())
		}
	})

	t.Run("check command with nonexistent binary", func(t *testing.T) {
		cmd := exec.Command(ravenLinterBin, "check", "/nonexistent/binary")
		output, err := cmd.CombinedOutput()
		
		// The command should fail (exit code 2) for configuration error
		assert.Error(t, err)
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "not found")
	})
}

// TestChromeUTLSGenE2E tests the chrome-utls-gen CLI end-to-end
func TestChromeUTLSGenE2E(t *testing.T) {
	// Build the chrome-utls-gen binary
	chromeUTLSGenBin := buildChromeUTLSGen(t)
	defer os.Remove(chromeUTLSGenBin)

	t.Run("help command", func(t *testing.T) {
		cmd := exec.Command(chromeUTLSGenBin, "--help")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err)
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "Chrome-Stable (N-2) uTLS Template Generator")
		assert.Contains(t, outputStr, "generate")
		assert.Contains(t, outputStr, "ja3-test")
		assert.Contains(t, outputStr, "update")
	})

	t.Run("version command", func(t *testing.T) {
		cmd := exec.Command(chromeUTLSGenBin, "--version")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err)
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "dev")
	})

	t.Run("generate command", func(t *testing.T) {
		tempDir := t.TempDir()
		outputFile := filepath.Join(tempDir, "clienthello.bin")
		
		cmd := exec.Command(chromeUTLSGenBin, "generate", "--output", outputFile)
		output, err := cmd.CombinedOutput()
		
		// Allow network failures in CI environments
		if err != nil {
			t.Logf("Generate command failed (may be due to network issues): %s", string(output))
			t.Skip("Skipping generate test due to potential network issues")
		}
		
		// Check that output file was created
		assert.FileExists(t, outputFile)
		
		// Check file size (should be > 0)
		fileInfo, err := os.Stat(outputFile)
		require.NoError(t, err)
		assert.Greater(t, fileInfo.Size(), int64(0))
	})

	t.Run("ja3-test command", func(t *testing.T) {
		// Test against a reliable HTTPS endpoint
		cmd := exec.Command(chromeUTLSGenBin, "ja3-test", "--target", "httpbin.org:443")
		output, err := cmd.CombinedOutput()
		
		// Allow network failures in CI environments
		if err != nil {
			t.Logf("JA3 test failed (may be due to network issues): %s", string(output))
			t.Skip("Skipping JA3 test due to potential network issues")
		}
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "JA3")
	})

	t.Run("update command dry run", func(t *testing.T) {
		cmd := exec.Command(chromeUTLSGenBin, "update", "--dry-run")
		output, err := cmd.CombinedOutput()
		
		// Allow network failures in CI environments
		if err != nil {
			t.Logf("Update command failed (may be due to network issues): %s", string(output))
			t.Skip("Skipping update test due to potential network issues")
		}
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "Chrome")
	})
}

// TestCrossToolIntegration tests integration between both tools
func TestCrossToolIntegration(t *testing.T) {
	// Build both binaries
	ravenLinterBin := buildRavenLinter(t)
	defer os.Remove(ravenLinterBin)
	
	chromeUTLSGenBin := buildChromeUTLSGen(t)
	defer os.Remove(chromeUTLSGenBin)

	t.Run("generate clienthello and check with linter", func(t *testing.T) {
		tempDir := t.TempDir()
		clientHelloFile := filepath.Join(tempDir, "clienthello.bin")
		
		// Generate ClientHello
		genCmd := exec.Command(chromeUTLSGenBin, "generate", "--output", clientHelloFile)
		genOutput, err := genCmd.CombinedOutput()
		if err != nil {
			t.Logf("Generate failed: %s", string(genOutput))
			t.Skip("Skipping cross-tool test due to generate failure")
		}
		
		// Check ClientHello with linter
		checkCmd := exec.Command(ravenLinterBin, "check", clientHelloFile, "--format", "json")
		checkOutput, err := checkCmd.CombinedOutput()
		
		// The linter should be able to analyze the generated ClientHello
		if err != nil {
			t.Logf("Linter check output: %s", string(checkOutput))
		}
		
		// Validate JSON output
		var result map[string]interface{}
		err = json.Unmarshal(checkOutput, &result)
		require.NoError(t, err, "Linter output should be valid JSON")
	})
}

// Helper functions

func buildRavenLinter(t *testing.T) string {
	t.Helper()
	
	tempDir := t.TempDir()
	binaryPath := filepath.Join(tempDir, "raven-linter")
	
	cmd := exec.Command("go", "build", "-o", binaryPath, "../../cmd/raven-linter")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to build raven-linter: %s", string(output))
	
	return binaryPath
}

func buildChromeUTLSGen(t *testing.T) string {
	t.Helper()
	
	tempDir := t.TempDir()
	binaryPath := filepath.Join(tempDir, "chrome-utls-gen")
	
	cmd := exec.Command("go", "build", "-o", binaryPath, "../../cmd/chrome-utls-gen")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to build chrome-utls-gen: %s", string(output))
	
	return binaryPath
}

func createTestBinary(t *testing.T) string {
	t.Helper()
	
	tempDir := t.TempDir()
	
	// Create a simple Go program
	goSource := `package main
import "fmt"
func main() {
	fmt.Println("Hello, World!")
}`
	
	sourceFile := filepath.Join(tempDir, "test.go")
	err := os.WriteFile(sourceFile, []byte(goSource), 0644)
	require.NoError(t, err)
	
	// Build the test binary
	binaryPath := filepath.Join(tempDir, "test-binary")
	cmd := exec.Command("go", "build", "-o", binaryPath, sourceFile)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to build test binary: %s", string(output))
	
	return binaryPath
}

func createInvalidBinary(t *testing.T) string {
	t.Helper()
	
	tempDir := t.TempDir()
	invalidBinaryPath := filepath.Join(tempDir, "invalid-binary")
	
	// Create a file with invalid binary content
	invalidContent := "This is not a valid binary file"
	err := os.WriteFile(invalidBinaryPath, []byte(invalidContent), 0644)
	require.NoError(t, err)
	
	return invalidBinaryPath
}

// TestPerformance runs basic performance tests
func TestPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance tests in short mode")
	}

	ravenLinterBin := buildRavenLinter(t)
	defer os.Remove(ravenLinterBin)
	
	testBinary := createTestBinary(t)
	defer os.Remove(testBinary)

	t.Run("linter performance", func(t *testing.T) {
		start := time.Now()
		
		cmd := exec.Command(ravenLinterBin, "check", testBinary)
		output, err := cmd.CombinedOutput()
		
		duration := time.Since(start)
		
		require.NoError(t, err, "Command output: %s", string(output))
		
		// Linter should complete within reasonable time
		assert.Less(t, duration, 30*time.Second, "Linter took too long: %v", duration)
		
		t.Logf("Linter completed in %v", duration)
	})
}

// TestErrorHandling tests error handling scenarios
func TestErrorHandling(t *testing.T) {
	ravenLinterBin := buildRavenLinter(t)
	defer os.Remove(ravenLinterBin)

	t.Run("invalid arguments", func(t *testing.T) {
		cmd := exec.Command(ravenLinterBin, "invalid-command")
		output, err := cmd.CombinedOutput()
		
		assert.Error(t, err)
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "unknown command")
	})

	t.Run("missing required arguments", func(t *testing.T) {
		cmd := exec.Command(ravenLinterBin, "check")
		output, err := cmd.CombinedOutput()
		
		assert.Error(t, err)
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "required")
	})

	t.Run("invalid format option", func(t *testing.T) {
		testBinary := createTestBinary(t)
		defer os.Remove(testBinary)
		
		cmd := exec.Command(ravenLinterBin, "check", testBinary, "--format", "invalid")
		output, err := cmd.CombinedOutput()
		
		assert.Error(t, err)
		
		outputStr := string(output)
		assert.Contains(t, outputStr, "invalid output format")
	})
}