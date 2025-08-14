package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testutils "github.com/raven-betanet/dual-cli/tests/utils"
)

// TestIntegrationFramework tests the integration test framework itself
func TestIntegrationFramework(t *testing.T) {
	runner := testutils.NewTestRunner(t)
	
	t.Run("TestRunner creates and cleans temp directories", func(t *testing.T) {
		tempDir := runner.CreateTempDir("framework-test-")
		
		// Verify directory exists
		assert.DirExists(t, tempDir)
		
		// Write a test file
		testFile := runner.WriteTestFile(tempDir, "test.txt", "test content")
		assert.FileExists(t, testFile)
		
		// Cleanup will be called automatically by t.Cleanup()
	})
	
	t.Run("Golden file assertion works", func(t *testing.T) {
		tempDir := runner.CreateTempDir("golden-test-")
		goldenPath := filepath.Join(tempDir, "test.golden")
		
		// Create a golden file
		expectedContent := []byte("expected output")
		err := os.WriteFile(goldenPath, expectedContent, 0644)
		require.NoError(t, err)
		
		// Test assertion passes with matching content
		testutils.AssertGoldenFile(t, goldenPath, expectedContent)
	})
}

// TestFixturesExist verifies that all required test fixtures are present
func TestFixturesExist(t *testing.T) {
	testCases := []struct {
		name string
		path string
	}{
		{"Valid ELF binary", "tests/fixtures/sample_binaries/valid_elf_binary"},
		{"Invalid ELF binary", "tests/fixtures/sample_binaries/invalid_elf_binary"},
		{"Corrupted binary", "tests/fixtures/sample_binaries/corrupted_binary"},
		{"Large binary", "tests/fixtures/sample_binaries/large_binary"},
		{"Valid config", "tests/fixtures/test_configs/valid_config.yaml"},
		{"Minimal config", "tests/fixtures/test_configs/minimal_config.yaml"},
		{"Chrome N handshake", "tests/golden/chrome_handshakes/chrome_stable_N/clienthello.bin"},
		{"Chrome N-2 handshake", "tests/golden/chrome_handshakes/chrome_stable_N-2/clienthello.bin"},
		{"CycloneDX SBOM golden", "tests/golden/sbom_outputs/valid_elf_cyclonedx.json"},
		{"SPDX SBOM golden", "tests/golden/sbom_outputs/valid_elf_spdx.json"},
		{"Valid compliance result", "tests/golden/compliance_results/valid_elf_all_pass.json"},
		{"Invalid compliance result", "tests/golden/compliance_results/invalid_elf_partial_fail.json"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Get absolute path from project root
			projectRoot := getProjectRoot(t)
			fullPath := filepath.Join(projectRoot, tc.path)
			
			assert.FileExists(t, fullPath, "Required test fixture missing: %s", tc.path)
		})
	}
}

// TestGoldenFileStructure verifies the golden file directory structure
func TestGoldenFileStructure(t *testing.T) {
	projectRoot := getProjectRoot(t)
	
	t.Run("Chrome handshake golden files", func(t *testing.T) {
		versions := []string{"chrome_stable_N", "chrome_stable_N-2"}
		
		for _, version := range versions {
			versionDir := filepath.Join(projectRoot, "tests/golden/chrome_handshakes", version)
			assert.DirExists(t, versionDir)
			
			// Check required files
			requiredFiles := []string{"clienthello.bin", "metadata.json"}
			for _, file := range requiredFiles {
				filePath := filepath.Join(versionDir, file)
				assert.FileExists(t, filePath, "Missing required file: %s", file)
			}
		}
	})
	
	t.Run("SBOM golden files", func(t *testing.T) {
		sbomDir := filepath.Join(projectRoot, "tests/golden/sbom_outputs")
		assert.DirExists(t, sbomDir)
		
		requiredFiles := []string{
			"valid_elf_cyclonedx.json",
			"valid_elf_spdx.json",
		}
		
		for _, file := range requiredFiles {
			filePath := filepath.Join(sbomDir, file)
			assert.FileExists(t, filePath, "Missing SBOM golden file: %s", file)
		}
	})
	
	t.Run("Compliance result golden files", func(t *testing.T) {
		complianceDir := filepath.Join(projectRoot, "tests/golden/compliance_results")
		assert.DirExists(t, complianceDir)
		
		requiredFiles := []string{
			"valid_elf_all_pass.json",
			"invalid_elf_partial_fail.json",
		}
		
		for _, file := range requiredFiles {
			filePath := filepath.Join(complianceDir, file)
			assert.FileExists(t, filePath, "Missing compliance golden file: %s", file)
		}
	})
}

// getProjectRoot finds the project root directory
func getProjectRoot(t *testing.T) string {
	// Start from current directory and walk up until we find go.mod
	dir, err := os.Getwd()
	require.NoError(t, err)
	
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("Could not find project root (go.mod not found)")
		}
		dir = parent
	}
}