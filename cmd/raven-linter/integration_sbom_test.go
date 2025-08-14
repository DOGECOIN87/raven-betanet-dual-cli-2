package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/raven-betanet/dual-cli/internal/utils"
)

func TestSBOMGeneration_CycloneDX(t *testing.T) {
	// Create a temporary test binary
	tempDir := t.TempDir()
	testBinary := filepath.Join(tempDir, "test-binary")
	sbomOutput := filepath.Join(tempDir, "test-sbom.json")
	
	// Create a simple test binary (ELF header)
	testData := createSimpleBinary()
	err := os.WriteFile(testBinary, testData, 0755)
	require.NoError(t, err)
	
	// Create root command for testing
	rootCmd := createTestRootCommand()
	
	// Capture output
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	
	// Reset global variables
	outputFormat = "json"
	generateSBOM = true
	sbomFormat = "cyclonedx"
	sbomOutput = sbomOutput
	
	// Set args and execute
	args := []string{"check", testBinary, "--sbom", "--sbom-format", "cyclonedx", "--sbom-output", sbomOutput, "--format", "json"}
	rootCmd.SetArgs(args)
	
	err = rootCmd.Execute()
	// CLI may exit with error if checks fail, but that's expected
	
	output := buf.String()
	
	// Verify SBOM file was created
	assert.FileExists(t, sbomOutput)
	
	// Read and validate SBOM content
	sbomData, err := os.ReadFile(sbomOutput)
	require.NoError(t, err)
	
	var sbomJSON map[string]interface{}
	err = json.Unmarshal(sbomData, &sbomJSON)
	require.NoError(t, err)
	
	// Validate CycloneDX structure
	assert.Equal(t, "CycloneDX", sbomJSON["bomFormat"])
	assert.Equal(t, "1.5", sbomJSON["specVersion"])
	assert.Contains(t, sbomJSON, "serialNumber")
	assert.Contains(t, sbomJSON, "metadata")
	assert.Contains(t, sbomJSON, "components")
	
	// Validate metadata
	metadata, ok := sbomJSON["metadata"].(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, metadata, "timestamp")
	assert.Contains(t, metadata, "tools")
	assert.Contains(t, metadata, "component")
	
	// Validate tools
	tools, ok := metadata["tools"].([]interface{})
	require.True(t, ok)
	require.Len(t, tools, 1)
	
	tool, ok := tools[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "Raven Betanet", tool["vendor"])
	assert.Equal(t, "raven-linter", tool["name"])
	
	// Validate main component
	component, ok := metadata["component"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "application", component["type"])
	assert.Equal(t, "test-binary", component["name"])
	assert.Contains(t, component, "hashes")
	
	// Verify JSON output contains SBOM path if output is valid JSON
	if output != "" {
		var report map[string]interface{}
		err = json.Unmarshal([]byte(output), &report)
		if err == nil {
			assert.Equal(t, sbomOutput, report["sbom_path"])
		}
	}
}

func TestSBOMGeneration_SPDX(t *testing.T) {
	// Create a temporary test binary
	tempDir := t.TempDir()
	testBinary := filepath.Join(tempDir, "test-binary")
	sbomOutput := filepath.Join(tempDir, "test-sbom-spdx.json")
	
	// Create a simple test binary (ELF header)
	testData := createSimpleBinary()
	err := os.WriteFile(testBinary, testData, 0755)
	require.NoError(t, err)
	
	// Create root command for testing
	rootCmd := createTestRootCommand()
	
	// Capture output
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	
	// Reset global variables
	outputFormat = "json"
	generateSBOM = true
	sbomFormat = "spdx"
	sbomOutput = sbomOutput
	
	// Set args and execute
	args := []string{"check", testBinary, "--sbom", "--sbom-format", "spdx", "--sbom-output", sbomOutput, "--format", "json"}
	rootCmd.SetArgs(args)
	
	err = rootCmd.Execute()
	// CLI may exit with error if checks fail, but that's expected
	
	output := buf.String()
	
	// Verify SBOM file was created
	assert.FileExists(t, sbomOutput)
	
	// Read and validate SBOM content
	sbomData, err := os.ReadFile(sbomOutput)
	require.NoError(t, err)
	
	var sbomJSON map[string]interface{}
	err = json.Unmarshal(sbomData, &sbomJSON)
	require.NoError(t, err)
	
	// Validate SPDX structure
	assert.Contains(t, sbomJSON["spdxVersion"], "SPDX-2.3")
	assert.Equal(t, "CC0-1.0", sbomJSON["dataLicense"])
	assert.Equal(t, "SPDXRef-DOCUMENT", sbomJSON["SPDXID"])
	assert.Contains(t, sbomJSON, "documentNamespace")
	assert.Contains(t, sbomJSON, "creationInfo")
	assert.Contains(t, sbomJSON, "packages")
	
	// Validate creation info
	creationInfo, ok := sbomJSON["creationInfo"].(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, creationInfo, "created")
	assert.Contains(t, creationInfo, "creators")
	
	creators, ok := creationInfo["creators"].([]interface{})
	require.True(t, ok)
	require.Len(t, creators, 1)
	assert.Contains(t, creators[0].(string), "Tool: raven-linter")
	
	// Validate packages
	packages, ok := sbomJSON["packages"].([]interface{})
	require.True(t, ok)
	require.GreaterOrEqual(t, len(packages), 1)
	
	mainPackage, ok := packages[0].(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, mainPackage["SPDXID"], "SPDXRef-Package-test-binary")
	assert.Equal(t, "test-binary", mainPackage["name"])
	
	// Verify JSON output contains SBOM path if output is valid JSON
	if output != "" {
		var report map[string]interface{}
		err = json.Unmarshal([]byte(output), &report)
		if err == nil {
			assert.Equal(t, sbomOutput, report["sbom_path"])
		}
	}
}

func TestSBOMGeneration_InvalidFormat(t *testing.T) {
	// Create a temporary test binary
	tempDir := t.TempDir()
	testBinary := filepath.Join(tempDir, "test-binary")
	sbomOutput := filepath.Join(tempDir, "test-sbom.json")
	
	// Create a simple test binary
	testData := createSimpleBinary()
	err := os.WriteFile(testBinary, testData, 0755)
	require.NoError(t, err)
	
	// Create root command for testing
	rootCmd := createTestRootCommand()
	
	// Capture output
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	
	// Reset global variables
	outputFormat = "text"
	generateSBOM = true
	sbomFormat = "invalid"
	sbomOutput = sbomOutput
	
	// Test with invalid SBOM format
	args := []string{"check", testBinary, "--sbom", "--sbom-format", "invalid", "--sbom-output", sbomOutput}
	rootCmd.SetArgs(args)
	
	err = rootCmd.Execute()
	// Should exit with error due to invalid format
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid SBOM format")
	
	// SBOM file should not be created
	assert.NoFileExists(t, sbomOutput)
}

func TestSBOMGeneration_EmptyOutputPath(t *testing.T) {
	// Create a temporary test binary
	tempDir := t.TempDir()
	testBinary := filepath.Join(tempDir, "test-binary")
	
	// Create a simple test binary
	testData := createSimpleBinary()
	err := os.WriteFile(testBinary, testData, 0755)
	require.NoError(t, err)
	
	// Create root command for testing
	rootCmd := createTestRootCommand()
	
	// Capture output
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	
	// Reset global variables
	outputFormat = "text"
	generateSBOM = true
	sbomFormat = "cyclonedx"
	sbomOutput = ""
	
	// Test with empty SBOM output path
	args := []string{"check", testBinary, "--sbom", "--sbom-output", ""}
	rootCmd.SetArgs(args)
	
	err = rootCmd.Execute()
	// Should exit with error due to empty output path
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SBOM output path cannot be empty")
}

func TestSBOMGeneration_TextOutput(t *testing.T) {
	// Create a temporary test binary
	tempDir := t.TempDir()
	testBinary := filepath.Join(tempDir, "test-binary")
	sbomOutput := filepath.Join(tempDir, "test-sbom.json")
	
	// Create a simple test binary
	testData := createSimpleBinary()
	err := os.WriteFile(testBinary, testData, 0755)
	require.NoError(t, err)
	
	// Create root command for testing
	rootCmd := createTestRootCommand()
	
	// Capture output
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	
	// Reset global variables
	outputFormat = "text"
	generateSBOM = true
	sbomFormat = "cyclonedx"
	sbomOutput = sbomOutput
	
	// Test SBOM generation with text output format
	args := []string{"check", testBinary, "--sbom", "--sbom-format", "cyclonedx", "--sbom-output", sbomOutput, "--format", "text"}
	rootCmd.SetArgs(args)
	
	err = rootCmd.Execute()
	// CLI may exit with error if checks fail, but that's expected
	
	output := buf.String()
	
	// Verify SBOM file was created
	assert.FileExists(t, sbomOutput)
	
	// Verify text output contains SBOM path
	assert.Contains(t, output, "SBOM: "+sbomOutput)
	
	// Verify text output shows progress message
	assert.Contains(t, output, "and generating SBOM")
}

func TestSBOMGeneration_WithoutFlag(t *testing.T) {
	// Create a temporary test binary
	tempDir := t.TempDir()
	testBinary := filepath.Join(tempDir, "test-binary")
	
	// Create a simple test binary
	testData := createSimpleBinary()
	err := os.WriteFile(testBinary, testData, 0755)
	require.NoError(t, err)
	
	// Create root command for testing
	rootCmd := createTestRootCommand()
	
	// Capture output
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	
	// Reset global variables
	outputFormat = "json"
	generateSBOM = false
	sbomFormat = "cyclonedx"
	sbomOutput = "sbom.json"
	
	// Test without SBOM flag
	args := []string{"check", testBinary, "--format", "json"}
	rootCmd.SetArgs(args)
	
	err = rootCmd.Execute()
	// CLI may exit with error if checks fail, but that's expected
	
	output := buf.String()
	
	// Parse the JSON output if it's valid
	if output != "" {
		var report map[string]interface{}
		err = json.Unmarshal([]byte(output), &report)
		if err == nil {
			// Verify no SBOM path in report
			sbomPath, exists := report["sbom_path"]
			if exists {
				assert.Empty(t, sbomPath)
			}
		}
	}
}

func TestGenerateSBOMFile_DirectCall(t *testing.T) {
	// Create a temporary test binary
	tempDir := t.TempDir()
	testBinary := filepath.Join(tempDir, "test-binary")
	sbomOutput := filepath.Join(tempDir, "direct-test-sbom.json")
	
	// Create a simple test binary
	testData := createSimpleBinary()
	err := os.WriteFile(testBinary, testData, 0755)
	require.NoError(t, err)
	
	// Create a real logger for testing
	logger := utils.NewDefaultLogger()
	
	// Test direct call to generateSBOMFile
	resultPath, err := generateSBOMFile(testBinary, "cyclonedx", sbomOutput, logger)
	require.NoError(t, err)
	assert.Equal(t, sbomOutput, resultPath)
	
	// Verify file was created
	assert.FileExists(t, sbomOutput)
	
	// Verify content
	sbomData, err := os.ReadFile(sbomOutput)
	require.NoError(t, err)
	
	var sbomJSON map[string]interface{}
	err = json.Unmarshal(sbomData, &sbomJSON)
	require.NoError(t, err)
	assert.Equal(t, "CycloneDX", sbomJSON["bomFormat"])
	
	// Test with SPDX format
	spdxOutput := filepath.Join(tempDir, "direct-test-spdx.json")
	resultPath, err = generateSBOMFile(testBinary, "spdx", spdxOutput, logger)
	require.NoError(t, err)
	assert.Equal(t, spdxOutput, resultPath)
	
	// Verify SPDX file
	assert.FileExists(t, spdxOutput)
	spdxData, err := os.ReadFile(spdxOutput)
	require.NoError(t, err)
	
	var spdxJSON map[string]interface{}
	err = json.Unmarshal(spdxData, &spdxJSON)
	require.NoError(t, err)
	assert.Contains(t, spdxJSON["spdxVersion"], "SPDX-2.3")
}

func TestGenerateSBOMFile_InvalidFormat(t *testing.T) {
	// Create a temporary test binary
	tempDir := t.TempDir()
	testBinary := filepath.Join(tempDir, "test-binary")
	sbomOutput := filepath.Join(tempDir, "test-sbom.json")
	
	// Create a simple test binary
	testData := createSimpleBinary()
	err := os.WriteFile(testBinary, testData, 0755)
	require.NoError(t, err)
	
	// Create a real logger for testing
	logger := utils.NewDefaultLogger()
	
	// Test with invalid format
	_, err = generateSBOMFile(testBinary, "invalid", sbomOutput, logger)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported SBOM format")
	
	// Verify file was not created
	assert.NoFileExists(t, sbomOutput)
}

func TestGenerateSBOMFile_NonexistentBinary(t *testing.T) {
	// Create a temporary directory
	tempDir := t.TempDir()
	nonexistentBinary := filepath.Join(tempDir, "nonexistent-binary")
	sbomOutput := filepath.Join(tempDir, "test-sbom.json")
	
	// Create a real logger for testing
	logger := utils.NewDefaultLogger()
	
	// Test with nonexistent binary
	_, err := generateSBOMFile(nonexistentBinary, "cyclonedx", sbomOutput, logger)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate SBOM")
	
	// Verify file was not created
	assert.NoFileExists(t, sbomOutput)
}

// createTestRootCommand creates a root command for testing
func createTestRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "raven-linter",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			cmd.SetContext(context.Background())
			return nil
		},
	}

	checkCmd := newCheckCommand()
	rootCmd.AddCommand(checkCmd)
	return rootCmd
}