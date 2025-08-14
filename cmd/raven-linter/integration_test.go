package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/raven-betanet/dual-cli/internal/checks"
)

// TestCLIIntegrationWithSampleBinaries tests the complete CLI workflow with sample binaries
func TestCLIIntegrationWithSampleBinaries(t *testing.T) {
	// Create temporary directory for test binaries
	tempDir := t.TempDir()

	// Create different types of test binaries
	testBinaries := map[string][]byte{
		"simple_binary":    createSimpleBinary(),
		"elf_binary":      createELFBinary(),
		"empty_file":      []byte{},
		"text_file":       []byte("This is just a text file, not a binary"),
	}

	for name, content := range testBinaries {
		binaryPath := filepath.Join(tempDir, name)
		if err := os.WriteFile(binaryPath, content, 0755); err != nil {
			t.Fatalf("Failed to create test binary %s: %v", name, err)
		}
	}

	tests := []struct {
		name           string
		binaryName     string
		format         string
		expectError    bool
		expectChecks   int
		validateOutput func(t *testing.T, output string, format string)
	}{
		{
			name:         "simple binary with text output",
			binaryName:   "simple_binary",
			format:       "text",
			expectError:  false,
			expectChecks: 11,
			validateOutput: func(t *testing.T, output string, format string) {
				if !strings.Contains(output, "Raven Betanet 1.1 Compliance Report") {
					t.Error("Expected compliance report header in text output")
				}
				if !strings.Contains(output, "CHECK ID") {
					t.Error("Expected check results table in text output")
				}
			},
		},
		{
			name:         "simple binary with JSON output",
			binaryName:   "simple_binary",
			format:       "json",
			expectError:  false,
			expectChecks: 11,
			validateOutput: func(t *testing.T, output string, format string) {
				var report checks.ComplianceReport
				if err := json.Unmarshal([]byte(output), &report); err != nil {
					t.Errorf("Failed to parse JSON output: %v", err)
					return
				}
				if report.TotalChecks != 11 {
					t.Errorf("Expected 11 checks, got %d", report.TotalChecks)
				}
				if len(report.Results) != 11 {
					t.Errorf("Expected 11 check results, got %d", len(report.Results))
				}
			},
		},
		{
			name:         "ELF binary",
			binaryName:   "elf_binary",
			format:       "text",
			expectError:  false,
			expectChecks: 11,
			validateOutput: func(t *testing.T, output string, format string) {
				if !strings.Contains(output, "Binary:") {
					t.Error("Expected binary path in output")
				}
				if !strings.Contains(output, "Hash:") {
					t.Error("Expected binary hash in output")
				}
			},
		},
		{
			name:         "empty file",
			binaryName:   "empty_file",
			format:       "text",
			expectError:  false,
			expectChecks: 11,
			validateOutput: func(t *testing.T, output string, format string) {
				// Empty file should still run all checks, but many will fail
				if !strings.Contains(output, "Summary:") {
					t.Error("Expected summary in output")
				}
			},
		},
		{
			name:         "text file (not a binary)",
			binaryName:   "text_file",
			format:       "text",
			expectError:  false,
			expectChecks: 11,
			validateOutput: func(t *testing.T, output string, format string) {
				// Text file should run checks but many will fail
				if !strings.Contains(output, "Summary:") {
					t.Error("Expected summary in output")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binaryPath := filepath.Join(tempDir, tt.binaryName)

			// Create root command for testing
			rootCmd := &cobra.Command{
				Use: "raven-linter",
				PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
					// Set a basic context for testing
					cmd.SetContext(context.Background())
					return nil
				},
			}

			checkCmd := newCheckCommand()
			rootCmd.AddCommand(checkCmd)

			// Capture output
			var buf bytes.Buffer
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(&buf)

			// Reset global variables
			outputFormat = tt.format

			// Set args and execute
			args := []string{"check", binaryPath}
			if tt.format != "text" {
				args = append(args, "--format", tt.format)
			}
			rootCmd.SetArgs(args)

			err := rootCmd.Execute()

			// Check error expectation
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				// For integration tests, we don't expect CLI errors, but checks may fail
				// The CLI exits with status 1 when compliance checks fail, which is expected behavior
				// We only care that the CLI ran successfully and produced output
				t.Logf("CLI exited with error (expected for failing checks): %v", err)
			}

			output := buf.String()
			if tt.validateOutput != nil {
				tt.validateOutput(t, output, tt.format)
			}
		})
	}
}

// TestCLIErrorHandling tests error handling scenarios
func TestCLIErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nonexistent binary",
			args:        []string{"check", "/nonexistent/binary"},
			expectError: true,
			errorMsg:    "binary file not found",
		},
		{
			name:        "invalid format",
			args:        []string{"check", "dummy", "--format", "xml"},
			expectError: true,
			errorMsg:    "invalid output format",
		},
		{
			name:        "directory instead of file",
			args:        []string{"check", "."},
			expectError: true,
			errorMsg:    "path is a directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create root command for testing
			rootCmd := &cobra.Command{
				Use: "raven-linter",
				PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
					cmd.SetContext(context.Background())
					return nil
				},
			}

			checkCmd := newCheckCommand()
			rootCmd.AddCommand(checkCmd)

			// Capture output
			var buf bytes.Buffer
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(&buf)

			// Reset global variables
			outputFormat = "text"

			// Set args and execute
			rootCmd.SetArgs(tt.args)
			err := rootCmd.Execute()

			// Check error expectation
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain %q, got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestCLIExitCodes tests that the CLI exits with correct codes
func TestCLIExitCodes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping exit code tests in short mode")
	}

	// Create a test binary
	tempDir := t.TempDir()
	testBinary := filepath.Join(tempDir, "test_binary")
	if err := os.WriteFile(testBinary, createSimpleBinary(), 0755); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	// Build the CLI binary for testing
	cliBinary := filepath.Join(tempDir, "raven-linter")
	buildCmd := exec.Command("go", "build", "-o", cliBinary, ".")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build CLI binary: %v", err)
	}

	tests := []struct {
		name           string
		args           []string
		expectedExit   int
		checkOutput    func(t *testing.T, output string)
	}{
		{
			name:         "successful check",
			args:         []string{"check", testBinary, "--format", "json"},
			expectedExit: 0, // May be 1 if checks fail, but CLI should work
			checkOutput: func(t *testing.T, output string) {
				// Should contain valid JSON
				var report checks.ComplianceReport
				if err := json.Unmarshal([]byte(output), &report); err != nil {
					t.Errorf("Output is not valid JSON: %v", err)
				}
			},
		},
		{
			name:         "help command",
			args:         []string{"--help"},
			expectedExit: 0,
			checkOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "Usage:") {
					t.Error("Help output should contain usage information")
				}
			},
		},
		{
			name:         "version command",
			args:         []string{"--version"},
			expectedExit: 0,
			checkOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "dev") {
					t.Error("Version output should contain version information")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(cliBinary, tt.args...)
			output, err := cmd.CombinedOutput()

			// Check exit code
			if exitError, ok := err.(*exec.ExitError); ok {
				exitCode := exitError.ExitCode()
				// For compliance checks, we may get exit code 1 if checks fail
				// This is expected behavior, not a CLI error
				if tt.name == "successful check" && (exitCode == 0 || exitCode == 1) {
					// Both are acceptable for check command
				} else if exitCode != tt.expectedExit {
					t.Errorf("Expected exit code %d, got %d", tt.expectedExit, exitCode)
				}
			} else if err != nil && tt.expectedExit != 0 {
				t.Errorf("Expected exit code %d but command failed with: %v", tt.expectedExit, err)
			}

			// Validate output
			if tt.checkOutput != nil {
				tt.checkOutput(t, string(output))
			}
		})
	}
}

// createSimpleBinary creates a simple test binary with some recognizable content
func createSimpleBinary() []byte {
	// Create a simple binary-like content with some strings that checks might find
	content := []byte{
		// Add some binary-like header
		0x7F, 0x45, 0x4C, 0x46, // ELF magic
		0x02, 0x01, 0x01, 0x00, // 64-bit, little-endian, current version
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
	}
	
	// Add some strings that various checks might look for
	content = append(content, []byte("Copyright 2024 Test Company")...)
	content = append(content, 0x00) // null terminator
	content = append(content, []byte("MIT License")...)
	content = append(content, 0x00)
	content = append(content, []byte("version 1.0.0")...)
	content = append(content, 0x00)
	content = append(content, []byte("__stack_chk_fail")...) // Stack canary symbol
	content = append(content, 0x00)
	
	// Add some padding to make it look more like a real binary
	padding := make([]byte, 1024)
	content = append(content, padding...)
	
	return content
}

// createELFBinary creates a more realistic ELF binary header
func createELFBinary() []byte {
	// Create a minimal ELF header
	content := []byte{
		// ELF header
		0x7F, 0x45, 0x4C, 0x46, // ELF magic
		0x02,                   // 64-bit
		0x01,                   // little-endian
		0x01,                   // current version
		0x00,                   // System V ABI
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
		0x02, 0x00, // executable file
		0x3E, 0x00, // x86-64
		0x01, 0x00, 0x00, 0x00, // version 1
		0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // entry point
		0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // program header offset
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // section header offset
		0x00, 0x00, 0x00, 0x00, // flags
		0x40, 0x00, // ELF header size
		0x38, 0x00, // program header size
		0x00, 0x00, // program header count
		0x40, 0x00, // section header size
		0x00, 0x00, // section header count
		0x00, 0x00, // section header string table index
	}
	
	// Add some content to make it more realistic
	content = append(content, []byte("This is a test ELF binary")...)
	content = append(content, 0x00)
	
	// Add padding
	padding := make([]byte, 512)
	content = append(content, padding...)
	
	return content
}