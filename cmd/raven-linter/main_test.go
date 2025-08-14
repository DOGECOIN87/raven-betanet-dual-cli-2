package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootCommand(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		expectError    bool
		expectHelpText bool
	}{
		{
			name:           "no arguments shows help",
			args:           []string{},
			expectError:    false,
			expectHelpText: true,
		},
		{
			name:        "version flag",
			args:        []string{"--version"},
			expectError: false,
		},
		{
			name:        "help flag",
			args:        []string{"--help"},
			expectError: false,
		},
		{
			name:        "invalid flag",
			args:        []string{"--invalid-flag"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create root command
			rootCmd := &cobra.Command{
				Use:   "raven-linter",
				Short: "Raven Betanet 1.1 Spec-Compliance Linter CLI",
				Long: `A command-line utility to run all 11 compliance checks described in §11 
of the Raven Betanet 1.1 spec against a candidate binary, generate a Software 
Bill of Materials (SBOM), and integrate into CI/CD via GitHub Actions.`,
				Version: "test-version",
			}

			// Add persistent flags
			rootCmd.PersistentFlags().String("log-level", "info", "Set log level")
			rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")

			// Add check command
			rootCmd.AddCommand(newCheckCommand())

			// Show help when run without arguments
			rootCmd.Run = func(cmd *cobra.Command, args []string) {
				cmd.Help()
			}

			// Capture output
			var buf bytes.Buffer
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(&buf)

			// Set args and execute
			rootCmd.SetArgs(tt.args)
			err := rootCmd.Execute()

			// Check error expectation
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check help text expectation
			output := buf.String()
			if tt.expectHelpText && !strings.Contains(output, "Usage:") {
				t.Errorf("expected help text but didn't find it in output: %s", output)
			}
		})
	}
}

func TestCheckCommand(t *testing.T) {
	// Create a temporary test binary file
	tempDir := t.TempDir()
	testBinary := filepath.Join(tempDir, "test-binary")
	if err := os.WriteFile(testBinary, []byte("test binary content"), 0755); err != nil {
		t.Fatalf("failed to create test binary: %v", err)
	}

	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "no arguments",
			args:        []string{"check"},
			expectError: true,
			errorMsg:    "accepts 1 arg(s), received 0",
		},
		{
			name:        "too many arguments",
			args:        []string{"check", "binary1", "binary2"},
			expectError: true,
			errorMsg:    "accepts 1 arg(s), received 2",
		},
		{
			name:        "valid binary path with default format",
			args:        []string{"check", testBinary},
			expectError: true, // Expected to fail since no checks are registered yet
			errorMsg:    "no checks to run",
		},
		{
			name:        "valid binary path with json format",
			args:        []string{"check", testBinary, "--format", "json"},
			expectError: true, // Expected to fail since no checks are registered yet
			errorMsg:    "no checks to run",
		},
		{
			name:        "valid binary path with text format",
			args:        []string{"check", testBinary, "--format", "text"},
			expectError: true, // Expected to fail since no checks are registered yet
			errorMsg:    "no checks to run",
		},
		{
			name:        "invalid output format",
			args:        []string{"check", testBinary, "--format", "xml"},
			expectError: true,
			errorMsg:    "invalid output format: xml",
		},
		{
			name:        "nonexistent binary",
			args:        []string{"check", "/nonexistent/binary"},
			expectError: true,
			errorMsg:    "binary file not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global variables
			outputFormat = "text"

			// Create root command with check subcommand
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

			// Set args and execute
			rootCmd.SetArgs(tt.args)
			err := rootCmd.Execute()

			// Check error expectation
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error message to contain %q, got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestOutputFormatValidation(t *testing.T) {
	tests := []struct {
		format string
		valid  bool
	}{
		{"json", true},
		{"text", true},
		{"JSON", true},
		{"TEXT", true},
		{"xml", false},
		{"yaml", false},
		{"", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			result := isValidOutputFormat(tt.format)
			if result != tt.valid {
				t.Errorf("isValidOutputFormat(%q) = %v, want %v", tt.format, result, tt.valid)
			}
		})
	}
}

func TestCheckCommandFlags(t *testing.T) {
	cmd := newCheckCommand()

	// Test that format flag exists and has correct default
	formatFlag := cmd.Flags().Lookup("format")
	if formatFlag == nil {
		t.Error("format flag not found")
	} else {
		if formatFlag.DefValue != "text" {
			t.Errorf("format flag default value = %q, want %q", formatFlag.DefValue, "text")
		}
		if formatFlag.Shorthand != "f" {
			t.Errorf("format flag shorthand = %q, want %q", formatFlag.Shorthand, "f")
		}
	}

	// Test flag parsing
	cmd.SetArgs([]string{"--format", "json", "dummy-binary"})
	err := cmd.ParseFlags([]string{"--format", "json"})
	if err != nil {
		t.Errorf("failed to parse flags: %v", err)
	}

	if outputFormat != "json" {
		t.Errorf("outputFormat = %q, want %q", outputFormat, "json")
	}
}

func TestRootCommandPersistentFlags(t *testing.T) {
	rootCmd := &cobra.Command{Use: "raven-linter"}
	
	// Add persistent flags like in main
	rootCmd.PersistentFlags().String("log-level", "info", "Set log level")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")

	// Test log-level flag
	logLevelFlag := rootCmd.PersistentFlags().Lookup("log-level")
	if logLevelFlag == nil {
		t.Error("log-level flag not found")
	} else if logLevelFlag.DefValue != "info" {
		t.Errorf("log-level flag default = %q, want %q", logLevelFlag.DefValue, "info")
	}

	// Test verbose flag
	verboseFlag := rootCmd.PersistentFlags().Lookup("verbose")
	if verboseFlag == nil {
		t.Error("verbose flag not found")
	} else {
		if verboseFlag.DefValue != "false" {
			t.Errorf("verbose flag default = %q, want %q", verboseFlag.DefValue, "false")
		}
		if verboseFlag.Shorthand != "v" {
			t.Errorf("verbose flag shorthand = %q, want %q", verboseFlag.Shorthand, "v")
		}
	}
}