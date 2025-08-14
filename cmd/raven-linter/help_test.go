package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRavenLinterHelpText(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		contains []string
	}{
		{
			name: "root help",
			args: []string{"--help"},
			contains: []string{
				"11 compliance checks",
				"SBOM",
				"Examples:",
				"raven-linter check ./my-binary",
				"--format json",
				"--sbom",
				"--verbose",
				"https://github.com/raven-betanet/dual-cli",
				"Binary analysis",
				"Cryptographic validation",
				"Security and metadata checks",
			},
		},
		{
			name: "check command help",
			args: []string{"check", "--help"},
			contains: []string{
				"Run all 11 compliance checks",
				"COMPLIANCE CHECKS:",
				"Binary Analysis (1-4):",
				"File signature validation",
				"Binary metadata extraction",
				"Dependency analysis",
				"Binary format compliance",
				"Cryptographic Validation (5-8):",
				"Certificate validation",
				"Signature verification",
				"Hash integrity checks",
				"Encryption standard compliance",
				"Security & Metadata (9-11):",
				"Security flag validation",
				"Version information extraction",
				"License compliance verification",
				"OUTPUT FORMATS:",
				"text - Human-readable",
				"json - Machine-readable",
				"SBOM GENERATION:",
				"cyclonedx - CycloneDX v1.5",
				"spdx - SPDX 2.3",
				"EXIT CODES:",
				"0 - All compliance checks passed",
				"1 - One or more compliance checks failed",
				"2 - Invalid arguments",
			},
		},
		{
			name: "update command help",
			args: []string{"update", "--help"},
			contains: []string{
				"Check for and install the latest version",
				"GitHub releases API",
				"--check-only",
				"--force",
				"backup of the current binary",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new root command for testing
			rootCmd := &cobra.Command{
				Use:   "raven-linter",
				Short: "Raven Betanet 1.1 Spec-Compliance Linter CLI",
				Long: `A command-line utility to run all 11 compliance checks described in §11 
of the Raven Betanet 1.1 spec against a candidate binary, generate a Software 
Bill of Materials (SBOM), and integrate into CI/CD via GitHub Actions.

The tool validates binaries against mandatory compliance requirements including:
• Binary analysis (file signature, metadata, dependencies, format)
• Cryptographic validation (certificates, signatures, hashes, encryption)
• Security and metadata checks (flags, version info, license compliance)

For detailed documentation, visit: https://github.com/raven-betanet/dual-cli

Examples:
  # Run all compliance checks on a binary
  raven-linter check ./my-binary

  # Output results in JSON format for CI/CD integration
  raven-linter check ./my-binary --format json

  # Generate SBOM alongside compliance checks
  raven-linter check ./my-binary --sbom --sbom-format cyclonedx

  # Enable verbose logging for troubleshooting
  raven-linter check ./my-binary --verbose

  # Check for updates
  raven-linter update --check-only`,
				Version: "test-version",
			}

			// Add subcommands
			rootCmd.AddCommand(newCheckCommand())
			rootCmd.AddCommand(newUpdateCommand())

			// Capture output
			var buf bytes.Buffer
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(&buf)
			rootCmd.SetArgs(tt.args)

			// Execute command
			err := rootCmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			output := buf.String()

			// Check that all expected strings are present
			for _, expected := range tt.contains {
				if !strings.Contains(output, expected) {
					t.Errorf("Help output missing expected text: %q\nFull output:\n%s", expected, output)
				}
			}
		})
	}
}

func TestRavenLinterNoArgsHelp(t *testing.T) {
	// Create a new root command for testing
	rootCmd := &cobra.Command{
		Use:   "raven-linter",
		Short: "Raven Betanet 1.1 Spec-Compliance Linter CLI",
		Version: "test-version",
	}

	// Add the no-args help behavior
	rootCmd.Run = func(cmd *cobra.Command, args []string) {
		cmd.Printf("Raven Betanet 1.1 Spec-Compliance Linter\n")
		cmd.Printf("=========================================\n\n")
		cmd.Printf("Run compliance checks against binaries and generate SBOMs.\n\n")
		cmd.Printf("Quick Start:\n")
		cmd.Printf("  %s check ./my-binary                    # Run all compliance checks\n", cmd.Name())
		cmd.Printf("  %s check ./my-binary --format json     # JSON output for CI/CD\n", cmd.Name())
		cmd.Printf("  %s check ./my-binary --sbom             # Generate SBOM\n", cmd.Name())
		cmd.Printf("  %s update                               # Check for updates\n\n", cmd.Name())
		cmd.Printf("For detailed help: %s --help\n", cmd.Name())
		cmd.Printf("For command help: %s <command> --help\n\n", cmd.Name())
		cmd.Printf("Available Commands:\n")
		for _, subCmd := range cmd.Commands() {
			if !subCmd.Hidden {
				cmd.Printf("  %-12s %s\n", subCmd.Name(), subCmd.Short)
			}
		}
		cmd.Printf("\nDocumentation: https://github.com/raven-betanet/dual-cli\n")
	}

	// Add subcommands
	rootCmd.AddCommand(newCheckCommand())
	rootCmd.AddCommand(newUpdateCommand())

	// Capture output
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{})

	// Execute command
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	output := buf.String()

	expectedStrings := []string{
		"Raven Betanet 1.1 Spec-Compliance Linter",
		"=========================================",
		"Run compliance checks against binaries and generate SBOMs",
		"Quick Start:",
		"raven-linter check ./my-binary",
		"JSON output for CI/CD",
		"Generate SBOM",
		"Check for updates",
		"For detailed help:",
		"Available Commands:",
		"Documentation: https://github.com/raven-betanet/dual-cli",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("No-args help output missing expected text: %q\nFull output:\n%s", expected, output)
		}
	}
}

func TestRavenLinterErrorMessages(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		expectedError  string
		expectedInHelp []string
	}{
		{
			name:          "invalid output format",
			args:          []string{"check", "test-binary", "--format", "xml"},
			expectedError: "invalid output format 'xml'",
			expectedInHelp: []string{
				"Supported formats:",
				"json - Machine-readable JSON",
				"text - Human-readable formatted",
				"Example: --format json",
			},
		},
		{
			name:          "invalid SBOM format",
			args:          []string{"check", "test-binary", "--sbom", "--sbom-format", "xml"},
			expectedError: "invalid SBOM format 'xml'",
			expectedInHelp: []string{
				"Supported SBOM formats:",
				"cyclonedx - CycloneDX v1.5 JSON",
				"spdx - SPDX 2.3 JSON",
				"Example: --sbom-format spdx",
			},
		},
		{
			name:          "empty SBOM output path",
			args:          []string{"check", "test-binary", "--sbom", "--sbom-output", ""},
			expectedError: "SBOM output path cannot be empty",
			expectedInHelp: []string{
				"Please specify an output path:",
				"Example: --sbom-output ./my-sbom.json",
			},
		},
		{
			name:          "missing binary argument",
			args:          []string{"check"},
			expectedError: "accepts 1 arg(s), received 0",
		},
		{
			name:          "too many arguments",
			args:          []string{"check", "binary1", "binary2"},
			expectedError: "accepts 1 arg(s), received 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new root command for testing
			rootCmd := &cobra.Command{
				Use:     "raven-linter",
				Short:   "Test CLI",
				Version: "test-version",
			}

			// Add subcommands
			rootCmd.AddCommand(newCheckCommand())

			// Capture output
			var buf bytes.Buffer
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(&buf)
			rootCmd.SetArgs(tt.args)

			// Execute command and expect error
			err := rootCmd.Execute()
			if err == nil {
				t.Fatalf("Expected error but command succeeded")
			}

			errorMsg := err.Error()

			// Check that the error contains expected text
			if !strings.Contains(errorMsg, tt.expectedError) {
				t.Errorf("Error message doesn't contain expected text: %q\nActual error: %s", tt.expectedError, errorMsg)
			}

			// Check for helpful information in error message
			for _, helpText := range tt.expectedInHelp {
				if !strings.Contains(errorMsg, helpText) {
					t.Errorf("Error message missing helpful text: %q\nActual error: %s", helpText, errorMsg)
				}
			}
		})
	}
}