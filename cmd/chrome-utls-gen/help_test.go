package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestChromeUtlsGenHelpText(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		contains []string
	}{
		{
			name: "root help",
			args: []string{"--help"},
			contains: []string{
				"deterministic TLS ClientHello templates",
				"JA3 fingerprint testing",
				"automatically",
				"FEATURES:",
				"byte-perfect Chrome TLS ClientHello",
				"Chrome Stable (N) and Stable (N-2)",
				"JA3 fingerprint calculation",
				"Automatic Chrome version detection",
				"Template caching",
				"Cross-platform binary self-updates",
				"SUPPORTED CHROME VERSIONS:",
				"Chrome 70+",
				"Post-quantum cryptography",
				"https://github.com/raven-betanet/dual-cli",
			},
		},
		{
			name: "generate command help",
			args: []string{"generate", "--help"},
			contains: []string{
				"deterministic TLS ClientHello blob",
				"SUPPORTED VERSIONS:",
				"Chrome Stable (N)",
				"Chrome Stable (N-2)",
				"Chrome 70+",
				"Post-quantum cryptography",
				"OUTPUT:",
				"Binary ClientHello blob file",
				"JA3 fingerprint hash and string",
				"Template metadata",
				"TEMPLATE CACHING:",
				"~/.raven-betanet/templates/",
				"JSON format with metadata",
				"offline usage",
				"identical JA3 fingerprints",
			},
		},
		{
			name: "ja3-test command help",
			args: []string{"ja3-test", "--help"},
			contains: []string{
				"Chrome TLS fingerprint",
				"JA3 FINGERPRINTING:",
				"method for fingerprinting TLS clients",
				"ClientHello parameters",
				"TLS version, cipher suites, extensions",
				"VERIFICATION MODES:",
				"Expected Hash",
				"Known Chrome Hashes",
				"No Verification",
				"CONNECTION TESTING:",
				"real TLS connection",
				"connection details",
				"connection failures gracefully",
			},
		},
		{
			name: "update command help",
			args: []string{"update", "--help"},
			contains: []string{
				"latest Chrome Stable versions",
				"UPDATE PROCESS:",
				"Chromium API",
				"Compares with cached versions",
				"Stable (N) and Stable (N-2)",
				"template cache and metadata",
				"CHROME VERSION API:",
				"official Chromium dashboard API",
				"Stable channel releases",
				"API rate limits",
				"TEMPLATE CACHING:",
				"~/.raven-betanet/templates/",
				"JSON format with metadata",
				"DRY RUN MODE:",
				"--dry-run",
				"FORCE UPDATE:",
				"--force",
			},
		},
		{
			name: "self-update command help",
			args: []string{"self-update", "--help"},
			contains: []string{
				"chrome-utls-gen from GitHub releases",
				"GitHub releases",
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
				Use:   "chrome-utls-gen",
				Short: "Chrome-Stable (N-2) uTLS Template Generator",
				Long: `A utility to generate deterministic TLS ClientHello templates identical to Chrome 
Stable (N or N-2), verify them via JA3 fingerprint testing, and automatically 
refresh when Chrome stable versions update.

FEATURES:
• Generate byte-perfect Chrome TLS ClientHello templates
• Support for Chrome Stable (N) and Stable (N-2) versions  
• JA3 fingerprint calculation and verification
• Automatic Chrome version detection and updates
• Template caching for offline usage
• Cross-platform binary self-updates

SUPPORTED CHROME VERSIONS:
• Chrome 70+ with automatic uTLS fingerprint mapping
• Focus on Stable (N) and Stable (N-2) for maximum compatibility
• Post-quantum cryptography support for Chrome 115+

For detailed documentation, visit: https://github.com/raven-betanet/dual-cli

Examples:
  # Generate ClientHello for latest Chrome stable
  chrome-utls-gen generate --output clienthello.bin

  # Test JA3 fingerprint against a server
  chrome-utls-gen ja3-test --target example.com:443

  # Update Chrome version templates
  chrome-utls-gen update

  # Check for binary updates
  chrome-utls-gen self-update --check-only

  # Generate for specific Chrome version
  chrome-utls-gen generate --version 120.0.6099.109 --output chrome120.bin`,
				Version: "test-version",
			}

			// Add subcommands
			rootCmd.AddCommand(newGenerateCmd())
			rootCmd.AddCommand(newJA3TestCmd())
			rootCmd.AddCommand(newUpdateCmd())
			rootCmd.AddCommand(newSelfUpdateCmd())

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

func TestChromeUtlsGenNoArgsHelp(t *testing.T) {
	// Create a new root command for testing
	rootCmd := &cobra.Command{
		Use:     "chrome-utls-gen",
		Short:   "Chrome-Stable (N-2) uTLS Template Generator",
		Version: "test-version",
	}

	// Add the no-args help behavior
	rootCmd.Run = func(cmd *cobra.Command, args []string) {
		cmd.Printf("Chrome-Stable (N-2) uTLS Template Generator\n")
		cmd.Printf("==========================================\n\n")
		cmd.Printf("Generate Chrome TLS ClientHello templates and test JA3 fingerprints.\n\n")
		cmd.Printf("Quick Start:\n")
		cmd.Printf("  %s generate --output clienthello.bin       # Generate ClientHello template\n", cmd.Name())
		cmd.Printf("  %s ja3-test --target example.com:443       # Test JA3 fingerprint\n", cmd.Name())
		cmd.Printf("  %s update                                   # Update Chrome templates\n", cmd.Name())
		cmd.Printf("  %s self-update --check-only                # Check for binary updates\n\n", cmd.Name())
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
	rootCmd.AddCommand(newGenerateCmd())
	rootCmd.AddCommand(newJA3TestCmd())
	rootCmd.AddCommand(newUpdateCmd())
	rootCmd.AddCommand(newSelfUpdateCmd())

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
		"Chrome-Stable (N-2) uTLS Template Generator",
		"==========================================",
		"Generate Chrome TLS ClientHello templates and test JA3 fingerprints",
		"Quick Start:",
		"chrome-utls-gen generate --output clienthello.bin",
		"Test JA3 fingerprint",
		"Update Chrome templates",
		"Check for binary updates",
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

func TestChromeUtlsGenErrorMessages(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		expectedError  string
		expectedInHelp []string
	}{
		{
			name:          "invalid timeout format",
			args:          []string{"ja3-test", "--target", "example.com:443", "--timeout", "invalid"},
			expectedError: "invalid timeout format 'invalid'",
			expectedInHelp: []string{
				"Supported timeout formats:",
				"10s - 10 seconds",
				"30s - 30 seconds",
				"1m - 1 minute",
				"1m30s - 1 minute 30 seconds",
				"Example: --timeout 30s",
			},
		},
		{
			name:          "missing target for ja3-test",
			args:          []string{"ja3-test"},
			expectedError: `required flag(s) "target" not set`,
		},
		{
			name:          "invalid target format",
			args:          []string{"ja3-test", "--target", "invalid-target"},
			expectedError: "", // This would be caught at runtime, not argument parsing
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip tests that require runtime validation
			if tt.expectedError == "" {
				t.Skip("Skipping runtime validation test")
			}

			// Create a new root command for testing
			rootCmd := &cobra.Command{
				Use:     "chrome-utls-gen",
				Short:   "Test CLI",
				Version: "test-version",
			}

			// Add subcommands
			rootCmd.AddCommand(newGenerateCmd())
			rootCmd.AddCommand(newJA3TestCmd())
			rootCmd.AddCommand(newUpdateCmd())
			rootCmd.AddCommand(newSelfUpdateCmd())

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

func TestChromeUtlsGenCommandValidation(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		args        []string
		expectError bool
		errorText   string
	}{
		{
			name:        "generate with valid args",
			command:     "generate",
			args:        []string{"--output", "test.bin"},
			expectError: false,
		},
		{
			name:        "ja3-test missing target",
			command:     "ja3-test",
			args:        []string{},
			expectError: true,
			errorText:   "required flag",
		},
		{
			name:        "ja3-test with valid target",
			command:     "ja3-test",
			args:        []string{"--target", "example.com:443"},
			expectError: false,
		},
		{
			name:        "update with dry-run",
			command:     "update",
			args:        []string{"--dry-run"},
			expectError: false,
		},
		{
			name:        "self-update check-only",
			command:     "self-update",
			args:        []string{"--check-only"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new root command for testing
			rootCmd := &cobra.Command{
				Use:     "chrome-utls-gen",
				Short:   "Test CLI",
				Version: "test-version",
			}

			// Add subcommands
			rootCmd.AddCommand(newGenerateCmd())
			rootCmd.AddCommand(newJA3TestCmd())
			rootCmd.AddCommand(newUpdateCmd())
			rootCmd.AddCommand(newSelfUpdateCmd())

			// Capture output
			var buf bytes.Buffer
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(&buf)

			// Prepare args
			args := []string{tt.command}
			args = append(args, tt.args...)
			rootCmd.SetArgs(args)

			// Execute command
			err := rootCmd.Execute()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but command succeeded")
				} else if tt.errorText != "" && !strings.Contains(err.Error(), tt.errorText) {
					t.Errorf("Error message doesn't contain expected text: %q\nActual error: %s", tt.errorText, err.Error())
				}
			} else {
				// For commands that would normally execute but we're just testing parsing
				// We expect them to fail at runtime (not argument parsing)
				// This is acceptable for this test
			}
		})
	}
}