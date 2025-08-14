package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootCommand(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "help flag",
			args:     []string{"--help"},
			wantErr:  false,
			contains: "A utility to generate a deterministic TLS ClientHello identical to Chrome",
		},
		{
			name:     "version flag",
			args:     []string{"--version"},
			wantErr:  false,
			contains: "dev",
		},
		{
			name:     "invalid flag",
			args:     []string{"--invalid"},
			wantErr:  true,
			contains: "unknown flag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create root command for testing
			rootCmd := &cobra.Command{
				Use:   "chrome-utls-gen",
				Short: "Chrome-Stable (N-2) uTLS Template Generator",
				Long: `A utility to generate a deterministic TLS ClientHello identical to Chrome 
Stable (N or N-2), verify it via JA3 fingerprint self-test, and auto-refresh 
when Chrome stable tags update.`,
				Version: "dev (commit: unknown, built: unknown)",
			}

			// Add global flags
			rootCmd.PersistentFlags().String("config", "", "config file")
			rootCmd.PersistentFlags().String("log-level", "info", "log level")
			rootCmd.PersistentFlags().String("log-format", "text", "log format")
			rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")

			// Add subcommands
			rootCmd.AddCommand(newGenerateCmd())
			rootCmd.AddCommand(newJA3TestCmd())
			rootCmd.AddCommand(newUpdateCmd())

			// Capture output
			var buf bytes.Buffer
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(&buf)

			// Set args and execute
			rootCmd.SetArgs(tt.args)
			err := rootCmd.Execute()

			// Check error expectation
			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check output contains expected string
			output := buf.String()
			if tt.contains != "" && !strings.Contains(output, tt.contains) {
				t.Errorf("output should contain %q, got: %s", tt.contains, output)
			}
		})
	}
}

// captureStdout captures stdout during function execution
func captureStdout(fn func() error) (string, error) {
	// Save original stdout
	originalStdout := os.Stdout
	
	// Create a pipe to capture output
	r, w, _ := os.Pipe()
	os.Stdout = w
	
	// Channel to capture the output
	outputChan := make(chan string)
	
	// Start goroutine to read from pipe
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outputChan <- buf.String()
	}()
	
	// Execute the function
	err := fn()
	
	// Close writer and restore stdout
	w.Close()
	os.Stdout = originalStdout
	
	// Get the captured output
	output := <-outputChan
	
	return output, err
}

func TestGenerateCommand(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "help flag",
			args:     []string{"generate", "--help"},
			wantErr:  false,
			contains: "Generate a deterministic TLS ClientHello blob identical to Chrome Stable",
		},
		{
			name:     "default output",
			args:     []string{"generate"},
			wantErr:  false,
			contains: "Generated ClientHello for Chrome",
		},
		{
			name:     "custom output file",
			args:     []string{"generate", "--output", "test.bin"},
			wantErr:  false,
			contains: "Output file: test.bin",
		},
		{
			name:     "specific version",
			args:     []string{"generate", "--version", "120.0.6099.109"},
			wantErr:  false,
			contains: "Generated ClientHello for Chrome 120.0.6099.109",
		},
		{
			name:     "custom cache directory",
			args:     []string{"generate", "--cache", "./templates"},
			wantErr:  false,
			contains: "Generated ClientHello for Chrome",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newGenerateCmd()

			var output string
			var err error

			if len(tt.args) > 1 && tt.args[1] == "--help" {
				// For help flag, capture command output buffer
				var buf bytes.Buffer
				cmd.SetOut(&buf)
				cmd.SetErr(&buf)
				cmd.SetArgs(tt.args[1:])
				err = cmd.Execute()
				output = buf.String()
			} else {
				// For actual command execution, capture stdout
				output, err = captureStdout(func() error {
					cmd.SetArgs(tt.args[1:])
					return cmd.Execute()
				})
			}

			// Check error expectation
			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check output contains expected string
			if tt.contains != "" && !strings.Contains(output, tt.contains) {
				t.Errorf("output should contain %q, got: %s", tt.contains, output)
			}
		})
	}
}

func TestJA3TestCommand(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "help flag",
			args:     []string{"ja3-test", "--help"},
			wantErr:  false,
			contains: "Connect to a target server using Chrome TLS fingerprint",
		},
		{
			name:     "missing target",
			args:     []string{"ja3-test"},
			wantErr:  true,
			contains: "required flag(s) \"target\" not set",
		},
		{
			name:     "valid target",
			args:     []string{"ja3-test", "--target", "example.com:443"},
			wantErr:  false,
			contains: "Target: example.com:443",
		},
		{
			name:     "with version",
			args:     []string{"ja3-test", "--target", "example.com:443", "--version", "120.0.6099.109"},
			wantErr:  false,
			contains: "Chrome version: 120.0.6099.109",
		},
		{
			name:     "with timeout",
			args:     []string{"ja3-test", "--target", "example.com:443", "--timeout", "30s"},
			wantErr:  false,
			contains: "Timeout: 30s",
		},
		{
			name:     "with expected JA3",
			args:     []string{"ja3-test", "--target", "example.com:443", "--expected", "cd08e31494f9531f560d64c695473da9"},
			wantErr:  false,
			contains: "Expected JA3: cd08e31494f9531f560d64c695473da9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newJA3TestCmd()

			var output string
			var err error

			if len(tt.args) > 1 && tt.args[1] == "--help" {
				// For help flag, capture command output buffer
				var buf bytes.Buffer
				cmd.SetOut(&buf)
				cmd.SetErr(&buf)
				cmd.SetArgs(tt.args[1:])
				err = cmd.Execute()
				output = buf.String()
			} else if tt.wantErr {
				// For error cases, capture command output buffer
				var buf bytes.Buffer
				cmd.SetOut(&buf)
				cmd.SetErr(&buf)
				cmd.SetArgs(tt.args[1:])
				err = cmd.Execute()
				output = buf.String()
			} else {
				// For actual command execution, capture stdout
				output, err = captureStdout(func() error {
					cmd.SetArgs(tt.args[1:])
					return cmd.Execute()
				})
			}

			// Check error expectation
			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check output contains expected string
			if tt.contains != "" && !strings.Contains(output, tt.contains) {
				t.Errorf("output should contain %q, got: %s", tt.contains, output)
			}
		})
	}
}

func TestUpdateCommand(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "help flag",
			args:     []string{"update", "--help"},
			wantErr:  false,
			contains: "Fetch the latest Chrome Stable versions and regenerate ClientHello templates",
		},
		{
			name:     "default update",
			args:     []string{"update"},
			wantErr:  false,
			contains: "Chrome Version Update Status",
		},
		{
			name:     "force update",
			args:     []string{"update", "--force"},
			wantErr:  false,
			contains: "Force Update: true",
		},
		{
			name:     "dry run",
			args:     []string{"update", "--dry-run"},
			wantErr:  false,
			contains: "Dry Run: true",
		},
		{
			name:     "custom cache directory",
			args:     []string{"update", "--cache", "./templates"},
			wantErr:  false,
			contains: "Template Cache Directory: ./templates",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newUpdateCmd()

			var output string
			var err error

			if len(tt.args) > 1 && tt.args[1] == "--help" {
				// For help flag, capture command output buffer
				var buf bytes.Buffer
				cmd.SetOut(&buf)
				cmd.SetErr(&buf)
				cmd.SetArgs(tt.args[1:])
				err = cmd.Execute()
				output = buf.String()
			} else {
				// For actual command execution, capture stdout
				output, err = captureStdout(func() error {
					cmd.SetArgs(tt.args[1:])
					return cmd.Execute()
				})
			}

			// Check error expectation
			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check output contains expected string
			if tt.contains != "" && !strings.Contains(output, tt.contains) {
				t.Errorf("output should contain %q, got: %s", tt.contains, output)
			}
		})
	}
}

func TestArgumentParsing(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		args        []string
		expectFlags map[string]string
	}{
		{
			name:    "generate with all flags",
			command: "generate",
			args:    []string{"--output", "test.bin", "--version", "120.0.6099.109", "--cache", "./templates"},
			expectFlags: map[string]string{
				"output":  "test.bin",
				"version": "120.0.6099.109",
				"cache":   "./templates",
			},
		},
		{
			name:    "ja3-test with all flags",
			command: "ja3-test",
			args:    []string{"--target", "example.com:443", "--version", "120.0.6099.109", "--timeout", "30s", "--expected", "abc123"},
			expectFlags: map[string]string{
				"target":   "example.com:443",
				"version":  "120.0.6099.109",
				"timeout":  "30s",
				"expected": "abc123",
			},
		},
		{
			name:    "update with all flags",
			command: "update",
			args:    []string{"--force", "--cache", "./templates", "--dry-run"},
			expectFlags: map[string]string{
				"force":   "true",
				"cache":   "./templates",
				"dry-run": "true",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cmd *cobra.Command
			switch tt.command {
			case "generate":
				cmd = newGenerateCmd()
			case "ja3-test":
				cmd = newJA3TestCmd()
			case "update":
				cmd = newUpdateCmd()
			default:
				t.Fatalf("unknown command: %s", tt.command)
			}

			// Parse flags
			cmd.SetArgs(tt.args)
			err := cmd.ParseFlags(tt.args)
			if err != nil {
				t.Fatalf("failed to parse flags: %v", err)
			}

			// Check flag values
			for flagName, expectedValue := range tt.expectFlags {
				flag := cmd.Flags().Lookup(flagName)
				if flag == nil {
					t.Errorf("flag %s not found", flagName)
					continue
				}

				actualValue := flag.Value.String()
				if actualValue != expectedValue {
					t.Errorf("flag %s: expected %q, got %q", flagName, expectedValue, actualValue)
				}
			}
		})
	}
}

func TestGlobalFlags(t *testing.T) {
	// Save original args
	originalArgs := os.Args

	tests := []struct {
		name     string
		args     []string
		expected map[string]interface{}
	}{
		{
			name: "verbose flag sets log level",
			args: []string{"chrome-utls-gen", "--verbose", "generate"},
			expected: map[string]interface{}{
				"verbose": true,
			},
		},
		{
			name: "log level flag",
			args: []string{"chrome-utls-gen", "--log-level", "debug", "generate"},
			expected: map[string]interface{}{
				"log-level": "debug",
			},
		},
		{
			name: "log format flag",
			args: []string{"chrome-utls-gen", "--log-format", "json", "generate"},
			expected: map[string]interface{}{
				"log-format": "json",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set test args
			os.Args = tt.args

			// Create root command
			rootCmd := &cobra.Command{
				Use: "chrome-utls-gen",
			}

			// Add global flags
			rootCmd.PersistentFlags().String("config", "", "config file")
			rootCmd.PersistentFlags().String("log-level", "info", "log level")
			rootCmd.PersistentFlags().String("log-format", "text", "log format")
			rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")

			// Add a dummy subcommand
			rootCmd.AddCommand(&cobra.Command{
				Use: "generate",
				Run: func(cmd *cobra.Command, args []string) {},
			})

			// Parse flags
			rootCmd.SetArgs(tt.args[1:])
			err := rootCmd.ParseFlags(tt.args[1:])
			if err != nil {
				t.Fatalf("failed to parse flags: %v", err)
			}

			// Check expected values
			for flagName, expectedValue := range tt.expected {
				flag := rootCmd.PersistentFlags().Lookup(flagName)
				if flag == nil {
					t.Errorf("flag %s not found", flagName)
					continue
				}

				actualValue := flag.Value.String()
				expectedStr := ""
				switch v := expectedValue.(type) {
				case bool:
					expectedStr = "false"
					if v {
						expectedStr = "true"
					}
				case string:
					expectedStr = v
				}

				if actualValue != expectedStr {
					t.Errorf("flag %s: expected %q, got %q", flagName, expectedStr, actualValue)
				}
			}
		})
	}

	// Restore original args
	os.Args = originalArgs
}