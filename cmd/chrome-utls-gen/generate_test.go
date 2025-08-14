package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/raven-betanet/dual-cli/internal/tlsgen"
)

func TestRunGenerate(t *testing.T) {
	// Create temporary directory for test outputs
	tempDir := t.TempDir()

	tests := []struct {
		name          string
		outputFile    string
		chromeVersion string
		templateCache string
		wantErr       bool
		checkOutput   bool
		checkCache    bool
	}{
		{
			name:          "generate with specific version",
			outputFile:    filepath.Join(tempDir, "test1.bin"),
			chromeVersion: "120.0.6099.109",
			templateCache: "",
			wantErr:       false,
			checkOutput:   true,
			checkCache:    false,
		},
		{
			name:          "generate with cache",
			outputFile:    filepath.Join(tempDir, "test2.bin"),
			chromeVersion: "119.0.6045.105",
			templateCache: filepath.Join(tempDir, "cache"),
			wantErr:       false,
			checkOutput:   true,
			checkCache:    true,
		},
		{
			name:          "invalid version format",
			outputFile:    filepath.Join(tempDir, "test3.bin"),
			chromeVersion: "invalid.version",
			templateCache: "",
			wantErr:       true,
			checkOutput:   false,
			checkCache:    false,
		},
		{
			name:          "generate latest version",
			outputFile:    filepath.Join(tempDir, "test4.bin"),
			chromeVersion: "", // Will fetch latest
			templateCache: "",
			wantErr:       false,
			checkOutput:   true,
			checkCache:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set global log level for testing
			logLevel = "error" // Reduce log noise during tests

			err := runGenerate(tt.outputFile, tt.chromeVersion, tt.templateCache)

			// Check error expectation
			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check if output file was created
			if tt.checkOutput && !tt.wantErr {
				if _, err := os.Stat(tt.outputFile); os.IsNotExist(err) {
					t.Errorf("output file was not created: %s", tt.outputFile)
				} else {
					// Check file size is reasonable (should be > 0 and < 10KB)
					info, _ := os.Stat(tt.outputFile)
					if info.Size() == 0 || info.Size() > 10240 {
						t.Errorf("output file size is unreasonable: %d bytes", info.Size())
					}

					// Check file starts with TLS record header (0x16 0x03)
					data, err := os.ReadFile(tt.outputFile)
					if err != nil {
						t.Errorf("failed to read output file: %v", err)
					} else if len(data) < 2 || data[0] != 0x16 || data[1] != 0x03 {
						t.Errorf("output file doesn't start with TLS record header")
					}
				}
			}

			// Check if cache was created
			if tt.checkCache && !tt.wantErr {
				cacheFiles, err := filepath.Glob(filepath.Join(tt.templateCache, "chrome_*.json"))
				if err != nil {
					t.Errorf("failed to check cache files: %v", err)
				} else if len(cacheFiles) == 0 {
					t.Errorf("no cache files were created")
				} else {
					// Validate cache file content
					cacheData, err := os.ReadFile(cacheFiles[0])
					if err != nil {
						t.Errorf("failed to read cache file: %v", err)
					} else {
						var template tlsgen.ClientHelloTemplate
						if err := json.Unmarshal(cacheData, &template); err != nil {
							t.Errorf("cache file contains invalid JSON: %v", err)
						} else {
							// Validate template structure
							if template.Version.Major == 0 {
								t.Errorf("cache template has invalid version")
							}
							if len(template.Bytes) == 0 {
								t.Errorf("cache template has no bytes")
							}
							if template.JA3Hash == "" {
								t.Errorf("cache template has no JA3 hash")
							}
							if template.JA3String == "" {
								t.Errorf("cache template has no JA3 string")
							}
						}
					}
				}
			}
		})
	}
}

func TestCacheTemplate(t *testing.T) {
	tempDir := t.TempDir()

	// Create a test template
	template := &tlsgen.ClientHelloTemplate{
		Version: tlsgen.ChromeVersion{
			Major: 120,
			Minor: 0,
			Build: 6099,
			Patch: 109,
		},
		Bytes:     []byte{0x16, 0x03, 0x01, 0x00, 0x10}, // Mock TLS record
		JA3Hash:   "test_hash",
		JA3String: "test_string",
	}

	tests := []struct {
		name     string
		cacheDir string
		wantErr  bool
	}{
		{
			name:     "valid cache directory",
			cacheDir: tempDir,
			wantErr:  false,
		},
		{
			name:     "non-existent directory (should create)",
			cacheDir: filepath.Join(tempDir, "new_dir"),
			wantErr:  false,
		},
		{
			name:     "invalid directory path",
			cacheDir: "/invalid/path/that/cannot/be/created",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cacheTemplate(template, tt.cacheDir)

			// Check error expectation
			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check if cache file was created
			if !tt.wantErr {
				expectedFile := filepath.Join(tt.cacheDir, "chrome_120.0.6099.109.json")
				if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
					t.Errorf("cache file was not created: %s", expectedFile)
				} else {
					// Validate cache file content
					data, err := os.ReadFile(expectedFile)
					if err != nil {
						t.Errorf("failed to read cache file: %v", err)
					} else {
						var cachedTemplate tlsgen.ClientHelloTemplate
						if err := json.Unmarshal(data, &cachedTemplate); err != nil {
							t.Errorf("cache file contains invalid JSON: %v", err)
						} else {
							// Validate cached data matches original
							if cachedTemplate.Version.String() != template.Version.String() {
								t.Errorf("cached version mismatch: got %s, want %s", 
									cachedTemplate.Version.String(), template.Version.String())
							}
							if cachedTemplate.JA3Hash != template.JA3Hash {
								t.Errorf("cached JA3 hash mismatch: got %s, want %s", 
									cachedTemplate.JA3Hash, template.JA3Hash)
							}
						}
					}
				}
			}
		})
	}
}

func TestGenerateCommandIntegration(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains []string
	}{
		{
			name: "generate with specific version",
			args: []string{
				"generate",
				"--version", "120.0.6099.109",
				"--output", filepath.Join(tempDir, "integration1.bin"),
			},
			wantErr: false,
			contains: []string{
				"Generated ClientHello for Chrome 120.0.6099.109",
				"Output file:",
				"JA3 Hash:",
				"JA3 String:",
			},
		},
		{
			name: "generate with cache",
			args: []string{
				"generate",
				"--version", "119.0.6045.105",
				"--output", filepath.Join(tempDir, "integration2.bin"),
				"--cache", filepath.Join(tempDir, "integration_cache"),
			},
			wantErr: false,
			contains: []string{
				"Generated ClientHello for Chrome 119.0.6045.105",
				"Output file:",
			},
		},
		{
			name: "invalid version",
			args: []string{
				"generate",
				"--version", "invalid",
				"--output", filepath.Join(tempDir, "integration3.bin"),
			},
			wantErr:  true,
			contains: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set global log level for testing
			logLevel = "error"

			// Create command
			cmd := newGenerateCmd()

			// Capture output
			output, err := captureStdout(func() error {
				cmd.SetArgs(tt.args[1:]) // Skip "generate"
				return cmd.Execute()
			})

			// Check error expectation
			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check output contains expected strings
			for _, expected := range tt.contains {
				if !strings.Contains(output, expected) {
					t.Errorf("output should contain %q, got: %s", expected, output)
				}
			}
		})
	}
}

// Note: captureStdout function is defined in main_test.go and reused here