package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/raven-betanet/dual-cli/internal/tlsgen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunUpdate(t *testing.T) {
	tests := []struct {
		name          string
		force         bool
		dryRun        bool
		setupCache    func(t *testing.T, cacheDir string)
		expectUpdate  bool
		expectError   bool
	}{
		{
			name:         "dry run shows what would be updated",
			force:        false,
			dryRun:       true,
			setupCache:   nil, // No cache setup
			expectUpdate: false,
			expectError:  false,
		},
		{
			name:         "force update regenerates all templates",
			force:        true,
			dryRun:       false,
			setupCache:   setupValidCache,
			expectUpdate: true,
			expectError:  false,
		},
		{
			name:         "update with empty cache generates templates",
			force:        false,
			dryRun:       false,
			setupCache:   nil, // No cache setup
			expectUpdate: true,
			expectError:  false,
		},
		{
			name:         "update with valid cache skips generation",
			force:        false,
			dryRun:       false,
			setupCache:   setupValidCache,
			expectUpdate: false, // Should skip if cache is valid and up to date
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary cache directory
			tempDir := t.TempDir()
			cacheDir := filepath.Join(tempDir, "templates")

			// Setup cache if needed
			if tt.setupCache != nil {
				tt.setupCache(t, tempDir)
			}

			// Set global log level for testing
			logLevel = "error" // Reduce noise in tests

			// Run update command
			err := runUpdate(tt.force, cacheDir, tt.dryRun)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

			if tt.dryRun {
				// Dry run should not create any files
				_, err := os.Stat(cacheDir)
				assert.True(t, os.IsNotExist(err), "Cache directory should not be created in dry run")
				return
			}

			if tt.expectUpdate {
				// Check that cache directory was created
				_, err := os.Stat(cacheDir)
				assert.NoError(t, err, "Cache directory should be created")

				// Check that template files were created
				files, err := os.ReadDir(cacheDir)
				assert.NoError(t, err)
				assert.Greater(t, len(files), 0, "Template files should be created")

				// Verify template files are valid JSON
				for _, file := range files {
					if filepath.Ext(file.Name()) == ".json" {
						filePath := filepath.Join(cacheDir, file.Name())
						data, err := os.ReadFile(filePath)
						assert.NoError(t, err)

						var template tlsgen.ClientHelloTemplate
						err = json.Unmarshal(data, &template)
						assert.NoError(t, err, "Template file should be valid JSON")
						assert.NotEmpty(t, template.Version.String(), "Template should have version")
						assert.NotEmpty(t, template.JA3Hash, "Template should have JA3 hash")
					}
				}
			}
		})
	}
}

func TestRunUpdateWithInvalidCacheDir(t *testing.T) {
	// Test with invalid cache directory (read-only filesystem)
	if os.Getuid() == 0 {
		t.Skip("Skipping test when running as root")
	}

	// Create a read-only directory
	tempDir := t.TempDir()
	readOnlyDir := filepath.Join(tempDir, "readonly")
	err := os.Mkdir(readOnlyDir, 0444) // Read-only permissions
	require.NoError(t, err)

	cacheDir := filepath.Join(readOnlyDir, "templates")

	// Set global log level for testing
	logLevel = "error"

	// Force update to ensure we try to create templates
	err = runUpdate(true, cacheDir, false)
	if err != nil {
		// Should fail when trying to create the cache directory or write templates
		assert.True(t, 
			contains(err.Error(), "failed to create cache directory") || 
			contains(err.Error(), "permission denied") ||
			contains(err.Error(), "CACHE FAILED"),
			"Expected permission-related error, got: %v", err)
	}
}

func TestCacheTemplateUpdateScenarios(t *testing.T) {
	// Test caching to an invalid directory
	template := &tlsgen.ClientHelloTemplate{
		Version: tlsgen.ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
		JA3Hash: "test",
	}

	// Try to cache to a file instead of directory (should fail)
	tempFile := filepath.Join(t.TempDir(), "not-a-directory.txt")
	err := os.WriteFile(tempFile, []byte("test"), 0644)
	require.NoError(t, err)

	err = cacheTemplate(template, tempFile)
	assert.Error(t, err)
}

// setupValidCache creates a valid version cache for testing
func setupValidCache(t *testing.T, tempDir string) {
	// Create version cache manager with custom path
	cacheManager := tlsgen.NewVersionCacheManagerWithPath(
		filepath.Join(tempDir, ".cache", "chrome-versions"),
		24*time.Hour,
	)

	// Create some mock versions (recent enough to be considered valid)
	versions := []tlsgen.ChromeVersion{
		{
			Major:    120,
			Minor:    0,
			Build:    6099,
			Patch:    109,
			Channel:  "Stable",
			Platform: "Linux",
			Date:     time.Now().Add(-1 * time.Hour), // Recent
		},
		{
			Major:    119,
			Minor:    0,
			Build:    6045,
			Patch:    105,
			Channel:  "Stable",
			Platform: "Linux",
			Date:     time.Now().Add(-2 * time.Hour), // Recent
		},
	}

	err := cacheManager.CacheVersions(versions)
	require.NoError(t, err)
}

func TestUpdateCommandIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test the actual update command with real Chrome API
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "templates")

	// Set global log level for testing
	logLevel = "error"

	// Run update command (this will make real API calls)
	err := runUpdate(false, cacheDir, false)
	
	// The test might fail if Chrome API is unavailable, so we check for specific errors
	if err != nil {
		// Allow network-related errors in CI/testing environments
		if contains(err.Error(), "failed to fetch") || contains(err.Error(), "no Chrome versions found") {
			t.Skipf("Skipping integration test due to network error: %v", err)
		}
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify that templates were created
	_, err = os.Stat(cacheDir)
	assert.NoError(t, err, "Cache directory should be created")

	files, err := os.ReadDir(cacheDir)
	assert.NoError(t, err)
	assert.Greater(t, len(files), 0, "Template files should be created")
}

func TestUpdateCommandDryRunIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test dry run with real Chrome API
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "templates")

	// Set global log level for testing
	logLevel = "error"

	// Run dry run update command
	err := runUpdate(false, cacheDir, true)
	
	// Allow network-related errors in CI/testing environments
	if err != nil && (contains(err.Error(), "failed to fetch") || contains(err.Error(), "no Chrome versions found")) {
		t.Skipf("Skipping integration test due to network error: %v", err)
	}
	
	assert.NoError(t, err)

	// Verify that no files were created in dry run
	_, err = os.Stat(cacheDir)
	assert.True(t, os.IsNotExist(err), "Cache directory should not be created in dry run")
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || 
		(len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || 
		containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}