package integration

import (
	"testing"
	"runtime"
	testutils "github.com/raven-betanet/dual-cli/tests/utils"
)

// TestCrossPlatformRunner is a simple test to verify cross-platform functionality
func TestCrossPlatformRunner(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping cross-platform runner test in short mode")
	}

	// Log platform information
	testutils.LogPlatformInfo(t)
	
	// Check if platform is supported
	if !testutils.IsPlatformSupported() {
		t.Skipf("Platform %s/%s is not supported", runtime.GOOS, runtime.GOARCH)
	}
	
	t.Run("Platform detection", func(t *testing.T) {
		info := testutils.GetPlatformInfo()
		
		t.Logf("Platform detection test:")
		t.Logf("  OS: %s", info.OS)
		t.Logf("  Architecture: %s", info.Architecture)
		t.Logf("  Bitness: %d-bit", info.Bitness)
		t.Logf("  Endianness: %s", info.Endianness)
		
		// Basic validation
		if info.OS == "" {
			t.Error("OS should not be empty")
		}
		if info.Architecture == "" {
			t.Error("Architecture should not be empty")
		}
		if info.Bitness != 32 && info.Bitness != 64 {
			t.Errorf("Bitness should be 32 or 64, got %d", info.Bitness)
		}
	})
	
	t.Run("Binary format detection", func(t *testing.T) {
		expectedFormat := testutils.GetExpectedBinaryFormat()
		t.Logf("Expected binary format for %s: %s", runtime.GOOS, expectedFormat)
		
		// Validate expected format
		validFormats := []string{"ELF", "PE", "Mach-O", "Unknown"}
		found := false
		for _, format := range validFormats {
			if expectedFormat == format {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected format %s is not valid", expectedFormat)
		}
	})
	
	t.Run("Test binary availability", func(t *testing.T) {
		projectRoot := getProjectRoot(t)
		
		// Check platform-specific binary
		platformBinary := testutils.GetPlatformSpecificBinaryPath(projectRoot)
		t.Logf("Platform-specific binary path: %s", platformBinary)
		
		// Check cross-architecture binaries
		crossArchBinaries := testutils.GetCrossArchBinaryPaths(projectRoot)
		t.Logf("Cross-architecture binaries:")
		for arch, path := range crossArchBinaries {
			t.Logf("  %s: %s", arch, path)
		}
		
		// Verify at least some binaries exist
		testutils.GenerateTestBinariesIfNeeded(t, projectRoot)
	})
	
	t.Run("Platform expectations", func(t *testing.T) {
		expectations := testutils.GetPlatformSpecificExpectations()
		
		t.Logf("Platform-specific expectations:")
		for key, value := range expectations {
			t.Logf("  %s: %v", key, value)
		}
		
		// Validate expectations structure
		if _, ok := expectations["binary_format"]; !ok {
			t.Error("Expectations should include binary_format")
		}
		if _, ok := expectations["bitness"]; !ok {
			t.Error("Expectations should include bitness")
		}
	})
	
	t.Logf("Cross-platform runner test completed successfully for %s/%s", 
		runtime.GOOS, runtime.GOARCH)
}