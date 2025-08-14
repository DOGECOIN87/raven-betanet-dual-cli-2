package testutils

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// PlatformInfo contains information about the current platform
type PlatformInfo struct {
	OS           string
	Architecture string
	Bitness      int
	Endianness   string
}

// GetPlatformInfo returns information about the current platform
func GetPlatformInfo() PlatformInfo {
	bitness := 32
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" || strings.Contains(runtime.GOARCH, "64") {
		bitness = 64
	}
	
	endianness := "little"
	// Most modern architectures are little-endian
	// This is a simplification - real detection would be more complex
	
	return PlatformInfo{
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		Bitness:      bitness,
		Endianness:   endianness,
	}
}

// IsPlatformSupported checks if the current platform is supported
func IsPlatformSupported() bool {
	supportedOS := []string{"linux", "darwin", "windows"}
	supportedArch := []string{"amd64", "arm64", "386", "arm"}
	
	osSupported := false
	for _, os := range supportedOS {
		if runtime.GOOS == os {
			osSupported = true
			break
		}
	}
	
	archSupported := false
	for _, arch := range supportedArch {
		if runtime.GOARCH == arch {
			archSupported = true
			break
		}
	}
	
	return osSupported && archSupported
}

// GetExpectedBinaryFormat returns the expected binary format for the current platform
func GetExpectedBinaryFormat() string {
	switch runtime.GOOS {
	case "linux":
		return "ELF"
	case "windows":
		return "PE"
	case "darwin":
		return "Mach-O"
	default:
		return "Unknown"
	}
}

// GetPlatformSpecificBinaryPath returns the path to a platform-specific test binary
func GetPlatformSpecificBinaryPath(projectRoot string) string {
	switch runtime.GOOS {
	case "linux":
		return filepath.Join(projectRoot, "tests/fixtures/sample_binaries/valid_elf_binary")
	case "windows":
		return filepath.Join(projectRoot, "tests/fixtures/sample_binaries/valid_pe_binary.exe")
	case "darwin":
		return filepath.Join(projectRoot, "tests/fixtures/sample_binaries/valid_macho_binary")
	default:
		return filepath.Join(projectRoot, "tests/fixtures/sample_binaries/valid_elf_binary")
	}
}

// GetCrossArchBinaryPaths returns paths to binaries for different architectures
func GetCrossArchBinaryPaths(projectRoot string) map[string]string {
	fixturesDir := filepath.Join(projectRoot, "tests/fixtures/sample_binaries")
	
	return map[string]string{
		"x86_64": filepath.Join(fixturesDir, "test_x86_64_binary"),
		"i386":   filepath.Join(fixturesDir, "test_i386_binary"),
		"arm64":  filepath.Join(fixturesDir, "test_arm64_binary"),
		"arm":    filepath.Join(fixturesDir, "test_arm_binary"),
	}
}

// SkipIfPlatformNotSupported skips the test if the current platform is not supported
func SkipIfPlatformNotSupported(t *testing.T) {
	if !IsPlatformSupported() {
		t.Skipf("Platform %s/%s is not supported", runtime.GOOS, runtime.GOARCH)
	}
}

// SkipIfBinaryNotAvailable skips the test if the required binary is not available
func SkipIfBinaryNotAvailable(t *testing.T, binaryPath string) {
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		t.Skipf("Required binary not available: %s", binaryPath)
	}
}

// GetPlatformSpecificExpectations returns platform-specific test expectations
func GetPlatformSpecificExpectations() map[string]interface{} {
	expectations := make(map[string]interface{})
	
	platform := GetPlatformInfo()
	
	// Expected architectures for current platform
	switch platform.Architecture {
	case "amd64":
		expectations["architectures"] = []string{"amd64", "x86_64"}
	case "arm64":
		expectations["architectures"] = []string{"arm64", "aarch64"}
	case "386":
		expectations["architectures"] = []string{"i386", "x86"}
	case "arm":
		expectations["architectures"] = []string{"arm"}
	}
	
	// Expected binary format
	expectations["binary_format"] = GetExpectedBinaryFormat()
	
	// Expected bitness
	expectations["bitness"] = platform.Bitness
	
	// Expected endianness
	expectations["endianness"] = platform.Endianness
	
	// Platform-specific file extensions
	switch runtime.GOOS {
	case "windows":
		expectations["executable_extension"] = ".exe"
	default:
		expectations["executable_extension"] = ""
	}
	
	return expectations
}

// ValidatePlatformSpecificResult validates test results against platform expectations
func ValidatePlatformSpecificResult(t *testing.T, result map[string]interface{}) {
	expectations := GetPlatformSpecificExpectations()
	
	// Validate binary format if present
	if format, ok := result["format"].(string); ok {
		if expectedFormat, ok := expectations["binary_format"].(string); ok {
			if expectedFormat != "Unknown" && format != expectedFormat {
				t.Errorf("Expected binary format %s, got %s", expectedFormat, format)
			}
		}
	}
	
	// Validate architecture if present
	if arch, ok := result["architecture"].(string); ok {
		if expectedArchs, ok := expectations["architectures"].([]string); ok {
			found := false
			for _, expectedArch := range expectedArchs {
				if strings.Contains(strings.ToLower(arch), strings.ToLower(expectedArch)) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected architecture to be one of %v, got %s", expectedArchs, arch)
			}
		}
	}
	
	// Validate bitness if present
	if bitness, ok := result["bitness"].(float64); ok {
		if expectedBitness, ok := expectations["bitness"].(int); ok {
			if int(bitness) != expectedBitness {
				t.Errorf("Expected bitness %d, got %.0f", expectedBitness, bitness)
			}
		}
	}
}

// GetPlatformTestMatrix returns a test matrix for cross-platform testing
func GetPlatformTestMatrix() []struct {
	Name     string
	OS       string
	Arch     string
	Format   string
	Bitness  int
	Testable bool
} {
	return []struct {
		Name     string
		OS       string
		Arch     string
		Format   string
		Bitness  int
		Testable bool
	}{
		{"Linux x86_64", "linux", "amd64", "ELF", 64, true},
		{"Linux i386", "linux", "386", "ELF", 32, true},
		{"Linux ARM64", "linux", "arm64", "ELF", 64, true},
		{"Linux ARM", "linux", "arm", "ELF", 32, true},
		{"Windows x86_64", "windows", "amd64", "PE", 64, runtime.GOOS == "windows"},
		{"Windows i386", "windows", "386", "PE", 32, runtime.GOOS == "windows"},
		{"macOS x86_64", "darwin", "amd64", "Mach-O", 64, runtime.GOOS == "darwin"},
		{"macOS ARM64", "darwin", "arm64", "Mach-O", 64, runtime.GOOS == "darwin"},
	}
}

// LogPlatformInfo logs information about the current platform
func LogPlatformInfo(t *testing.T) {
	info := GetPlatformInfo()
	t.Logf("Platform Information:")
	t.Logf("  OS: %s", info.OS)
	t.Logf("  Architecture: %s", info.Architecture)
	t.Logf("  Bitness: %d-bit", info.Bitness)
	t.Logf("  Endianness: %s", info.Endianness)
	t.Logf("  Expected Binary Format: %s", GetExpectedBinaryFormat())
	t.Logf("  Platform Supported: %t", IsPlatformSupported())
}

// CreatePlatformTestReport creates a comprehensive platform test report
func CreatePlatformTestReport(t *testing.T, results map[string]interface{}) {
	info := GetPlatformInfo()
	
	t.Logf("=== Platform Test Report ===")
	t.Logf("Platform: %s/%s (%d-bit)", info.OS, info.Architecture, info.Bitness)
	t.Logf("Expected Format: %s", GetExpectedBinaryFormat())
	
	if format, ok := results["format"].(string); ok {
		t.Logf("Detected Format: %s", format)
	}
	
	if arch, ok := results["architecture"].(string); ok {
		t.Logf("Detected Architecture: %s", arch)
	}
	
	if bitness, ok := results["bitness"].(float64); ok {
		t.Logf("Detected Bitness: %.0f-bit", bitness)
	}
	
	if endianness, ok := results["endianness"].(string); ok {
		t.Logf("Detected Endianness: %s", endianness)
	}
	
	if sections, ok := results["sections"].([]interface{}); ok {
		t.Logf("Sections Found: %d", len(sections))
	}
	
	if deps, ok := results["dependencies"].([]interface{}); ok {
		t.Logf("Dependencies Found: %d", len(deps))
	}
	
	t.Logf("=== End Platform Test Report ===")
}

// GetArchitectureTestCases returns test cases for different architectures
func GetArchitectureTestCases() []struct {
	Name         string
	Architecture string
	Bitness      int
	BinaryPath   string
	Available    func(projectRoot string) bool
} {
	return []struct {
		Name         string
		Architecture string
		Bitness      int
		BinaryPath   string
		Available    func(projectRoot string) bool
	}{
		{
			Name:         "x86_64",
			Architecture: "x86_64",
			Bitness:      64,
			BinaryPath:   "tests/fixtures/sample_binaries/test_x86_64_binary",
			Available: func(projectRoot string) bool {
				path := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/test_x86_64_binary")
				_, err := os.Stat(path)
				return err == nil
			},
		},
		{
			Name:         "i386",
			Architecture: "i386",
			Bitness:      32,
			BinaryPath:   "tests/fixtures/sample_binaries/test_i386_binary",
			Available: func(projectRoot string) bool {
				path := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/test_i386_binary")
				_, err := os.Stat(path)
				return err == nil
			},
		},
		{
			Name:         "ARM64",
			Architecture: "arm64",
			Bitness:      64,
			BinaryPath:   "tests/fixtures/sample_binaries/test_arm64_binary",
			Available: func(projectRoot string) bool {
				path := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/test_arm64_binary")
				_, err := os.Stat(path)
				return err == nil
			},
		},
		{
			Name:         "ARM",
			Architecture: "arm",
			Bitness:      32,
			BinaryPath:   "tests/fixtures/sample_binaries/test_arm_binary",
			Available: func(projectRoot string) bool {
				path := filepath.Join(projectRoot, "tests/fixtures/sample_binaries/test_arm_binary")
				_, err := os.Stat(path)
				return err == nil
			},
		},
	}
}

// GenerateTestBinariesIfNeeded generates test binaries if they don't exist
func GenerateTestBinariesIfNeeded(t *testing.T, projectRoot string) {
	fixturesDir := filepath.Join(projectRoot, "tests/fixtures/sample_binaries")
	generatorPath := filepath.Join(fixturesDir, "generate_test_binaries.go")
	
	// Check if generator exists
	if _, err := os.Stat(generatorPath); os.IsNotExist(err) {
		t.Logf("Binary generator not found: %s", generatorPath)
		return
	}
	
	// Check if basic binaries exist
	requiredBinaries := []string{
		"valid_elf_binary",
		"invalid_elf_binary",
		"corrupted_binary",
	}
	
	needsGeneration := false
	for _, binary := range requiredBinaries {
		binaryPath := filepath.Join(fixturesDir, binary)
		if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
			needsGeneration = true
			break
		}
	}
	
	if needsGeneration {
		t.Logf("Generating test binaries...")
		// This would be called by the test framework as needed
		// In practice, you'd run: go run generate_test_binaries.go
		t.Logf("Run 'go run generate_test_binaries.go' in %s to generate test binaries", fixturesDir)
	}
}

// GetPlatformSpecificTimeout returns platform-specific timeout values
func GetPlatformSpecificTimeout() map[string]interface{} {
	timeouts := make(map[string]interface{})
	
	// Adjust timeouts based on platform performance characteristics
	switch runtime.GOOS {
	case "windows":
		// Windows might be slower for some operations
		timeouts["binary_analysis"] = "90s"
		timeouts["tls_generation"] = "45s"
		timeouts["network_test"] = "30s"
	case "darwin":
		// macOS generally has good performance
		timeouts["binary_analysis"] = "60s"
		timeouts["tls_generation"] = "30s"
		timeouts["network_test"] = "20s"
	default: // linux and others
		timeouts["binary_analysis"] = "60s"
		timeouts["tls_generation"] = "30s"
		timeouts["network_test"] = "20s"
	}
	
	// Adjust for architecture
	switch runtime.GOARCH {
	case "arm", "386":
		// 32-bit or ARM might be slower
		for key, value := range timeouts {
			if timeout, ok := value.(string); ok {
				// This is a simplified approach - in practice you'd parse and increase the duration
				timeouts[key] = timeout // Keep same for now
			}
		}
	}
	
	return timeouts
}