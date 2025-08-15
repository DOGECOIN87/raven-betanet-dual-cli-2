package sbom

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBinaryComponentExtractor_GetSupportedFormats(t *testing.T) {
	extractor := NewBinaryComponentExtractor()
	formats := extractor.GetSupportedFormats()

	assert.Contains(t, formats, "ELF")
	assert.Contains(t, formats, "PE")
	assert.Contains(t, formats, "Mach-O")
}

func TestBinaryComponentExtractor_DetectBinaryFormat(t *testing.T) {
	extractor := NewBinaryComponentExtractor()

	tests := []struct {
		name     string
		header   []byte
		expected string
	}{
		{
			name:     "ELF format",
			header:   []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00},
			expected: "ELF",
		},
		{
			name:     "PE format",
			header:   []byte{'M', 'Z', 0x90, 0x00, 0x03, 0x00, 0x00, 0x00},
			expected: "PE",
		},
		{
			name:     "Mach-O format (feedface)",
			header:   []byte{0xfe, 0xed, 0xfa, 0xce, 0x00, 0x00, 0x00, 0x00},
			expected: "Mach-O",
		},
		{
			name:     "Unknown format",
			header:   []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			expected: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file with test header
			tempFile := createTempFileWithContent(t, tt.header)
			defer os.Remove(tempFile)

			format, err := extractor.detectBinaryFormat(tempFile)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, format)
		})
	}
}

func TestBinaryComponentExtractor_CreateBasicComponent(t *testing.T) {
	extractor := NewBinaryComponentExtractor()
	
	// Create a temporary file
	tempFile := createTempFileWithContent(t, []byte("test content"))
	defer os.Remove(tempFile)

	component := extractor.createBasicComponent(tempFile)

	assert.Equal(t, ComponentTypeApplication, component.Type)
	assert.Equal(t, filepath.Base(tempFile), component.Name)
	assert.Equal(t, "unknown", component.Version)
	assert.Equal(t, "Binary application (unknown format)", component.Description)

	// Check properties
	found := false
	for _, prop := range component.Properties {
		if prop.Name == "binary.format" && prop.Value == "unknown" {
			found = true
			break
		}
	}
	assert.True(t, found, "Should have binary.format property")
}

func TestBinaryComponentExtractor_ExtractGoModules(t *testing.T) {
	extractor := NewBinaryComponentExtractor()

	content := `
	github.com/example/module@v1.2.3
	golang.org/x/crypto@v0.1.0
	github.com/stretchr/testify@v1.8.4
	invalid-module-format
	`

	modules := extractor.extractGoModules(content)

	assert.Len(t, modules, 3)

	// Check first module
	assert.Equal(t, "module", modules[0].Name)
	assert.Equal(t, "1.2.3", modules[0].Version)
	assert.Equal(t, "github.com/example/module", modules[0].Path)

	// Check second module
	assert.Equal(t, "crypto", modules[1].Name)
	assert.Equal(t, "0.1.0", modules[1].Version)
	assert.Equal(t, "golang.org/x/crypto", modules[1].Path)
}

func TestBinaryComponentExtractor_ExtractRustCrates(t *testing.T) {
	extractor := NewBinaryComponentExtractor()

	content := `
	serde-1.0.136
	tokio-1.21.2
	clap-4.0.32
	lib-invalid  // Should be filtered out
	`

	crates := extractor.extractRustCrates(content)

	assert.Len(t, crates, 3)

	// Check first crate
	assert.Equal(t, "serde", crates[0].Name)
	assert.Equal(t, "1.0.136", crates[0].Version)

	// Check second crate
	assert.Equal(t, "tokio", crates[1].Name)
	assert.Equal(t, "1.21.2", crates[1].Version)
}

func TestBinaryComponentExtractor_ExtractNodePackages(t *testing.T) {
	extractor := NewBinaryComponentExtractor()

	content := `
	express@4.18.2
	@types/node@18.11.9
	lodash@4.17.21
	invalid@format@test  // Should be handled gracefully
	`

	packages := extractor.extractNodePackages(content)

	assert.GreaterOrEqual(t, len(packages), 2) // At least express and lodash

	// Find express package
	var expressFound bool
	for _, pkg := range packages {
		if pkg.Name == "express" && pkg.Version == "4.18.2" {
			expressFound = true
			break
		}
	}
	assert.True(t, expressFound, "Should find express package")
}

func TestBinaryComponentExtractor_ExtractPythonPackages(t *testing.T) {
	extractor := NewBinaryComponentExtractor()

	content := `
	requests==2.28.1
	numpy-1.24.1
	django==4.1.4
	lib==invalid  // Should be filtered out
	`

	packages := extractor.extractPythonPackages(content)

	assert.GreaterOrEqual(t, len(packages), 2) // At least requests and numpy

	// Find requests package
	var requestsFound bool
	for _, pkg := range packages {
		if pkg.Name == "requests" && pkg.Version == "2.28.1" {
			requestsFound = true
			break
		}
	}
	assert.True(t, requestsFound, "Should find requests package")
}

func TestBinaryComponentExtractor_IsValidRustCrateName(t *testing.T) {
	extractor := NewBinaryComponentExtractor()

	tests := []struct {
		name     string
		crateName string
		expected bool
	}{
		{"valid crate", "serde", true},
		{"valid crate with underscore", "serde_json", true},
		{"invalid - too short", "ab", false},
		{"invalid - lib", "lib", false},
		{"invalid - std", "std", false},
		{"invalid - too long", "this-is-a-very-long-crate-name-that-exceeds-the-limit", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractor.isValidRustCrateName(tt.crateName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBinaryComponentExtractor_IsValidNodePackageName(t *testing.T) {
	extractor := NewBinaryComponentExtractor()

	tests := []struct {
		name        string
		packageName string
		expected    bool
	}{
		{"valid package", "express", true},
		{"valid scoped package", "@types/node", true},
		{"invalid - starts with dot", ".hidden", false},
		{"invalid - contains double dots", "package..name", false},
		{"invalid - too short", "a", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractor.isValidNodePackageName(tt.packageName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBinaryComponentExtractor_IsValidPythonPackageName(t *testing.T) {
	extractor := NewBinaryComponentExtractor()

	tests := []struct {
		name        string
		packageName string
		expected    bool
	}{
		{"valid package", "requests", true},
		{"valid package with underscore", "python_package", true},
		{"invalid - too short", "ab", false},
		{"invalid - lib", "lib", false},
		{"invalid - src", "src", false},
		{"invalid - too long", "this-is-a-very-long-python-package-name-that-exceeds", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractor.isValidPythonPackageName(tt.packageName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBinaryComponentExtractor_InferLibrariesFromSymbols(t *testing.T) {
	extractor := NewBinaryComponentExtractor()

	symbols := []string{
		"ssl_connect",
		"SSL_library_init",
		"crypto_hash",
		"CRYPTO_malloc",
		"z_compress",
		"deflate",
		"curl_easy_init",
		"sqlite3_open",
		"json_parse",
		"xmlParseDoc",
		"pthread_create",
		"unknown_symbol",
	}

	components := extractor.inferLibrariesFromSymbols(symbols)

	// Should find several libraries
	assert.GreaterOrEqual(t, len(components), 5)

	// Check that we found some expected libraries
	libraryNames := make(map[string]bool)
	for _, comp := range components {
		libraryNames[comp.Name] = true
	}

	assert.True(t, libraryNames["openssl"], "Should infer openssl from ssl_ symbols")
	assert.True(t, libraryNames["libcrypto"], "Should infer libcrypto from crypto_ symbols")
	assert.True(t, libraryNames["zlib"], "Should infer zlib from z_ symbols")
	assert.True(t, libraryNames["libcurl"], "Should infer libcurl from curl_ symbols")
	assert.True(t, libraryNames["sqlite3"], "Should infer sqlite3 from sqlite3_ symbols")
}

func TestBinaryComponentExtractor_ExtractComponents_UnknownFormat(t *testing.T) {
	extractor := NewBinaryComponentExtractor()

	// Create a file with unknown format
	tempFile := createTempFileWithContent(t, []byte("unknown binary format"))
	defer os.Remove(tempFile)

	components, err := extractor.ExtractComponents(tempFile)
	require.NoError(t, err)

	// Should have at least one component (the main application)
	assert.GreaterOrEqual(t, len(components), 1)

	// First component should be the main application
	mainComponent := components[0]
	assert.Equal(t, ComponentTypeApplication, mainComponent.Type)
	assert.Equal(t, filepath.Base(tempFile), mainComponent.Name)
	assert.Equal(t, "unknown", mainComponent.Version)
}

// Helper function to create temporary file with content
func createTempFileWithContent(t *testing.T, content []byte) string {
	t.Helper()

	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "test-binary")

	err := os.WriteFile(tempFile, content, 0644)
	require.NoError(t, err)

	return tempFile
}

// Benchmark tests
func BenchmarkBinaryComponentExtractor_DetectBinaryFormat(b *testing.B) {
	extractor := NewBinaryComponentExtractor()
	
	// Create a temporary ELF file
	tempFile := filepath.Join(b.TempDir(), "test-elf")
	elfHeader := []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}
	err := os.WriteFile(tempFile, elfHeader, 0644)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := extractor.detectBinaryFormat(tempFile)
		require.NoError(b, err)
	}
}

func BenchmarkBinaryComponentExtractor_ExtractGoModules(b *testing.B) {
	extractor := NewBinaryComponentExtractor()
	
	content := `
	github.com/example/module@v1.2.3
	golang.org/x/crypto@v0.1.0
	github.com/stretchr/testify@v1.8.4
	github.com/gin-gonic/gin@v1.9.1
	github.com/gorilla/mux@v1.8.0
	`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = extractor.extractGoModules(content)
	}
}