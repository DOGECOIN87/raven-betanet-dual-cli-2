package sbom

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/raven-betanet/dual-cli/internal/checks"
)

func TestNewBinaryComponentExtractor(t *testing.T) {
	extractor := NewBinaryComponentExtractor()
	
	if extractor == nil {
		t.Error("Expected extractor to be created")
	}
	
	if extractor.parser == nil {
		t.Error("Expected parser to be initialized")
	}
}

func TestBinaryComponentExtractor_GetSupportedFormats(t *testing.T) {
	extractor := NewBinaryComponentExtractor()
	formats := extractor.GetSupportedFormats()
	
	expectedFormats := []string{"ELF", "PE", "Mach-O"}
	
	if len(formats) != len(expectedFormats) {
		t.Errorf("Expected %d formats, got %d", len(expectedFormats), len(formats))
	}
	
	for i, expected := range expectedFormats {
		if formats[i] != expected {
			t.Errorf("Expected format '%s', got '%s'", expected, formats[i])
		}
	}
}

func TestBinaryComponentExtractor_ExtractComponents_NonExistentFile(t *testing.T) {
	extractor := NewBinaryComponentExtractor()
	
	_, err := extractor.ExtractComponents("/non/existent/file")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestBinaryComponentExtractor_ExtractComponents_ValidBinary(t *testing.T) {
	// Create a temporary test binary file
	tempDir := t.TempDir()
	testBinary := filepath.Join(tempDir, "test-binary")
	
	// Create a simple ELF-like file (just the magic bytes for testing)
	elfHeader := []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}
	elfHeader = append(elfHeader, make([]byte, 56)...) // Pad to minimum ELF header size
	
	err := os.WriteFile(testBinary, elfHeader, 0644)
	if err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}
	
	extractor := NewBinaryComponentExtractor()
	components, err := extractor.ExtractComponents(testBinary)
	
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	if len(components) == 0 {
		t.Error("Expected at least one component (main application)")
	}
	
	// Check that we have a main application component
	hasMainApp := false
	for _, comp := range components {
		if comp.Type == ComponentTypeApplication {
			hasMainApp = true
			break
		}
	}
	
	if !hasMainApp {
		t.Error("Expected to find main application component")
	}
}

func TestBinaryComponentExtractor_createMainComponent(t *testing.T) {
	// Create a temporary test file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test-binary")
	testContent := []byte("test binary content")
	
	err := os.WriteFile(testFile, testContent, 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	
	extractor := NewBinaryComponentExtractor()
	
	// Create mock binary info
	binaryInfo := &checks.BinaryInfo{
		Format:       checks.FormatELF,
		Architecture: "x86_64",
		Bitness:      64,
		Endianness:   "little",
		EntryPoint:   0x1000,
		Sections:     []string{".text", ".data", ".bss"},
		Dependencies: []string{},
		Symbols:      []string{},
		FileSize:     int64(len(testContent)),
	}
	
	component, err := extractor.createMainComponent(testFile, binaryInfo)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	if component.Type != ComponentTypeApplication {
		t.Errorf("Expected component type %s, got %s", ComponentTypeApplication, component.Type)
	}
	
	if component.Name != "test-binary" {
		t.Errorf("Expected component name 'test-binary', got '%s'", component.Name)
	}
	
	if component.BOMRef == "" {
		t.Error("Expected BOM reference to be generated")
	}
	
	if len(component.Hashes) == 0 {
		t.Error("Expected component to have hash")
	}
	
	if component.Hashes["sha256"] == "" {
		t.Error("Expected SHA256 hash to be calculated")
	}
	
	// Check properties
	expectedProperties := map[string]string{
		"binary.format":       "ELF",
		"binary.architecture": "x86_64",
		"binary.bitness":      "64",
		"binary.endianness":   "little",
		"binary.entry_point":  "0x1000",
		"binary.file_size":    "19",
		"binary.section_count": "3",
		"binary.sections":     ".text,.data,.bss",
	}
	
	for expectedName, expectedValue := range expectedProperties {
		found := false
		for _, prop := range component.Properties {
			if prop.Name == expectedName && prop.Value == expectedValue {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected property %s=%s not found", expectedName, expectedValue)
		}
	}
	
	// Check evidence
	if component.Evidence == nil {
		t.Error("Expected component to have evidence")
	}
	
	if component.Evidence.Identity == nil {
		t.Error("Expected component to have identity evidence")
	}
	
	if component.Evidence.Identity.Field != "binary_analysis" {
		t.Errorf("Expected evidence field 'binary_analysis', got '%s'", component.Evidence.Identity.Field)
	}
	
	if component.Evidence.Identity.Confidence != 1.0 {
		t.Errorf("Expected evidence confidence 1.0, got %f", component.Evidence.Identity.Confidence)
	}
}

func TestBinaryComponentExtractor_extractDependencyComponents(t *testing.T) {
	extractor := NewBinaryComponentExtractor()
	
	binaryInfo := &checks.BinaryInfo{
		Format:       checks.FormatELF,
		Dependencies: []string{"libc.so.6", "libm.so.6", "libpthread.so.0"},
	}
	
	components, err := extractor.extractDependencyComponents(binaryInfo, "main-ref")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	if len(components) != 3 {
		t.Errorf("Expected 3 dependency components, got %d", len(components))
	}
	
	// Check first dependency
	comp := components[0]
	if comp.Name != "libc" {
		t.Errorf("Expected component name 'libc', got '%s'", comp.Name)
	}
	
	if comp.Type != ComponentTypeOperatingSystem {
		t.Errorf("Expected component type %s for libc, got %s", ComponentTypeOperatingSystem, comp.Type)
	}
	
	if comp.Scope != ScopeRequired {
		t.Errorf("Expected component scope %s, got %s", ScopeRequired, comp.Scope)
	}
	
	// Check evidence
	if comp.Evidence == nil {
		t.Error("Expected dependency component to have evidence")
	}
	
	if comp.Evidence.Identity.Field != "dependency_analysis" {
		t.Errorf("Expected evidence field 'dependency_analysis', got '%s'", comp.Evidence.Identity.Field)
	}
}

func TestBinaryComponentExtractor_createDependencyComponent(t *testing.T) {
	extractor := NewBinaryComponentExtractor()
	
	tests := []struct {
		depName      string
		format       checks.BinaryFormat
		expectedType ComponentType
		expectedName string
		expectedVersion string
	}{
		{"libc.so.6", checks.FormatELF, ComponentTypeOperatingSystem, "libc", "6"},
		{"libqt5core.so.5.15.2", checks.FormatELF, ComponentTypeFramework, "libqt5core", "5.15.2"},
		{"user32.dll", checks.FormatPE, ComponentTypeOperatingSystem, "user32.dll", "unknown"},
		{"mylib-1.2.3.dll", checks.FormatPE, ComponentTypeLibrary, "mylib", "1.2.3"},
		{"libssl.1.1.dylib", checks.FormatMachO, ComponentTypeLibrary, "libssl", "1.1"},
	}
	
	for _, test := range tests {
		comp := extractor.createDependencyComponent(test.depName, test.format)
		
		if comp.Type != test.expectedType {
			t.Errorf("For %s: expected type %s, got %s", test.depName, test.expectedType, comp.Type)
		}
		
		if comp.Name != test.expectedName {
			t.Errorf("For %s: expected name '%s', got '%s'", test.depName, test.expectedName, comp.Name)
		}
		
		if comp.Version != test.expectedVersion {
			t.Errorf("For %s: expected version '%s', got '%s'", test.depName, test.expectedVersion, comp.Version)
		}
		
		if comp.Scope != ScopeRequired {
			t.Errorf("For %s: expected scope %s, got %s", test.depName, ScopeRequired, comp.Scope)
		}
	}
}

func TestBinaryComponentExtractor_inferComponentType(t *testing.T) {
	extractor := NewBinaryComponentExtractor()
	
	tests := []struct {
		depName      string
		format       checks.BinaryFormat
		expectedType ComponentType
	}{
		{"libqt5core.so", checks.FormatELF, ComponentTypeFramework},
		{"libgtk-3.so", checks.FormatELF, ComponentTypeFramework},
		{"libc.so.6", checks.FormatELF, ComponentTypeOperatingSystem},
		{"kernel32.dll", checks.FormatPE, ComponentTypeOperatingSystem},
		{"libpng.so", checks.FormatELF, ComponentTypeLibrary},
		{"mylib.dll", checks.FormatPE, ComponentTypeLibrary},
	}
	
	for _, test := range tests {
		result := extractor.inferComponentType(test.depName, test.format)
		if result != test.expectedType {
			t.Errorf("For %s: expected type %s, got %s", test.depName, test.expectedType, result)
		}
	}
}

func TestBinaryComponentExtractor_parseNameVersion(t *testing.T) {
	extractor := NewBinaryComponentExtractor()
	
	tests := []struct {
		depName         string
		expectedName    string
		expectedVersion string
	}{
		{"libc.so.6", "libc", "6"},
		{"libssl.so.1.1", "libssl", "1.1"},
		{"libqt5core.so.5.15.2", "libqt5core", "5.15.2"},
		{"mylib-1.2.3.dll", "mylib", "1.2.3"},
		{"libssl.1.1.dylib", "libssl", "1.1"},
		{"libpng.16.37.0.dylib", "libpng", "16.37.0"},
		{"simple.dll", "simple.dll", "unknown"},
		{"noversion", "noversion", "unknown"},
	}
	
	for _, test := range tests {
		name, version := extractor.parseNameVersion(test.depName)
		if name != test.expectedName {
			t.Errorf("For %s: expected name '%s', got '%s'", test.depName, test.expectedName, name)
		}
		if version != test.expectedVersion {
			t.Errorf("For %s: expected version '%s', got '%s'", test.depName, test.expectedVersion, version)
		}
	}
}

func TestBinaryComponentExtractor_looksLikeVersion(t *testing.T) {
	extractor := NewBinaryComponentExtractor()
	
	tests := []struct {
		input    string
		expected bool
	}{
		{"1.2.3", true},
		{"1.0", true},
		{"2.15.1", true},
		{"1.2.3-beta", true},
		{"1.2.3_rc1", true},
		{"abc", false},
		{"", false},
		{"1.2.3.xyz", false},
		{"123", true},
	}
	
	for _, test := range tests {
		result := extractor.looksLikeVersion(test.input)
		if result != test.expected {
			t.Errorf("For '%s': expected %t, got %t", test.input, test.expected, result)
		}
	}
}

func TestBinaryComponentExtractor_looksLikeVersionPart(t *testing.T) {
	extractor := NewBinaryComponentExtractor()
	
	tests := []struct {
		input    string
		expected bool
	}{
		{"1", true},
		{"15", true},
		{"1a", true},
		{"2b", true},
		{"3rc", true},
		{"abc", false},
		{"", false},
		{"1x", false},
	}
	
	for _, test := range tests {
		result := extractor.looksLikeVersionPart(test.input)
		if result != test.expected {
			t.Errorf("For '%s': expected %t, got %t", test.input, test.expected, result)
		}
	}
}

func TestBinaryComponentExtractor_groupSymbolsByLibrary(t *testing.T) {
	extractor := NewBinaryComponentExtractor()
	
	symbols := []string{
		"std::string::size",
		"std::vector::push_back",
		"boost::filesystem::path",
		"boost::regex::match",
		"gtk_window_new",
		"gtk_widget_show",
		"cairo_create",
		"png_read_info",
		"unknown_symbol",
		"__internal_symbol",
	}
	
	groups := extractor.groupSymbolsByLibrary(symbols)
	
	// Check that we have expected groups
	expectedGroups := []string{"libstdc++", "boost", "GTK", "Cairo", "libpng"}
	for _, expected := range expectedGroups {
		if _, found := groups[expected]; !found {
			t.Errorf("Expected to find group '%s'", expected)
		}
	}
	
	// Check libstdc++ group
	if len(groups["libstdc++"]) != 2 {
		t.Errorf("Expected 2 symbols in libstdc++ group, got %d", len(groups["libstdc++"]))
	}
	
	// Check boost group
	if len(groups["boost"]) != 2 {
		t.Errorf("Expected 2 symbols in boost group, got %d", len(groups["boost"]))
	}
	
	// Check that internal symbols are not grouped
	for groupName, symbols := range groups {
		for _, symbol := range symbols {
			if symbol == "__internal_symbol" {
				t.Errorf("Internal symbol should not be in group '%s'", groupName)
			}
		}
	}
}

func TestBinaryComponentExtractor_inferLibraryFromSymbol(t *testing.T) {
	extractor := NewBinaryComponentExtractor()
	
	tests := []struct {
		symbol   string
		expected string
	}{
		{"std::string::size", "libstdc++"},
		{"boost::filesystem::path", "boost"},
		{"gtk_window_new", "GTK"},
		{"g_malloc", "GLib"},
		{"cairo_create", "Cairo"},
		{"png_read_info", "libpng"},
		{"jpeg_start_decompress", "libjpeg"},
		{"ssl_connect", "OpenSSL"},
		{"crypto_hash", "OpenSSL"},
		{"curl_easy_init", "libcurl"},
		{"sqlite3_open", "SQLite"},
		{"mysql_connect", "MySQL"},
		{"postgres_connect", "PostgreSQL"},
		{"xmlParseDoc", "libxml2"},
		{"json_parse", "JSON library"},
		{"deflate", "zlib"},
		{"BZ2_bzopen", "bzip2"},
		{"__internal_symbol", ""},
		{"unknown_symbol", ""},
	}
	
	for _, test := range tests {
		result := extractor.inferLibraryFromSymbol(test.symbol)
		if result != test.expected {
			t.Errorf("For symbol '%s': expected '%s', got '%s'", test.symbol, test.expected, result)
		}
	}
}

func TestBinaryComponentExtractor_calculateFileHash(t *testing.T) {
	// Create a temporary test file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test-file")
	testContent := []byte("test content for hashing")
	
	err := os.WriteFile(testFile, testContent, 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	
	extractor := NewBinaryComponentExtractor()
	hash, err := extractor.calculateFileHash(testFile)
	
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	if hash == "" {
		t.Error("Expected hash to be calculated")
	}
	
	// Hash should be 64 characters (SHA256 hex)
	if len(hash) != 64 {
		t.Errorf("Expected hash length 64, got %d", len(hash))
	}
	
	// Hash should be consistent
	hash2, err := extractor.calculateFileHash(testFile)
	if err != nil {
		t.Fatalf("Expected no error on second hash, got: %v", err)
	}
	
	if hash != hash2 {
		t.Error("Expected consistent hash values")
	}
}

func TestBinaryComponentExtractor_calculateFileHash_NonExistentFile(t *testing.T) {
	extractor := NewBinaryComponentExtractor()
	
	_, err := extractor.calculateFileHash("/non/existent/file")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}