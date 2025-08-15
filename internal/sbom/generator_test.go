package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewGenerator(t *testing.T) {
	generator := NewGenerator()
	
	if generator == nil {
		t.Error("Expected generator to be created")
	}
	
	if generator.extractor == nil {
		t.Error("Expected extractor to be initialized")
	}
}

func TestNewGeneratorWithExtractor(t *testing.T) {
	mockExtractor := NewBinaryComponentExtractor()
	generator := NewGeneratorWithExtractor(mockExtractor)
	
	if generator == nil {
		t.Error("Expected generator to be created")
	}
	
	if generator.extractor != mockExtractor {
		t.Error("Expected custom extractor to be set")
	}
}

func TestGenerator_GetSupportedFormats(t *testing.T) {
	generator := NewGenerator()
	formats := generator.GetSupportedFormats()
	
	expectedFormats := []SBOMFormat{CycloneDX, SPDX}
	
	if len(formats) != len(expectedFormats) {
		t.Errorf("Expected %d formats, got %d", len(expectedFormats), len(formats))
	}
	
	for i, expected := range expectedFormats {
		if formats[i] != expected {
			t.Errorf("Expected format %s, got %s", expected, formats[i])
		}
	}
}

func TestGenerator_Generate_NonExistentFile(t *testing.T) {
	generator := NewGenerator()
	
	_, err := generator.Generate("/non/existent/file", CycloneDX)
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestGenerator_Generate_ValidBinary(t *testing.T) {
	// Use the actual valid ELF binary from fixtures
	testBinary := "../../tests/fixtures/sample_binaries/valid_elf_binary"
	
	// Check if the test binary exists
	if _, err := os.Stat(testBinary); os.IsNotExist(err) {
		t.Skip("Test binary not found, skipping test")
	}
	
	generator := NewGenerator()
	sbom, err := generator.Generate(testBinary, CycloneDX)
	
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	if sbom == nil {
		t.Fatal("Expected SBOM to be generated")
	}
	
	if sbom.Format != CycloneDX {
		t.Errorf("Expected format %s, got %s", CycloneDX, sbom.Format)
	}
	
	if sbom.Version != "1.5" {
		t.Errorf("Expected version '1.5', got '%s'", sbom.Version)
	}
	
	if sbom.Metadata.Target.Name != "test-binary" {
		t.Errorf("Expected target name 'test-binary', got '%s'", sbom.Metadata.Target.Name)
	}
	
	if len(sbom.Metadata.Target.Hashes) == 0 {
		t.Error("Expected target to have hashes")
	}
	
	if sbom.Metadata.SerialNumber == "" {
		t.Error("Expected serial number to be generated")
	}
	
	if len(sbom.Components) == 0 {
		t.Error("Expected at least one component")
	}
}

func TestGenerator_WriteToFile_CycloneDX(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "test-sbom.json")
	
	// Create a test SBOM
	sbom := NewSBOM(CycloneDX)
	sbom.SetVersion()
	sbom.SetTarget("test-binary", "/path/to/test-binary", 1024, 
		map[string]string{"sha256": "abcd1234"}, "x86_64", "ELF")
	
	comp := NewComponent(ComponentTypeLibrary, "test-lib", "1.0.0")
	sbom.AddComponent(comp)
	
	generator := NewGenerator()
	err := generator.WriteToFile(sbom, outputPath)
	
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	// Check that file was created
	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("Expected output file to be created: %v", err)
	}
	
	// Read and validate JSON structure
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}
	
	var cycloneDX map[string]interface{}
	err = json.Unmarshal(data, &cycloneDX)
	if err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	
	// Validate CycloneDX structure
	if cycloneDX["bomFormat"] != "CycloneDX" {
		t.Errorf("Expected bomFormat 'CycloneDX', got '%v'", cycloneDX["bomFormat"])
	}
	
	if cycloneDX["specVersion"] != "1.5" {
		t.Errorf("Expected specVersion '1.5', got '%v'", cycloneDX["specVersion"])
	}
	
	components, ok := cycloneDX["components"].([]interface{})
	if !ok {
		t.Fatal("Expected components to be an array")
	}
	
	if len(components) != 1 {
		t.Errorf("Expected 1 component, got %d", len(components))
	}
}

func TestGenerator_WriteToFile_SPDX(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "test-sbom.json")
	
	// Create a test SBOM
	sbom := NewSBOM(SPDX)
	sbom.SetVersion()
	sbom.SetTarget("test-binary", "/path/to/test-binary", 1024, 
		map[string]string{"sha256": "abcd1234"}, "x86_64", "ELF")
	
	comp := NewComponent(ComponentTypeLibrary, "test-lib", "1.0.0")
	sbom.AddComponent(comp)
	
	generator := NewGenerator()
	err := generator.WriteToFile(sbom, outputPath)
	
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	// Check that file was created
	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("Expected output file to be created: %v", err)
	}
	
	// Read and validate JSON structure
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}
	
	var spdx map[string]interface{}
	err = json.Unmarshal(data, &spdx)
	if err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	
	// Validate SPDX structure
	if spdx["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("Expected spdxVersion 'SPDX-2.3', got '%v'", spdx["spdxVersion"])
	}
	
	if spdx["dataLicense"] != "CC0-1.0" {
		t.Errorf("Expected dataLicense 'CC0-1.0', got '%v'", spdx["dataLicense"])
	}
	
	packages, ok := spdx["packages"].([]interface{})
	if !ok {
		t.Fatal("Expected packages to be an array")
	}
	
	// Should have main package + 1 component = 2 packages
	if len(packages) != 2 {
		t.Errorf("Expected 2 packages, got %d", len(packages))
	}
}

func TestGenerator_WriteToFile_UnsupportedFormat(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "test-sbom.json")
	
	// Create a test SBOM with unsupported format
	sbom := NewSBOM(SBOMFormat(999))
	
	generator := NewGenerator()
	err := generator.WriteToFile(sbom, outputPath)
	
	if err == nil {
		t.Error("Expected error for unsupported format")
	}
}

func TestGenerator_setTargetInfo(t *testing.T) {
	// Create a temporary test file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test-binary")
	testContent := []byte("test binary content")
	
	err := os.WriteFile(testFile, testContent, 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	
	generator := NewGenerator()
	sbom := NewSBOM(CycloneDX)
	
	err = generator.setTargetInfo(sbom, testFile)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	target := sbom.Metadata.Target
	if target.Name != "test-binary" {
		t.Errorf("Expected target name 'test-binary', got '%s'", target.Name)
	}
	
	if target.Path != testFile {
		t.Errorf("Expected target path '%s', got '%s'", testFile, target.Path)
	}
	
	if target.Size != int64(len(testContent)) {
		t.Errorf("Expected target size %d, got %d", len(testContent), target.Size)
	}
	
	if len(target.Hashes) == 0 {
		t.Error("Expected target to have hashes")
	}
	
	if target.Hashes["sha256"] == "" {
		t.Error("Expected SHA256 hash to be calculated")
	}
}

func TestGenerator_generateSerialNumber(t *testing.T) {
	generator := NewGenerator()
	timestamp := time.Now()
	
	serial1 := generator.generateSerialNumber("/path/to/binary", timestamp)
	serial2 := generator.generateSerialNumber("/path/to/binary", timestamp)
	serial3 := generator.generateSerialNumber("/different/path", timestamp)
	
	// Same inputs should generate same serial number
	if serial1 != serial2 {
		t.Error("Expected same inputs to generate same serial number")
	}
	
	// Different inputs should generate different serial numbers
	if serial1 == serial3 {
		t.Error("Expected different inputs to generate different serial numbers")
	}
	
	// Serial number should be in URN format
	if len(serial1) < 10 || serial1[:9] != "urn:uuid:" {
		t.Errorf("Expected serial number to start with 'urn:uuid:', got '%s'", serial1)
	}
}

func TestGenerator_calculateFileHash(t *testing.T) {
	// Create a temporary test file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test-file")
	testContent := []byte("test content for hashing")
	
	err := os.WriteFile(testFile, testContent, 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	
	generator := NewGenerator()
	hash, err := generator.calculateFileHash(testFile)
	
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
	hash2, err := generator.calculateFileHash(testFile)
	if err != nil {
		t.Fatalf("Expected no error on second hash, got: %v", err)
	}
	
	if hash != hash2 {
		t.Error("Expected consistent hash values")
	}
}

func TestGenerator_detectBinaryInfo(t *testing.T) {
	generator := NewGenerator()
	
	tests := []struct {
		name             string
		header           []byte
		expectedFormat   string
		expectedArch     string
	}{
		{
			name:           "ELF x86_64",
			header:         append([]byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x00}, make([]byte, 20)...),
			expectedFormat: "ELF",
			expectedArch:   "x86_64",
		},
		{
			name:           "ELF i386",
			header:         append([]byte{0x7F, 'E', 'L', 'F', 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00}, make([]byte, 20)...),
			expectedFormat: "ELF",
			expectedArch:   "i386",
		},
		{
			name:           "PE",
			header:         append([]byte{'M', 'Z', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, make([]byte, 20)...),
			expectedFormat: "PE",
			expectedArch:   "x86",
		},
		{
			name:           "Mach-O",
			header:         append([]byte{0xfe, 0xed, 0xfa, 0xce, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, make([]byte, 20)...),
			expectedFormat: "Mach-O",
			expectedArch:   "unknown",
		},
		{
			name:           "Unknown",
			header:         append([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, make([]byte, 20)...),
			expectedFormat: "unknown",
			expectedArch:   "unknown",
		},
	}
	
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create temporary file with test header
			tempDir := t.TempDir()
			testFile := filepath.Join(tempDir, "test-binary")
			
			err := os.WriteFile(testFile, test.header, 0644)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}
			
			format, arch, err := generator.detectBinaryInfo(testFile)
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}
			
			if format != test.expectedFormat {
				t.Errorf("Expected format '%s', got '%s'", test.expectedFormat, format)
			}
			
			if arch != test.expectedArch {
				t.Errorf("Expected architecture '%s', got '%s'", test.expectedArch, arch)
			}
		})
	}
}

func TestGenerator_convertHashesForCycloneDX(t *testing.T) {
	generator := NewGenerator()
	
	hashes := map[string]string{
		"sha256": "abcd1234",
		"md5":    "efgh5678",
	}
	
	result := generator.convertHashesForCycloneDX(hashes)
	
	if len(result) != 2 {
		t.Errorf("Expected 2 hashes, got %d", len(result))
	}
	
	// Check that both hashes are present
	foundSHA256 := false
	foundMD5 := false
	
	for _, hash := range result {
		if hash["alg"] == "sha256" && hash["content"] == "abcd1234" {
			foundSHA256 = true
		}
		if hash["alg"] == "md5" && hash["content"] == "efgh5678" {
			foundMD5 = true
		}
	}
	
	if !foundSHA256 {
		t.Error("Expected to find SHA256 hash")
	}
	
	if !foundMD5 {
		t.Error("Expected to find MD5 hash")
	}
}

func TestGenerator_convertComponentsForCycloneDX(t *testing.T) {
	generator := NewGenerator()
	
	comp := NewComponent(ComponentTypeLibrary, "test-lib", "1.0.0")
	comp.Description = "Test library"
	comp.Publisher = "Test Publisher"
	comp.Group = "test.group"
	comp.Scope = ScopeRequired
	comp.AddHash("sha256", "abcd1234")
	comp.AddLicense(License{ID: "MIT", Name: "MIT License"})
	comp.AddProperty("test-prop", "test-value")
	
	components := []Component{comp}
	result := generator.convertComponentsForCycloneDX(components)
	
	if len(result) != 1 {
		t.Errorf("Expected 1 component, got %d", len(result))
	}
	
	cyclonComp := result[0]
	
	if cyclonComp["type"] != string(ComponentTypeLibrary) {
		t.Errorf("Expected type '%s', got '%v'", ComponentTypeLibrary, cyclonComp["type"])
	}
	
	if cyclonComp["name"] != "test-lib" {
		t.Errorf("Expected name 'test-lib', got '%v'", cyclonComp["name"])
	}
	
	if cyclonComp["version"] != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%v'", cyclonComp["version"])
	}
	
	if cyclonComp["description"] != "Test library" {
		t.Errorf("Expected description 'Test library', got '%v'", cyclonComp["description"])
	}
	
	if cyclonComp["publisher"] != "Test Publisher" {
		t.Errorf("Expected publisher 'Test Publisher', got '%v'", cyclonComp["publisher"])
	}
	
	if cyclonComp["group"] != "test.group" {
		t.Errorf("Expected group 'test.group', got '%v'", cyclonComp["group"])
	}
	
	if cyclonComp["scope"] != string(ScopeRequired) {
		t.Errorf("Expected scope '%s', got '%v'", ScopeRequired, cyclonComp["scope"])
	}
	
	// Check hashes
	hashes, ok := cyclonComp["hashes"].([]map[string]string)
	if !ok || len(hashes) != 1 {
		t.Error("Expected hashes array with 1 element")
	} else if hashes[0]["alg"] != "sha256" || hashes[0]["content"] != "abcd1234" {
		t.Error("Expected correct hash format")
	}
	
	// Check licenses
	licenses, ok := cyclonComp["licenses"].([]map[string]interface{})
	if !ok || len(licenses) != 1 {
		t.Error("Expected licenses array with 1 element")
	}
	
	// Check properties
	properties, ok := cyclonComp["properties"].([]map[string]string)
	if !ok || len(properties) != 1 {
		t.Error("Expected properties array with 1 element")
	} else if properties[0]["name"] != "test-prop" || properties[0]["value"] != "test-value" {
		t.Error("Expected correct property format")
	}
}

func TestGenerator_convertComponentsForSPDX(t *testing.T) {
	generator := NewGenerator()
	
	comp := NewComponent(ComponentTypeLibrary, "test-lib", "1.0.0")
	comp.Description = "Test library"
	comp.Publisher = "Test Publisher"
	comp.AddHash("sha256", "abcd1234")
	comp.AddLicense(License{ID: "MIT", Name: "MIT License"})
	
	target := Target{
		Name:         "test-binary",
		Path:         "/path/to/binary",
		Size:         1024,
		Hashes:       map[string]string{"sha256": "target-hash"},
		Architecture: "x86_64",
		Format:       "ELF",
	}
	
	components := []Component{comp}
	result := generator.convertComponentsForSPDX(components, target)
	
	// Should have main package + 1 component = 2 packages
	if len(result) != 2 {
		t.Errorf("Expected 2 packages, got %d", len(result))
	}
	
	// Check main package
	mainPkg := result[0]
	if mainPkg["name"] != "test-binary" {
		t.Errorf("Expected main package name 'test-binary', got '%v'", mainPkg["name"])
	}
	
	// Check component package
	compPkg := result[1]
	if compPkg["name"] != "test-lib" {
		t.Errorf("Expected component package name 'test-lib', got '%v'", compPkg["name"])
	}
	
	if compPkg["versionInfo"] != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%v'", compPkg["versionInfo"])
	}
	
	if compPkg["description"] != "Test library" {
		t.Errorf("Expected description 'Test library', got '%v'", compPkg["description"])
	}
	
	if compPkg["supplier"] != "Organization: Test Publisher" {
		t.Errorf("Expected supplier 'Organization: Test Publisher', got '%v'", compPkg["supplier"])
	}
	
	if compPkg["licenseConcluded"] != "MIT" {
		t.Errorf("Expected licenseConcluded 'MIT', got '%v'", compPkg["licenseConcluded"])
	}
}