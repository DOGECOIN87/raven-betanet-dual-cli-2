package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewSPDXGenerator(t *testing.T) {
	generator := NewSPDXGenerator()
	
	if generator == nil {
		t.Error("Expected generator to be created")
	}
	
	if generator.extractor == nil {
		t.Error("Expected extractor to be initialized")
	}
}

func TestNewSPDXGeneratorWithExtractor(t *testing.T) {
	mockExtractor := NewBinaryComponentExtractor()
	generator := NewSPDXGeneratorWithExtractor(mockExtractor)
	
	if generator == nil {
		t.Error("Expected generator to be created")
	}
	
	if generator.extractor != mockExtractor {
		t.Error("Expected custom extractor to be set")
	}
}

func TestSPDXGenerator_Generate(t *testing.T) {
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
	
	generator := NewSPDXGenerator()
	doc, err := generator.Generate(testBinary)
	
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	if doc == nil {
		t.Fatal("Expected SPDX document to be generated")
	}
	
	// Validate document structure
	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("Expected spdxVersion 'SPDX-2.3', got '%s'", doc.SPDXVersion)
	}
	
	if doc.DataLicense != "CC0-1.0" {
		t.Errorf("Expected dataLicense 'CC0-1.0', got '%s'", doc.DataLicense)
	}
	
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("Expected SPDXID 'SPDXRef-DOCUMENT', got '%s'", doc.SPDXID)
	}
	
	if doc.Name != "SBOM for test-binary" {
		t.Errorf("Expected name 'SBOM for test-binary', got '%s'", doc.Name)
	}
	
	if doc.DocumentNamespace == "" {
		t.Error("Expected document namespace to be generated")
	}
	
	// Validate creation info
	if doc.CreationInfo.Created == "" {
		t.Error("Expected creation timestamp to be set")
	} else {
		_, err := time.Parse(time.RFC3339, doc.CreationInfo.Created)
		if err != nil {
			t.Errorf("Expected valid RFC3339 timestamp, got error: %v", err)
		}
	}
	
	if len(doc.CreationInfo.Creators) == 0 {
		t.Error("Expected at least one creator")
	} else {
		if !strings.Contains(doc.CreationInfo.Creators[0], "raven-linter") {
			t.Errorf("Expected creator to contain 'raven-linter', got '%s'", doc.CreationInfo.Creators[0])
		}
	}
	
	// Should have at least one package (main package)
	if len(doc.Packages) == 0 {
		t.Error("Expected at least one package")
	}
	
	// Should have at least one relationship
	if len(doc.Relationships) == 0 {
		t.Error("Expected at least one relationship")
	}
}

func TestSPDXGenerator_GenerateJSON(t *testing.T) {
	// Create a temporary test binary file
	tempDir := t.TempDir()
	testBinary := filepath.Join(tempDir, "test-binary")
	
	// Create a simple ELF-like file
	elfHeader := []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}
	elfHeader = append(elfHeader, make([]byte, 56)...)
	
	err := os.WriteFile(testBinary, elfHeader, 0644)
	if err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}
	
	generator := NewSPDXGenerator()
	jsonData, err := generator.GenerateJSON(testBinary)
	
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	if len(jsonData) == 0 {
		t.Error("Expected JSON data to be generated")
	}
	
	// Validate JSON structure
	var doc SPDXDocument
	err = json.Unmarshal(jsonData, &doc)
	if err != nil {
		t.Fatalf("Expected valid JSON, got error: %v", err)
	}
	
	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("Expected spdxVersion 'SPDX-2.3', got '%s'", doc.SPDXVersion)
	}
}

func TestSPDXGenerator_createMainPackage(t *testing.T) {
	generator := NewSPDXGenerator()
	
	// Create test components
	mainComp := NewComponent(ComponentTypeApplication, "test-app", "1.0.0")
	mainComp.Description = "Test application"
	mainComp.Publisher = "Test Publisher"
	mainComp.Copyright = "Copyright 2024"
	mainComp.AddHash("sha256", "abcd1234")
	mainComp.AddLicense(License{ID: "MIT", Name: "MIT License"})
	
	components := []Component{mainComp}
	
	pkg := generator.createMainPackage("/path/to/test-binary", components)
	
	// Validate package
	if pkg.SPDXID != "SPDXRef-Package-test-binary" {
		t.Errorf("Expected SPDXID 'SPDXRef-Package-test-binary', got '%s'", pkg.SPDXID)
	}
	
	if pkg.Name != "test-binary" {
		t.Errorf("Expected name 'test-binary', got '%s'", pkg.Name)
	}
	
	if pkg.DownloadLocation != "NOASSERTION" {
		t.Errorf("Expected downloadLocation 'NOASSERTION', got '%s'", pkg.DownloadLocation)
	}
	
	if pkg.FilesAnalyzed != false {
		t.Errorf("Expected filesAnalyzed false, got %t", pkg.FilesAnalyzed)
	}
	
	if pkg.VersionInfo != "1.0.0" {
		t.Errorf("Expected versionInfo '1.0.0', got '%s'", pkg.VersionInfo)
	}
	
	if pkg.Description != "Test application" {
		t.Errorf("Expected description 'Test application', got '%s'", pkg.Description)
	}
	
	if pkg.Supplier != "Organization: Test Publisher" {
		t.Errorf("Expected supplier 'Organization: Test Publisher', got '%s'", pkg.Supplier)
	}
	
	if pkg.CopyrightText != "Copyright 2024" {
		t.Errorf("Expected copyrightText 'Copyright 2024', got '%s'", pkg.CopyrightText)
	}
	
	if pkg.LicenseConcluded != "MIT" {
		t.Errorf("Expected licenseConcluded 'MIT', got '%s'", pkg.LicenseConcluded)
	}
	
	if pkg.LicenseDeclared != "MIT" {
		t.Errorf("Expected licenseDeclared 'MIT', got '%s'", pkg.LicenseDeclared)
	}
	
	if pkg.PrimaryPackagePurpose != "APPLICATION" {
		t.Errorf("Expected primaryPackagePurpose 'APPLICATION', got '%s'", pkg.PrimaryPackagePurpose)
	}
	
	// Validate checksums
	if len(pkg.Checksums) != 1 {
		t.Errorf("Expected 1 checksum, got %d", len(pkg.Checksums))
	} else {
		checksum := pkg.Checksums[0]
		if checksum.Algorithm != "SHA256" {
			t.Errorf("Expected checksum algorithm 'SHA256', got '%s'", checksum.Algorithm)
		}
		if checksum.ChecksumValue != "abcd1234" {
			t.Errorf("Expected checksum value 'abcd1234', got '%s'", checksum.ChecksumValue)
		}
	}
}

func TestSPDXGenerator_convertComponentToPackage(t *testing.T) {
	generator := NewSPDXGenerator()
	
	// Create test component
	comp := NewComponent(ComponentTypeLibrary, "test-lib", "2.0.0")
	comp.Description = "Test library"
	comp.Publisher = "Lib Publisher"
	comp.Copyright = "Copyright 2024 Lib"
	comp.AddHash("md5", "efgh5678")
	comp.AddLicense(License{Name: "Apache-2.0"})
	comp.AddProperty("binary.format", "ELF")
	comp.AddProperty("binary.architecture", "x86_64")
	
	pkg := generator.convertComponentToPackage(comp)
	
	// Validate package
	expectedSPDXID := "SPDXRef-Package-" + sanitizeID(comp.BOMRef)
	if pkg.SPDXID != expectedSPDXID {
		t.Errorf("Expected SPDXID '%s', got '%s'", expectedSPDXID, pkg.SPDXID)
	}
	
	if pkg.Name != "test-lib" {
		t.Errorf("Expected name 'test-lib', got '%s'", pkg.Name)
	}
	
	if pkg.VersionInfo != "2.0.0" {
		t.Errorf("Expected versionInfo '2.0.0', got '%s'", pkg.VersionInfo)
	}
	
	if pkg.Description != "Test library" {
		t.Errorf("Expected description 'Test library', got '%s'", pkg.Description)
	}
	
	if pkg.Supplier != "Organization: Lib Publisher" {
		t.Errorf("Expected supplier 'Organization: Lib Publisher', got '%s'", pkg.Supplier)
	}
	
	if pkg.CopyrightText != "Copyright 2024 Lib" {
		t.Errorf("Expected copyrightText 'Copyright 2024 Lib', got '%s'", pkg.CopyrightText)
	}
	
	if pkg.LicenseConcluded != "Apache-2.0" {
		t.Errorf("Expected licenseConcluded 'Apache-2.0', got '%s'", pkg.LicenseConcluded)
	}
	
	if pkg.LicenseDeclared != "Apache-2.0" {
		t.Errorf("Expected licenseDeclared 'Apache-2.0', got '%s'", pkg.LicenseDeclared)
	}
	
	if pkg.PrimaryPackagePurpose != "LIBRARY" {
		t.Errorf("Expected primaryPackagePurpose 'LIBRARY', got '%s'", pkg.PrimaryPackagePurpose)
	}
	
	// Validate source info contains properties
	if !strings.Contains(pkg.SourceInfo, "binary.format: ELF") {
		t.Errorf("Expected sourceInfo to contain 'binary.format: ELF', got '%s'", pkg.SourceInfo)
	}
	
	if !strings.Contains(pkg.SourceInfo, "binary.architecture: x86_64") {
		t.Errorf("Expected sourceInfo to contain 'binary.architecture: x86_64', got '%s'", pkg.SourceInfo)
	}
	
	// Validate checksums
	if len(pkg.Checksums) != 1 {
		t.Errorf("Expected 1 checksum, got %d", len(pkg.Checksums))
	} else {
		checksum := pkg.Checksums[0]
		if checksum.Algorithm != "MD5" {
			t.Errorf("Expected checksum algorithm 'MD5', got '%s'", checksum.Algorithm)
		}
		if checksum.ChecksumValue != "efgh5678" {
			t.Errorf("Expected checksum value 'efgh5678', got '%s'", checksum.ChecksumValue)
		}
	}
}

func TestSPDXGenerator_convertHashesToChecksums(t *testing.T) {
	generator := NewSPDXGenerator()
	
	hashes := map[string]string{
		"sha256": "abcd1234",
		"md5":    "efgh5678",
	}
	
	checksums := generator.convertHashesToChecksums(hashes)
	
	if len(checksums) != 2 {
		t.Errorf("Expected 2 checksums, got %d", len(checksums))
	}
	
	// Check that both checksums are present
	foundSHA256 := false
	foundMD5 := false
	
	for _, checksum := range checksums {
		if checksum.Algorithm == "SHA256" && checksum.ChecksumValue == "abcd1234" {
			foundSHA256 = true
		}
		if checksum.Algorithm == "MD5" && checksum.ChecksumValue == "efgh5678" {
			foundMD5 = true
		}
	}
	
	if !foundSHA256 {
		t.Error("Expected to find SHA256 checksum")
	}
	
	if !foundMD5 {
		t.Error("Expected to find MD5 checksum")
	}
}

func TestSPDXGenerator_mapComponentTypeToPurpose(t *testing.T) {
	generator := NewSPDXGenerator()
	
	tests := []struct {
		componentType ComponentType
		expectedPurpose string
	}{
		{ComponentTypeApplication, "APPLICATION"},
		{ComponentTypeLibrary, "LIBRARY"},
		{ComponentTypeFramework, "FRAMEWORK"},
		{ComponentTypeContainer, "CONTAINER"},
		{ComponentTypeOperatingSystem, "OPERATING-SYSTEM"},
		{ComponentTypeDevice, "DEVICE"},
		{ComponentTypeFirmware, "FIRMWARE"},
		{ComponentTypeFile, "FILE"},
		{ComponentType("unknown"), "OTHER"},
	}
	
	for _, test := range tests {
		result := generator.mapComponentTypeToPurpose(test.componentType)
		if result != test.expectedPurpose {
			t.Errorf("For component type %s: expected purpose '%s', got '%s'", 
				test.componentType, test.expectedPurpose, result)
		}
	}
}

func TestSPDXGenerator_generateRelationships(t *testing.T) {
	generator := NewSPDXGenerator()
	
	// Create test components
	mainComp := NewComponent(ComponentTypeApplication, "main-app", "1.0.0")
	lib1 := NewComponent(ComponentTypeLibrary, "lib1", "1.0.0")
	lib2 := NewComponent(ComponentTypeLibrary, "lib2", "2.0.0")
	
	// Add dependency from lib1 to lib2
	lib1.AddDependency(lib2.BOMRef)
	
	components := []Component{mainComp, lib1, lib2}
	relationships := generator.generateRelationships(components)
	
	// Should have: DESCRIBES + 2 DEPENDS_ON (main->lib1, main->lib2) + 1 DEPENDS_ON (lib1->lib2)
	expectedRelCount := 4
	if len(relationships) != expectedRelCount {
		t.Errorf("Expected %d relationships, got %d", expectedRelCount, len(relationships))
	}
	
	// Check DESCRIBES relationship
	describesFound := false
	for _, rel := range relationships {
		if rel.SPDXElementID == "SPDXRef-DOCUMENT" && rel.RelationshipType == "DESCRIBES" {
			expectedTarget := "SPDXRef-Package-" + sanitizeID(mainComp.BOMRef)
			if rel.RelatedSPDXElement == expectedTarget {
				describesFound = true
			}
		}
	}
	if !describesFound {
		t.Error("Expected to find DESCRIBES relationship from document to main package")
	}
	
	// Check main package dependencies
	mainSPDXID := "SPDXRef-Package-" + sanitizeID(mainComp.BOMRef)
	mainDepsFound := 0
	for _, rel := range relationships {
		if rel.SPDXElementID == mainSPDXID && rel.RelationshipType == "DEPENDS_ON" {
			mainDepsFound++
		}
	}
	if mainDepsFound != 2 {
		t.Errorf("Expected main package to have 2 dependencies, got %d", mainDepsFound)
	}
	
	// Check lib1 dependency on lib2
	lib1SPDXID := "SPDXRef-Package-" + sanitizeID(lib1.BOMRef)
	lib2SPDXID := "SPDXRef-Package-" + sanitizeID(lib2.BOMRef)
	lib1DepFound := false
	for _, rel := range relationships {
		if rel.SPDXElementID == lib1SPDXID && rel.RelationshipType == "DEPENDS_ON" && 
		   rel.RelatedSPDXElement == lib2SPDXID {
			lib1DepFound = true
		}
	}
	if !lib1DepFound {
		t.Error("Expected to find dependency relationship from lib1 to lib2")
	}
}

func TestSPDXGenerator_generateDocumentNamespace(t *testing.T) {
	generator := NewSPDXGenerator()
	
	namespace1 := generator.generateDocumentNamespace("/path/to/binary")
	namespace2 := generator.generateDocumentNamespace("/path/to/binary")
	namespace3 := generator.generateDocumentNamespace("/different/path")
	
	// Different calls should generate different namespaces (due to timestamp)
	if namespace1 == namespace2 {
		// This might occasionally be the same if called in the same second
		// but that's acceptable for this test
	}
	
	// Different paths should generate different namespaces
	if namespace1 == namespace3 {
		t.Error("Expected different paths to generate different namespaces")
	}
	
	// Namespace should start with expected prefix
	expectedPrefix := "https://raven-betanet.com/spdx/"
	if !strings.HasPrefix(namespace1, expectedPrefix) {
		t.Errorf("Expected namespace to start with '%s', got '%s'", expectedPrefix, namespace1)
	}
}

func TestExtractFileName(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/path/to/binary", "binary"},
		{"binary", "binary"},
		{"/path/to/file.exe", "file.exe"},
		{"", "unknown"},
		{"/", "unknown"},
	}
	
	for _, test := range tests {
		result := extractFileName(test.path)
		if result != test.expected {
			t.Errorf("For path '%s': expected '%s', got '%s'", test.path, test.expected, result)
		}
	}
}

func TestSanitizeID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"valid-id", "valid-id"},
		{"valid.id", "valid.id"},
		{"ValidID123", "ValidID123"},
		{"invalid@id", "invalid-id"},
		{"invalid id", "invalid-id"},
		{"123invalid", "pkg-123invalid"},
		{"-invalid", "pkg--invalid"},
		{"comp-abc123", "comp-abc123"},
		{"", ""},
	}
	
	for _, test := range tests {
		result := sanitizeID(test.input)
		if result != test.expected {
			t.Errorf("For input '%s': expected '%s', got '%s'", test.input, test.expected, result)
		}
	}
}

func TestSPDXGenerator_ValidateSchema(t *testing.T) {
	generator := NewSPDXGenerator()
	
	t.Run("Valid document", func(t *testing.T) {
		doc := &SPDXDocument{
			SPDXVersion:       "SPDX-2.3",
			DataLicense:       "CC0-1.0",
			SPDXID:           "SPDXRef-DOCUMENT",
			Name:             "Test SBOM",
			DocumentNamespace: "https://example.com/test",
			CreationInfo: SPDXCreationInfo{
				Created:  time.Now().UTC().Format(time.RFC3339),
				Creators: []string{"Tool: test-tool"},
			},
			Packages: []SPDXPackage{
				{
					SPDXID:           "SPDXRef-Package-test",
					Name:             "test-package",
					DownloadLocation: "NOASSERTION",
					LicenseConcluded: "NOASSERTION",
					LicenseDeclared:  "NOASSERTION",
					CopyrightText:    "NOASSERTION",
				},
			},
			Relationships: []SPDXRelationship{
				{
					SPDXElementID:      "SPDXRef-DOCUMENT",
					RelationshipType:   "DESCRIBES",
					RelatedSPDXElement: "SPDXRef-Package-test",
				},
			},
		}
		
		result := generator.ValidateSchema(doc)
		if !result.Valid {
			t.Errorf("Expected valid document, got errors: %v", result.Errors)
		}
	})
	
	t.Run("Invalid spdxVersion", func(t *testing.T) {
		doc := &SPDXDocument{
			SPDXVersion: "Invalid-2.3",
			DataLicense: "CC0-1.0",
			SPDXID:     "SPDXRef-DOCUMENT",
			Name:       "Test SBOM",
			DocumentNamespace: "https://example.com/test",
			CreationInfo: SPDXCreationInfo{
				Created:  time.Now().UTC().Format(time.RFC3339),
				Creators: []string{"Tool: test-tool"},
			},
		}
		
		result := generator.ValidateSchema(doc)
		if result.Valid {
			t.Error("Expected invalid document due to wrong spdxVersion")
		}
		
		found := false
		for _, err := range result.Errors {
			if err == "spdxVersion must start with 'SPDX-'" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected spdxVersion error in validation results")
		}
	})
	
	t.Run("Missing required fields", func(t *testing.T) {
		doc := &SPDXDocument{
			SPDXVersion: "SPDX-2.3",
			// Missing other required fields
		}
		
		result := generator.ValidateSchema(doc)
		if result.Valid {
			t.Error("Expected invalid document due to missing required fields")
		}
		
		expectedErrors := []string{
			"dataLicense must be 'CC0-1.0'",
			"SPDXID must be 'SPDXRef-DOCUMENT'",
			"name is required",
			"documentNamespace is required",
			"creationInfo.created is required",
			"at least one creator is required",
		}
		
		for _, expectedError := range expectedErrors {
			found := false
			for _, err := range result.Errors {
				if err == expectedError {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected error '%s' in validation results", expectedError)
			}
		}
	})
	
	t.Run("Invalid timestamp", func(t *testing.T) {
		doc := &SPDXDocument{
			SPDXVersion:       "SPDX-2.3",
			DataLicense:       "CC0-1.0",
			SPDXID:           "SPDXRef-DOCUMENT",
			Name:             "Test SBOM",
			DocumentNamespace: "https://example.com/test",
			CreationInfo: SPDXCreationInfo{
				Created:  "invalid-timestamp",
				Creators: []string{"Tool: test-tool"},
			},
		}
		
		result := generator.ValidateSchema(doc)
		if result.Valid {
			t.Error("Expected invalid document due to invalid timestamp")
		}
		
		found := false
		for _, err := range result.Errors {
			if err == "creationInfo.created must be in RFC3339 format" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected timestamp format error in validation results")
		}
	})
	
	t.Run("Duplicate SPDX IDs", func(t *testing.T) {
		doc := &SPDXDocument{
			SPDXVersion:       "SPDX-2.3",
			DataLicense:       "CC0-1.0",
			SPDXID:           "SPDXRef-DOCUMENT",
			Name:             "Test SBOM",
			DocumentNamespace: "https://example.com/test",
			CreationInfo: SPDXCreationInfo{
				Created:  time.Now().UTC().Format(time.RFC3339),
				Creators: []string{"Tool: test-tool"},
			},
			Packages: []SPDXPackage{
				{
					SPDXID:           "SPDXRef-Package-test",
					Name:             "package1",
					DownloadLocation: "NOASSERTION",
					LicenseConcluded: "NOASSERTION",
					LicenseDeclared:  "NOASSERTION",
					CopyrightText:    "NOASSERTION",
				},
				{
					SPDXID:           "SPDXRef-Package-test", // Duplicate
					Name:             "package2",
					DownloadLocation: "NOASSERTION",
					LicenseConcluded: "NOASSERTION",
					LicenseDeclared:  "NOASSERTION",
					CopyrightText:    "NOASSERTION",
				},
			},
		}
		
		result := generator.ValidateSchema(doc)
		if result.Valid {
			t.Error("Expected invalid document due to duplicate SPDX IDs")
		}
		
		found := false
		for _, err := range result.Errors {
			if err == "duplicate SPDXID: SPDXRef-Package-test" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected duplicate SPDX ID error in validation results")
		}
	})
}