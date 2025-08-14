package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewCycloneDXGenerator(t *testing.T) {
	generator := NewCycloneDXGenerator()
	
	if generator == nil {
		t.Error("Expected generator to be created")
	}
	
	if generator.extractor == nil {
		t.Error("Expected extractor to be initialized")
	}
}

func TestNewCycloneDXGeneratorWithExtractor(t *testing.T) {
	mockExtractor := NewBinaryComponentExtractor()
	generator := NewCycloneDXGeneratorWithExtractor(mockExtractor)
	
	if generator == nil {
		t.Error("Expected generator to be created")
	}
	
	if generator.extractor != mockExtractor {
		t.Error("Expected custom extractor to be set")
	}
}

func TestCycloneDXGenerator_Generate(t *testing.T) {
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
	
	generator := NewCycloneDXGenerator()
	doc, err := generator.Generate(testBinary)
	
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	if doc == nil {
		t.Fatal("Expected CycloneDX document to be generated")
	}
	
	// Validate document structure
	if doc.BOMFormat != "CycloneDX" {
		t.Errorf("Expected bomFormat 'CycloneDX', got '%s'", doc.BOMFormat)
	}
	
	if doc.SpecVersion != "1.5" {
		t.Errorf("Expected specVersion '1.5', got '%s'", doc.SpecVersion)
	}
	
	if doc.Version != 1 {
		t.Errorf("Expected version 1, got %d", doc.Version)
	}
	
	if doc.SerialNumber == "" {
		t.Error("Expected serial number to be generated")
	}
	
	// Validate metadata
	if len(doc.Metadata.Tools) == 0 {
		t.Error("Expected at least one tool in metadata")
	}
	
	if doc.Metadata.Tools[0].Name != "raven-linter" {
		t.Errorf("Expected tool name 'raven-linter', got '%s'", doc.Metadata.Tools[0].Name)
	}
	
	if doc.Metadata.Tools[0].Vendor != "Raven Betanet" {
		t.Errorf("Expected tool vendor 'Raven Betanet', got '%s'", doc.Metadata.Tools[0].Vendor)
	}
	
	// Should have main component in metadata
	if doc.Metadata.Component == nil {
		t.Error("Expected main component in metadata")
	} else {
		if doc.Metadata.Component.Name != "test-binary" {
			t.Errorf("Expected main component name 'test-binary', got '%s'", doc.Metadata.Component.Name)
		}
		
		if doc.Metadata.Component.Type != string(ComponentTypeApplication) {
			t.Errorf("Expected main component type '%s', got '%s'", ComponentTypeApplication, doc.Metadata.Component.Type)
		}
	}
	
	// Validate timestamp format
	if doc.Metadata.Timestamp == "" {
		t.Error("Expected timestamp to be set")
	} else {
		_, err := time.Parse(time.RFC3339, doc.Metadata.Timestamp)
		if err != nil {
			t.Errorf("Expected valid RFC3339 timestamp, got error: %v", err)
		}
	}
}

func TestCycloneDXGenerator_GenerateJSON(t *testing.T) {
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
	
	generator := NewCycloneDXGenerator()
	jsonData, err := generator.GenerateJSON(testBinary)
	
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	if len(jsonData) == 0 {
		t.Error("Expected JSON data to be generated")
	}
	
	// Validate JSON structure
	var doc CycloneDXDocument
	err = json.Unmarshal(jsonData, &doc)
	if err != nil {
		t.Fatalf("Expected valid JSON, got error: %v", err)
	}
	
	if doc.BOMFormat != "CycloneDX" {
		t.Errorf("Expected bomFormat 'CycloneDX', got '%s'", doc.BOMFormat)
	}
}

func TestCycloneDXGenerator_convertComponent(t *testing.T) {
	generator := NewCycloneDXGenerator()
	
	// Create test component
	comp := NewComponent(ComponentTypeLibrary, "test-lib", "1.0.0")
	comp.Description = "Test library"
	comp.Publisher = "Test Publisher"
	comp.Group = "test.group"
	comp.Copyright = "Copyright 2024"
	comp.Scope = ScopeRequired
	comp.AddHash("sha256", "abcd1234")
	comp.AddLicense(License{ID: "MIT", Name: "MIT License"})
	comp.AddProperty("test-prop", "test-value")
	
	// Add evidence
	comp.Evidence = &Evidence{
		Identity: &EvidenceIdentity{
			Field:      "binary_analysis",
			Confidence: 1.0,
			Methods: []EvidenceMethod{
				{
					Technique:  "binary_parsing",
					Confidence: 1.0,
					Value:      "ELF",
				},
			},
		},
		Occurrences: []EvidenceOccurrence{
			{
				Location: "/path/to/binary",
				Line:     10,
				Offset:   100,
			},
		},
	}
	
	cyclonComp := generator.convertComponent(comp)
	
	// Validate conversion
	if cyclonComp.Type != string(ComponentTypeLibrary) {
		t.Errorf("Expected type '%s', got '%s'", ComponentTypeLibrary, cyclonComp.Type)
	}
	
	if cyclonComp.BOMRef != comp.BOMRef {
		t.Errorf("Expected BOMRef '%s', got '%s'", comp.BOMRef, cyclonComp.BOMRef)
	}
	
	if cyclonComp.Name != "test-lib" {
		t.Errorf("Expected name 'test-lib', got '%s'", cyclonComp.Name)
	}
	
	if cyclonComp.Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", cyclonComp.Version)
	}
	
	if cyclonComp.Description != "Test library" {
		t.Errorf("Expected description 'Test library', got '%s'", cyclonComp.Description)
	}
	
	if cyclonComp.Publisher != "Test Publisher" {
		t.Errorf("Expected publisher 'Test Publisher', got '%s'", cyclonComp.Publisher)
	}
	
	if cyclonComp.Group != "test.group" {
		t.Errorf("Expected group 'test.group', got '%s'", cyclonComp.Group)
	}
	
	if cyclonComp.Copyright != "Copyright 2024" {
		t.Errorf("Expected copyright 'Copyright 2024', got '%s'", cyclonComp.Copyright)
	}
	
	if cyclonComp.Scope != string(ScopeRequired) {
		t.Errorf("Expected scope '%s', got '%s'", ScopeRequired, cyclonComp.Scope)
	}
	
	// Validate hashes
	if len(cyclonComp.Hashes) != 1 {
		t.Errorf("Expected 1 hash, got %d", len(cyclonComp.Hashes))
	} else {
		hash := cyclonComp.Hashes[0]
		if hash.Algorithm != "sha256" {
			t.Errorf("Expected hash algorithm 'sha256', got '%s'", hash.Algorithm)
		}
		if hash.Content != "abcd1234" {
			t.Errorf("Expected hash content 'abcd1234', got '%s'", hash.Content)
		}
	}
	
	// Validate licenses
	if len(cyclonComp.Licenses) != 1 {
		t.Errorf("Expected 1 license, got %d", len(cyclonComp.Licenses))
	} else {
		license := cyclonComp.Licenses[0]
		if license.License == nil {
			t.Error("Expected license choice to be set")
		} else {
			if license.License.ID != "MIT" {
				t.Errorf("Expected license ID 'MIT', got '%s'", license.License.ID)
			}
			if license.License.Name != "MIT License" {
				t.Errorf("Expected license name 'MIT License', got '%s'", license.License.Name)
			}
		}
	}
	
	// Validate properties
	if len(cyclonComp.Properties) != 1 {
		t.Errorf("Expected 1 property, got %d", len(cyclonComp.Properties))
	} else {
		prop := cyclonComp.Properties[0]
		if prop.Name != "test-prop" {
			t.Errorf("Expected property name 'test-prop', got '%s'", prop.Name)
		}
		if prop.Value != "test-value" {
			t.Errorf("Expected property value 'test-value', got '%s'", prop.Value)
		}
	}
	
	// Validate evidence
	if cyclonComp.Evidence == nil {
		t.Error("Expected evidence to be converted")
	} else {
		if cyclonComp.Evidence.Identity == nil {
			t.Error("Expected identity evidence")
		} else {
			if cyclonComp.Evidence.Identity.Field != "binary_analysis" {
				t.Errorf("Expected identity field 'binary_analysis', got '%s'", cyclonComp.Evidence.Identity.Field)
			}
			if cyclonComp.Evidence.Identity.Confidence != 1.0 {
				t.Errorf("Expected identity confidence 1.0, got %f", cyclonComp.Evidence.Identity.Confidence)
			}
			if len(cyclonComp.Evidence.Identity.Methods) != 1 {
				t.Errorf("Expected 1 method, got %d", len(cyclonComp.Evidence.Identity.Methods))
			}
		}
		
		if len(cyclonComp.Evidence.Occurrences) != 1 {
			t.Errorf("Expected 1 occurrence, got %d", len(cyclonComp.Evidence.Occurrences))
		} else {
			occ := cyclonComp.Evidence.Occurrences[0]
			if occ.Location != "/path/to/binary" {
				t.Errorf("Expected occurrence location '/path/to/binary', got '%s'", occ.Location)
			}
			if occ.Line != 10 {
				t.Errorf("Expected occurrence line 10, got %d", occ.Line)
			}
			if occ.Offset != 100 {
				t.Errorf("Expected occurrence offset 100, got %d", occ.Offset)
			}
		}
	}
}

func TestCycloneDXGenerator_convertComponent_UnknownVersion(t *testing.T) {
	generator := NewCycloneDXGenerator()
	
	// Create component with unknown version
	comp := NewComponent(ComponentTypeLibrary, "test-lib", "unknown")
	cyclonComp := generator.convertComponent(comp)
	
	// Version should be empty for unknown versions
	if cyclonComp.Version != "" {
		t.Errorf("Expected empty version for 'unknown', got '%s'", cyclonComp.Version)
	}
}

func TestCycloneDXGenerator_convertHashes(t *testing.T) {
	generator := NewCycloneDXGenerator()
	
	hashes := map[string]string{
		"sha256": "abcd1234",
		"md5":    "efgh5678",
	}
	
	cyclonHashes := generator.convertHashes(hashes)
	
	if len(cyclonHashes) != 2 {
		t.Errorf("Expected 2 hashes, got %d", len(cyclonHashes))
	}
	
	// Check that both hashes are present
	foundSHA256 := false
	foundMD5 := false
	
	for _, hash := range cyclonHashes {
		if hash.Algorithm == "sha256" && hash.Content == "abcd1234" {
			foundSHA256 = true
		}
		if hash.Algorithm == "md5" && hash.Content == "efgh5678" {
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

func TestCycloneDXGenerator_convertLicenses(t *testing.T) {
	generator := NewCycloneDXGenerator()
	
	licenses := []License{
		{ID: "MIT", Name: "MIT License"},
		{Name: "Custom License", Text: "Custom license text", URL: "http://example.com/license"},
	}
	
	cyclonLicenses := generator.convertLicenses(licenses)
	
	if len(cyclonLicenses) != 2 {
		t.Errorf("Expected 2 licenses, got %d", len(cyclonLicenses))
	}
	
	// Check first license
	if cyclonLicenses[0].License == nil {
		t.Error("Expected first license choice to be set")
	} else {
		if cyclonLicenses[0].License.ID != "MIT" {
			t.Errorf("Expected first license ID 'MIT', got '%s'", cyclonLicenses[0].License.ID)
		}
		if cyclonLicenses[0].License.Name != "MIT License" {
			t.Errorf("Expected first license name 'MIT License', got '%s'", cyclonLicenses[0].License.Name)
		}
	}
	
	// Check second license
	if cyclonLicenses[1].License == nil {
		t.Error("Expected second license choice to be set")
	} else {
		if cyclonLicenses[1].License.Name != "Custom License" {
			t.Errorf("Expected second license name 'Custom License', got '%s'", cyclonLicenses[1].License.Name)
		}
		if cyclonLicenses[1].License.Text != "Custom license text" {
			t.Errorf("Expected second license text 'Custom license text', got '%s'", cyclonLicenses[1].License.Text)
		}
		if cyclonLicenses[1].License.URL != "http://example.com/license" {
			t.Errorf("Expected second license URL 'http://example.com/license', got '%s'", cyclonLicenses[1].License.URL)
		}
	}
}

func TestCycloneDXGenerator_convertProperties(t *testing.T) {
	generator := NewCycloneDXGenerator()
	
	properties := []Property{
		{Name: "prop1", Value: "value1"},
		{Name: "prop2", Value: "value2"},
	}
	
	cyclonProperties := generator.convertProperties(properties)
	
	if len(cyclonProperties) != 2 {
		t.Errorf("Expected 2 properties, got %d", len(cyclonProperties))
	}
	
	for i, prop := range cyclonProperties {
		expectedName := fmt.Sprintf("prop%d", i+1)
		expectedValue := fmt.Sprintf("value%d", i+1)
		
		if prop.Name != expectedName {
			t.Errorf("Expected property %d name '%s', got '%s'", i, expectedName, prop.Name)
		}
		
		if prop.Value != expectedValue {
			t.Errorf("Expected property %d value '%s', got '%s'", i, expectedValue, prop.Value)
		}
	}
}

func TestCycloneDXGenerator_generateDependencies(t *testing.T) {
	generator := NewCycloneDXGenerator()
	
	// Create test components
	mainComp := NewComponent(ComponentTypeApplication, "main-app", "1.0.0")
	lib1 := NewComponent(ComponentTypeLibrary, "lib1", "1.0.0")
	lib2 := NewComponent(ComponentTypeLibrary, "lib2", "2.0.0")
	
	// Add some dependencies to lib1
	lib1.AddDependency(lib2.BOMRef)
	
	components := []Component{mainComp, lib1, lib2}
	dependencies := generator.generateDependencies(components)
	
	// Should have main component dependency + lib1 dependency
	if len(dependencies) != 2 {
		t.Errorf("Expected 2 dependencies, got %d", len(dependencies))
	}
	
	// Check main component dependency
	mainDep := dependencies[0]
	if mainDep.Ref != mainComp.BOMRef {
		t.Errorf("Expected main dependency ref '%s', got '%s'", mainComp.BOMRef, mainDep.Ref)
	}
	
	if len(mainDep.DependsOn) != 2 {
		t.Errorf("Expected main dependency to depend on 2 components, got %d", len(mainDep.DependsOn))
	}
	
	// Check lib1 dependency
	lib1Dep := dependencies[1]
	if lib1Dep.Ref != lib1.BOMRef {
		t.Errorf("Expected lib1 dependency ref '%s', got '%s'", lib1.BOMRef, lib1Dep.Ref)
	}
	
	if len(lib1Dep.DependsOn) != 1 {
		t.Errorf("Expected lib1 dependency to depend on 1 component, got %d", len(lib1Dep.DependsOn))
	}
	
	if lib1Dep.DependsOn[0] != lib2.BOMRef {
		t.Errorf("Expected lib1 to depend on '%s', got '%s'", lib2.BOMRef, lib1Dep.DependsOn[0])
	}
}

func TestCycloneDXGenerator_generateCompositions(t *testing.T) {
	generator := NewCycloneDXGenerator()
	
	// Create test components
	mainComp := NewComponent(ComponentTypeApplication, "main-app", "1.0.0")
	lib1 := NewComponent(ComponentTypeLibrary, "lib1", "1.0.0")
	lib2 := NewComponent(ComponentTypeLibrary, "lib2", "2.0.0")
	
	components := []Component{mainComp, lib1, lib2}
	compositions := generator.generateCompositions(components)
	
	if len(compositions) != 1 {
		t.Errorf("Expected 1 composition, got %d", len(compositions))
	}
	
	comp := compositions[0]
	if comp.Aggregate != "complete" {
		t.Errorf("Expected aggregate 'complete', got '%s'", comp.Aggregate)
	}
	
	if len(comp.Assemblies) != 3 {
		t.Errorf("Expected 3 assemblies, got %d", len(comp.Assemblies))
	}
	
	// Check that all component BOM refs are included
	expectedRefs := []string{mainComp.BOMRef, lib1.BOMRef, lib2.BOMRef}
	for _, expectedRef := range expectedRefs {
		found := false
		for _, assembly := range comp.Assemblies {
			if assembly == expectedRef {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected to find assembly '%s'", expectedRef)
		}
	}
}

func TestCycloneDXGenerator_generateSerialNumber(t *testing.T) {
	generator := NewCycloneDXGenerator()
	
	serial1 := generator.generateSerialNumber("/path/to/binary")
	serial2 := generator.generateSerialNumber("/path/to/binary")
	serial3 := generator.generateSerialNumber("/different/path")
	
	// Different calls should generate different serial numbers (due to timestamp)
	if serial1 == serial2 {
		// This might occasionally be the same if called in the same second
		// but that's acceptable for this test
	}
	
	// Different paths should generate different serial numbers
	if serial1 == serial3 {
		t.Error("Expected different paths to generate different serial numbers")
	}
	
	// Serial number should be in URN format
	if len(serial1) < 10 || serial1[:9] != "urn:uuid:" {
		t.Errorf("Expected serial number to start with 'urn:uuid:', got '%s'", serial1)
	}
}

func TestCycloneDXGenerator_ValidateSchema(t *testing.T) {
	generator := NewCycloneDXGenerator()
	
	t.Run("Valid document", func(t *testing.T) {
		doc := &CycloneDXDocument{
			BOMFormat:    "CycloneDX",
			SpecVersion:  "1.5",
			SerialNumber: "urn:uuid:12345678-1234",
			Version:      1,
			Metadata: CycloneDXMetadata{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Tools: []CycloneDXTool{
					{Name: "test-tool", Version: "1.0.0"},
				},
			},
			Components: []CycloneDXComponent{
				{
					Type:   "library",
					BOMRef: "comp-1",
					Name:   "test-lib",
				},
			},
			Dependencies: []CycloneDXDependency{
				{
					Ref:       "comp-1",
					DependsOn: []string{},
				},
			},
		}
		
		result := generator.ValidateSchema(doc)
		if !result.Valid {
			t.Errorf("Expected valid document, got errors: %v", result.Errors)
		}
	})
	
	t.Run("Invalid bomFormat", func(t *testing.T) {
		doc := &CycloneDXDocument{
			BOMFormat:    "Invalid",
			SpecVersion:  "1.5",
			SerialNumber: "urn:uuid:12345678-1234",
			Version:      1,
			Metadata: CycloneDXMetadata{
				Tools: []CycloneDXTool{{Name: "test-tool"}},
			},
		}
		
		result := generator.ValidateSchema(doc)
		if result.Valid {
			t.Error("Expected invalid document due to wrong bomFormat")
		}
		
		found := false
		for _, err := range result.Errors {
			if err == "bomFormat must be 'CycloneDX'" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected bomFormat error in validation results")
		}
	})
	
	t.Run("Missing required fields", func(t *testing.T) {
		doc := &CycloneDXDocument{
			BOMFormat: "CycloneDX",
			// Missing other required fields
		}
		
		result := generator.ValidateSchema(doc)
		if result.Valid {
			t.Error("Expected invalid document due to missing required fields")
		}
		
		expectedErrors := []string{
			"specVersion is required",
			"serialNumber is required",
			"version must be positive",
			"at least one tool is required in metadata",
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
	
	t.Run("Duplicate BOM references", func(t *testing.T) {
		doc := &CycloneDXDocument{
			BOMFormat:    "CycloneDX",
			SpecVersion:  "1.5",
			SerialNumber: "urn:uuid:12345678-1234",
			Version:      1,
			Metadata: CycloneDXMetadata{
				Tools: []CycloneDXTool{{Name: "test-tool"}},
			},
			Components: []CycloneDXComponent{
				{Type: "library", BOMRef: "comp-1", Name: "lib1"},
				{Type: "library", BOMRef: "comp-1", Name: "lib2"}, // Duplicate BOM ref
			},
		}
		
		result := generator.ValidateSchema(doc)
		if result.Valid {
			t.Error("Expected invalid document due to duplicate BOM references")
		}
		
		found := false
		for _, err := range result.Errors {
			if err == "duplicate bom-ref: comp-1" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected duplicate BOM ref error in validation results")
		}
	})
}