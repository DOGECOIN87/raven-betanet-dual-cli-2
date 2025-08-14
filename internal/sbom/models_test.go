package sbom

import (
	"testing"
	"time"
)

func TestSBOMFormat_String(t *testing.T) {
	tests := []struct {
		format   SBOMFormat
		expected string
	}{
		{CycloneDX, "CycloneDX"},
		{SPDX, "SPDX"},
		{SBOMFormat(999), "Unknown"},
	}

	for _, test := range tests {
		result := test.format.String()
		if result != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, result)
		}
	}
}

func TestNewComponent(t *testing.T) {
	comp := NewComponent(ComponentTypeLibrary, "test-lib", "1.0.0")

	if comp.Type != ComponentTypeLibrary {
		t.Errorf("Expected type %s, got %s", ComponentTypeLibrary, comp.Type)
	}

	if comp.Name != "test-lib" {
		t.Errorf("Expected name 'test-lib', got '%s'", comp.Name)
	}

	if comp.Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", comp.Version)
	}

	if comp.BOMRef == "" {
		t.Error("Expected BOMRef to be generated")
	}

	if comp.Hashes == nil {
		t.Error("Expected Hashes map to be initialized")
	}
}

func TestComponent_AddHash(t *testing.T) {
	comp := NewComponent(ComponentTypeLibrary, "test-lib", "1.0.0")
	comp.AddHash("sha256", "abcd1234")

	if comp.Hashes["sha256"] != "abcd1234" {
		t.Errorf("Expected hash 'abcd1234', got '%s'", comp.Hashes["sha256"])
	}
}

func TestComponent_AddLicense(t *testing.T) {
	comp := NewComponent(ComponentTypeLibrary, "test-lib", "1.0.0")
	license := License{ID: "MIT", Name: "MIT License"}
	comp.AddLicense(license)

	if len(comp.Licenses) != 1 {
		t.Errorf("Expected 1 license, got %d", len(comp.Licenses))
	}

	if comp.Licenses[0].ID != "MIT" {
		t.Errorf("Expected license ID 'MIT', got '%s'", comp.Licenses[0].ID)
	}
}

func TestComponent_AddProperty(t *testing.T) {
	comp := NewComponent(ComponentTypeLibrary, "test-lib", "1.0.0")
	comp.AddProperty("test-key", "test-value")

	if len(comp.Properties) != 1 {
		t.Errorf("Expected 1 property, got %d", len(comp.Properties))
	}

	if comp.Properties[0].Name != "test-key" {
		t.Errorf("Expected property name 'test-key', got '%s'", comp.Properties[0].Name)
	}

	if comp.Properties[0].Value != "test-value" {
		t.Errorf("Expected property value 'test-value', got '%s'", comp.Properties[0].Value)
	}
}

func TestComponent_AddDependency(t *testing.T) {
	comp := NewComponent(ComponentTypeLibrary, "test-lib", "1.0.0")
	comp.AddDependency("dep-ref-123")

	if len(comp.Dependencies) != 1 {
		t.Errorf("Expected 1 dependency, got %d", len(comp.Dependencies))
	}

	if comp.Dependencies[0] != "dep-ref-123" {
		t.Errorf("Expected dependency 'dep-ref-123', got '%s'", comp.Dependencies[0])
	}
}

func TestNewSBOM(t *testing.T) {
	sbom := NewSBOM(CycloneDX)

	if sbom.Format != CycloneDX {
		t.Errorf("Expected format %s, got %s", CycloneDX, sbom.Format)
	}

	if sbom.Components == nil {
		t.Error("Expected Components slice to be initialized")
	}

	if sbom.Metadata.Tool.Name != "raven-linter" {
		t.Errorf("Expected tool name 'raven-linter', got '%s'", sbom.Metadata.Tool.Name)
	}

	if sbom.Metadata.Tool.Vendor != "Raven Betanet" {
		t.Errorf("Expected tool vendor 'Raven Betanet', got '%s'", sbom.Metadata.Tool.Vendor)
	}

	if sbom.GeneratedAt.IsZero() {
		t.Error("Expected GeneratedAt to be set")
	}
}

func TestSBOM_SetVersion(t *testing.T) {
	tests := []struct {
		format          SBOMFormat
		expectedVersion string
	}{
		{CycloneDX, "1.5"},
		{SPDX, "2.3"},
		{SBOMFormat(999), "1.0"},
	}

	for _, test := range tests {
		sbom := NewSBOM(test.format)
		sbom.SetVersion()

		if sbom.Version != test.expectedVersion {
			t.Errorf("For format %s, expected version '%s', got '%s'", 
				test.format, test.expectedVersion, sbom.Version)
		}
	}
}

func TestSBOM_AddComponent(t *testing.T) {
	sbom := NewSBOM(CycloneDX)
	comp := NewComponent(ComponentTypeLibrary, "test-lib", "1.0.0")
	
	// Clear BOMRef to test generation
	comp.BOMRef = ""
	
	sbom.AddComponent(comp)

	if len(sbom.Components) != 1 {
		t.Errorf("Expected 1 component, got %d", len(sbom.Components))
	}

	if sbom.Components[0].BOMRef == "" {
		t.Error("Expected BOMRef to be generated when adding component")
	}
}

func TestSBOM_SetTarget(t *testing.T) {
	sbom := NewSBOM(CycloneDX)
	hashes := map[string]string{"sha256": "abcd1234"}
	
	sbom.SetTarget("test-binary", "/path/to/test-binary", 1024, hashes, "x86_64", "ELF")

	target := sbom.Metadata.Target
	if target.Name != "test-binary" {
		t.Errorf("Expected target name 'test-binary', got '%s'", target.Name)
	}

	if target.Path != "/path/to/test-binary" {
		t.Errorf("Expected target path '/path/to/test-binary', got '%s'", target.Path)
	}

	if target.Size != 1024 {
		t.Errorf("Expected target size 1024, got %d", target.Size)
	}

	if target.Architecture != "x86_64" {
		t.Errorf("Expected target architecture 'x86_64', got '%s'", target.Architecture)
	}

	if target.Format != "ELF" {
		t.Errorf("Expected target format 'ELF', got '%s'", target.Format)
	}

	if target.Hashes["sha256"] != "abcd1234" {
		t.Errorf("Expected hash 'abcd1234', got '%s'", target.Hashes["sha256"])
	}
}

func TestSBOM_GetComponentCount(t *testing.T) {
	sbom := NewSBOM(CycloneDX)
	
	if sbom.GetComponentCount() != 0 {
		t.Errorf("Expected 0 components, got %d", sbom.GetComponentCount())
	}

	comp1 := NewComponent(ComponentTypeLibrary, "lib1", "1.0.0")
	comp2 := NewComponent(ComponentTypeLibrary, "lib2", "2.0.0")
	
	sbom.AddComponent(comp1)
	sbom.AddComponent(comp2)

	if sbom.GetComponentCount() != 2 {
		t.Errorf("Expected 2 components, got %d", sbom.GetComponentCount())
	}
}

func TestSBOM_FindComponent(t *testing.T) {
	sbom := NewSBOM(CycloneDX)
	comp := NewComponent(ComponentTypeLibrary, "test-lib", "1.0.0")
	sbom.AddComponent(comp)

	found := sbom.FindComponent(comp.BOMRef)
	if found == nil {
		t.Error("Expected to find component")
	}

	if found.Name != "test-lib" {
		t.Errorf("Expected component name 'test-lib', got '%s'", found.Name)
	}

	notFound := sbom.FindComponent("non-existent")
	if notFound != nil {
		t.Error("Expected not to find non-existent component")
	}
}

func TestSBOM_FindComponentsByType(t *testing.T) {
	sbom := NewSBOM(CycloneDX)
	
	lib1 := NewComponent(ComponentTypeLibrary, "lib1", "1.0.0")
	lib2 := NewComponent(ComponentTypeLibrary, "lib2", "2.0.0")
	app := NewComponent(ComponentTypeApplication, "app", "1.0.0")
	
	sbom.AddComponent(lib1)
	sbom.AddComponent(lib2)
	sbom.AddComponent(app)

	libraries := sbom.FindComponentsByType(ComponentTypeLibrary)
	if len(libraries) != 2 {
		t.Errorf("Expected 2 libraries, got %d", len(libraries))
	}

	applications := sbom.FindComponentsByType(ComponentTypeApplication)
	if len(applications) != 1 {
		t.Errorf("Expected 1 application, got %d", len(applications))
	}

	frameworks := sbom.FindComponentsByType(ComponentTypeFramework)
	if len(frameworks) != 0 {
		t.Errorf("Expected 0 frameworks, got %d", len(frameworks))
	}
}

func TestSBOM_Validate(t *testing.T) {
	t.Run("Valid SBOM", func(t *testing.T) {
		sbom := NewSBOM(CycloneDX)
		sbom.SetVersion()
		sbom.SetTarget("test-binary", "/path/to/test-binary", 1024, 
			map[string]string{"sha256": "abcd1234"}, "x86_64", "ELF")
		
		comp := NewComponent(ComponentTypeLibrary, "test-lib", "1.0.0")
		sbom.AddComponent(comp)

		result := sbom.Validate()
		if !result.Valid {
			t.Errorf("Expected valid SBOM, got errors: %v", result.Errors)
		}
	})

	t.Run("Missing version", func(t *testing.T) {
		sbom := NewSBOM(CycloneDX)
		sbom.Version = ""
		sbom.SetTarget("test-binary", "/path/to/test-binary", 1024, 
			map[string]string{"sha256": "abcd1234"}, "x86_64", "ELF")

		result := sbom.Validate()
		if result.Valid {
			t.Error("Expected invalid SBOM due to missing version")
		}

		found := false
		for _, err := range result.Errors {
			if err == "SBOM version is required" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected version error in validation results")
		}
	})

	t.Run("Missing tool name", func(t *testing.T) {
		sbom := NewSBOM(CycloneDX)
		sbom.SetVersion()
		sbom.Metadata.Tool.Name = ""
		sbom.SetTarget("test-binary", "/path/to/test-binary", 1024, 
			map[string]string{"sha256": "abcd1234"}, "x86_64", "ELF")

		result := sbom.Validate()
		if result.Valid {
			t.Error("Expected invalid SBOM due to missing tool name")
		}
	})

	t.Run("Missing target name", func(t *testing.T) {
		sbom := NewSBOM(CycloneDX)
		sbom.SetVersion()

		result := sbom.Validate()
		if result.Valid {
			t.Error("Expected invalid SBOM due to missing target name")
		}
	})

	t.Run("Component missing name", func(t *testing.T) {
		sbom := NewSBOM(CycloneDX)
		sbom.SetVersion()
		sbom.SetTarget("test-binary", "/path/to/test-binary", 1024, 
			map[string]string{"sha256": "abcd1234"}, "x86_64", "ELF")
		
		comp := Component{
			Type:    ComponentTypeLibrary,
			BOMRef:  "test-ref",
			Version: "1.0.0",
		}
		sbom.AddComponent(comp)

		result := sbom.Validate()
		if result.Valid {
			t.Error("Expected invalid SBOM due to component missing name")
		}
	})

	t.Run("Component missing type", func(t *testing.T) {
		sbom := NewSBOM(CycloneDX)
		sbom.SetVersion()
		sbom.SetTarget("test-binary", "/path/to/test-binary", 1024, 
			map[string]string{"sha256": "abcd1234"}, "x86_64", "ELF")
		
		comp := Component{
			Name:    "test-lib",
			BOMRef:  "test-ref",
			Version: "1.0.0",
		}
		sbom.AddComponent(comp)

		result := sbom.Validate()
		if result.Valid {
			t.Error("Expected invalid SBOM due to component missing type")
		}
	})

	t.Run("Duplicate BOM references", func(t *testing.T) {
		sbom := NewSBOM(CycloneDX)
		sbom.SetVersion()
		sbom.SetTarget("test-binary", "/path/to/test-binary", 1024, 
			map[string]string{"sha256": "abcd1234"}, "x86_64", "ELF")
		
		comp1 := NewComponent(ComponentTypeLibrary, "lib1", "1.0.0")
		comp2 := NewComponent(ComponentTypeLibrary, "lib2", "2.0.0")
		comp2.BOMRef = comp1.BOMRef // Duplicate reference
		
		sbom.AddComponent(comp1)
		sbom.AddComponent(comp2)

		result := sbom.Validate()
		if result.Valid {
			t.Error("Expected invalid SBOM due to duplicate BOM references")
		}
	})
}

func TestGenerateBOMRef(t *testing.T) {
	comp1 := Component{
		Type:    ComponentTypeLibrary,
		Name:    "test-lib",
		Version: "1.0.0",
	}

	comp2 := Component{
		Type:    ComponentTypeLibrary,
		Name:    "test-lib",
		Version: "1.0.0",
	}

	comp3 := Component{
		Type:    ComponentTypeLibrary,
		Name:    "test-lib",
		Version: "2.0.0",
	}

	ref1 := generateBOMRef(comp1)
	ref2 := generateBOMRef(comp2)
	ref3 := generateBOMRef(comp3)

	// Same components should generate same reference
	if ref1 != ref2 {
		t.Error("Expected same components to generate same BOM reference")
	}

	// Different components should generate different references
	if ref1 == ref3 {
		t.Error("Expected different components to generate different BOM references")
	}

	// Reference should start with "comp-"
	if len(ref1) < 5 || ref1[:5] != "comp-" {
		t.Errorf("Expected BOM reference to start with 'comp-', got '%s'", ref1)
	}
}

func TestComponentTypes(t *testing.T) {
	types := []ComponentType{
		ComponentTypeApplication,
		ComponentTypeFramework,
		ComponentTypeLibrary,
		ComponentTypeContainer,
		ComponentTypeOperatingSystem,
		ComponentTypeDevice,
		ComponentTypeFirmware,
		ComponentTypeFile,
	}

	expectedStrings := []string{
		"application",
		"framework",
		"library",
		"container",
		"operating-system",
		"device",
		"firmware",
		"file",
	}

	for i, componentType := range types {
		if string(componentType) != expectedStrings[i] {
			t.Errorf("Expected component type '%s', got '%s'", expectedStrings[i], string(componentType))
		}
	}
}

func TestComponentScopes(t *testing.T) {
	scopes := []ComponentScope{
		ScopeRequired,
		ScopeOptional,
		ScopeExcluded,
	}

	expectedStrings := []string{
		"required",
		"optional",
		"excluded",
	}

	for i, scope := range scopes {
		if string(scope) != expectedStrings[i] {
			t.Errorf("Expected scope '%s', got '%s'", expectedStrings[i], string(scope))
		}
	}
}

func TestValidationResult(t *testing.T) {
	// Valid result
	validResult := ValidationResult{
		Valid:  true,
		Errors: nil,
	}

	if !validResult.Valid {
		t.Error("Expected valid result to be valid")
	}

	if len(validResult.Errors) != 0 {
		t.Error("Expected valid result to have no errors")
	}

	// Invalid result
	invalidResult := ValidationResult{
		Valid:  false,
		Errors: []string{"error 1", "error 2"},
	}

	if invalidResult.Valid {
		t.Error("Expected invalid result to be invalid")
	}

	if len(invalidResult.Errors) != 2 {
		t.Errorf("Expected 2 errors, got %d", len(invalidResult.Errors))
	}
}

func TestSBOMMetadata(t *testing.T) {
	now := time.Now()
	metadata := SBOMMetadata{
		Tool: ToolInfo{
			Vendor:  "Test Vendor",
			Name:    "Test Tool",
			Version: "1.0.0",
		},
		Target: Target{
			Name:         "test-binary",
			Path:         "/path/to/binary",
			Size:         1024,
			Hashes:       map[string]string{"sha256": "abcd1234"},
			Architecture: "x86_64",
			Format:       "ELF",
		},
		Timestamp:    now.Format(time.RFC3339),
		SerialNumber: "test-serial-123",
		Version:      1,
	}

	if metadata.Tool.Vendor != "Test Vendor" {
		t.Errorf("Expected tool vendor 'Test Vendor', got '%s'", metadata.Tool.Vendor)
	}

	if metadata.Target.Name != "test-binary" {
		t.Errorf("Expected target name 'test-binary', got '%s'", metadata.Target.Name)
	}

	if metadata.SerialNumber != "test-serial-123" {
		t.Errorf("Expected serial number 'test-serial-123', got '%s'", metadata.SerialNumber)
	}
}