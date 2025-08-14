package sbom

import (
	"crypto/sha256"
	"fmt"
	"time"
)

// SBOMFormat represents the format of the SBOM output
type SBOMFormat int

const (
	// CycloneDX format
	CycloneDX SBOMFormat = iota
	// SPDX format
	SPDX
)

// String returns the string representation of the SBOM format
func (f SBOMFormat) String() string {
	switch f {
	case CycloneDX:
		return "CycloneDX"
	case SPDX:
		return "SPDX"
	default:
		return "Unknown"
	}
}

// SBOM represents a Software Bill of Materials
type SBOM struct {
	Format      SBOMFormat    `json:"format"`
	Version     string        `json:"version"`
	Components  []Component   `json:"components"`
	Metadata    SBOMMetadata  `json:"metadata"`
	GeneratedAt time.Time     `json:"generated_at"`
}

// SBOMMetadata contains metadata about the SBOM itself
type SBOMMetadata struct {
	Tool        ToolInfo `json:"tool"`
	Target      Target   `json:"target"`
	Timestamp   string   `json:"timestamp"`
	SerialNumber string  `json:"serial_number,omitempty"`
	Version     int      `json:"version,omitempty"`
}

// ToolInfo contains information about the tool that generated the SBOM
type ToolInfo struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Target contains information about the analyzed binary
type Target struct {
	Name         string            `json:"name"`
	Path         string            `json:"path"`
	Size         int64             `json:"size"`
	Hashes       map[string]string `json:"hashes"`
	Architecture string            `json:"architecture"`
	Format       string            `json:"format"`
}

// Component represents a component in the SBOM
type Component struct {
	Type         ComponentType     `json:"type"`
	BOMRef       string            `json:"bom_ref"`
	Name         string            `json:"name"`
	Version      string            `json:"version,omitempty"`
	Description  string            `json:"description,omitempty"`
	Hashes       map[string]string `json:"hashes,omitempty"`
	Licenses     []License         `json:"licenses,omitempty"`
	Copyright    string            `json:"copyright,omitempty"`
	Publisher    string            `json:"publisher,omitempty"`
	Group        string            `json:"group,omitempty"`
	Scope        ComponentScope    `json:"scope,omitempty"`
	Dependencies []string          `json:"dependencies,omitempty"`
	Properties   []Property        `json:"properties,omitempty"`
	Evidence     *Evidence         `json:"evidence,omitempty"`
}

// ComponentType represents the type of component
type ComponentType string

const (
	ComponentTypeApplication ComponentType = "application"
	ComponentTypeFramework   ComponentType = "framework"
	ComponentTypeLibrary     ComponentType = "library"
	ComponentTypeContainer   ComponentType = "container"
	ComponentTypeOperatingSystem ComponentType = "operating-system"
	ComponentTypeDevice      ComponentType = "device"
	ComponentTypeFirmware    ComponentType = "firmware"
	ComponentTypeFile        ComponentType = "file"
)

// ComponentScope represents the scope of the component
type ComponentScope string

const (
	ScopeRequired ComponentScope = "required"
	ScopeOptional ComponentScope = "optional"
	ScopeExcluded ComponentScope = "excluded"
)

// License represents license information
type License struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Text string `json:"text,omitempty"`
	URL  string `json:"url,omitempty"`
}

// Property represents a name-value property
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Evidence represents evidence of how the component was identified
type Evidence struct {
	Identity    *EvidenceIdentity    `json:"identity,omitempty"`
	Occurrences []EvidenceOccurrence `json:"occurrences,omitempty"`
}

// EvidenceIdentity represents identity evidence
type EvidenceIdentity struct {
	Field      string `json:"field"`
	Confidence float64 `json:"confidence"`
	Methods    []EvidenceMethod `json:"methods,omitempty"`
}

// EvidenceOccurrence represents occurrence evidence
type EvidenceOccurrence struct {
	Location string `json:"location"`
	Line     int    `json:"line,omitempty"`
	Offset   int64  `json:"offset,omitempty"`
}

// EvidenceMethod represents the method used to identify the component
type EvidenceMethod struct {
	Technique  string `json:"technique"`
	Confidence float64 `json:"confidence"`
	Value      string `json:"value,omitempty"`
}

// ComponentExtractor defines the interface for extracting components from binaries
type ComponentExtractor interface {
	// ExtractComponents extracts components from a binary file
	ExtractComponents(binaryPath string) ([]Component, error)
	
	// GetSupportedFormats returns the binary formats this extractor supports
	GetSupportedFormats() []string
}

// SBOMGenerator defines the interface for generating SBOMs
type SBOMGenerator interface {
	// Generate creates an SBOM from a binary file
	Generate(binaryPath string, format SBOMFormat) (*SBOM, error)
	
	// WriteToFile writes an SBOM to a file
	WriteToFile(sbom *SBOM, outputPath string) error
	
	// GetSupportedFormats returns the SBOM formats this generator supports
	GetSupportedFormats() []SBOMFormat
}

// ValidationResult represents the result of SBOM validation
type ValidationResult struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
}

// SBOMValidator defines the interface for validating SBOMs
type SBOMValidator interface {
	// Validate validates an SBOM against its schema
	Validate(sbom *SBOM) ValidationResult
	
	// ValidateFile validates an SBOM file
	ValidateFile(filePath string) ValidationResult
}

// generateBOMRef generates a unique BOM reference for a component
func generateBOMRef(component Component) string {
	// Create a unique reference based on component properties
	data := fmt.Sprintf("%s:%s:%s", component.Type, component.Name, component.Version)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("comp-%x", hash[:8])
}

// NewComponent creates a new component with a generated BOM reference
func NewComponent(componentType ComponentType, name, version string) Component {
	comp := Component{
		Type:    componentType,
		Name:    name,
		Version: version,
		Hashes:  make(map[string]string),
	}
	comp.BOMRef = generateBOMRef(comp)
	return comp
}

// AddHash adds a hash to the component
func (c *Component) AddHash(algorithm, value string) {
	if c.Hashes == nil {
		c.Hashes = make(map[string]string)
	}
	c.Hashes[algorithm] = value
}

// AddLicense adds a license to the component
func (c *Component) AddLicense(license License) {
	c.Licenses = append(c.Licenses, license)
}

// AddProperty adds a property to the component
func (c *Component) AddProperty(name, value string) {
	c.Properties = append(c.Properties, Property{
		Name:  name,
		Value: value,
	})
}

// AddDependency adds a dependency reference to the component
func (c *Component) AddDependency(bomRef string) {
	c.Dependencies = append(c.Dependencies, bomRef)
}

// NewSBOM creates a new SBOM with the specified format
func NewSBOM(format SBOMFormat) *SBOM {
	return &SBOM{
		Format:      format,
		Components:  make([]Component, 0),
		GeneratedAt: time.Now(),
		Metadata: SBOMMetadata{
			Tool: ToolInfo{
				Vendor:  "Raven Betanet",
				Name:    "raven-linter",
				Version: "1.0.0", // This should be injected at build time
			},
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}
}

// AddComponent adds a component to the SBOM
func (s *SBOM) AddComponent(component Component) {
	// Ensure BOM reference is set
	if component.BOMRef == "" {
		component.BOMRef = generateBOMRef(component)
	}
	s.Components = append(s.Components, component)
}

// SetTarget sets the target information for the SBOM
func (s *SBOM) SetTarget(name, path string, size int64, hashes map[string]string, architecture, format string) {
	s.Metadata.Target = Target{
		Name:         name,
		Path:         path,
		Size:         size,
		Hashes:       hashes,
		Architecture: architecture,
		Format:       format,
	}
}

// SetVersion sets the SBOM version based on format
func (s *SBOM) SetVersion() {
	switch s.Format {
	case CycloneDX:
		s.Version = "1.5"
	case SPDX:
		s.Version = "2.3"
	default:
		s.Version = "1.0"
	}
}

// GetComponentCount returns the number of components in the SBOM
func (s *SBOM) GetComponentCount() int {
	return len(s.Components)
}

// FindComponent finds a component by BOM reference
func (s *SBOM) FindComponent(bomRef string) *Component {
	for i := range s.Components {
		if s.Components[i].BOMRef == bomRef {
			return &s.Components[i]
		}
	}
	return nil
}

// FindComponentsByType finds all components of a specific type
func (s *SBOM) FindComponentsByType(componentType ComponentType) []Component {
	var components []Component
	for _, comp := range s.Components {
		if comp.Type == componentType {
			components = append(components, comp)
		}
	}
	return components
}

// Validate performs basic validation on the SBOM
func (s *SBOM) Validate() ValidationResult {
	var errors []string
	
	// Check required fields
	if s.Version == "" {
		errors = append(errors, "SBOM version is required")
	}
	
	if s.Metadata.Tool.Name == "" {
		errors = append(errors, "Tool name is required in metadata")
	}
	
	if s.Metadata.Target.Name == "" {
		errors = append(errors, "Target name is required in metadata")
	}
	
	// Validate components
	bomRefs := make(map[string]bool)
	for i, comp := range s.Components {
		// Check for duplicate BOM references
		if bomRefs[comp.BOMRef] {
			errors = append(errors, fmt.Sprintf("Duplicate BOM reference: %s", comp.BOMRef))
		}
		bomRefs[comp.BOMRef] = true
		
		// Check required component fields
		if comp.Name == "" {
			errors = append(errors, fmt.Sprintf("Component %d: name is required", i))
		}
		
		if comp.Type == "" {
			errors = append(errors, fmt.Sprintf("Component %d: type is required", i))
		}
		
		// Validate dependency references
		for _, depRef := range comp.Dependencies {
			if !bomRefs[depRef] && depRef != comp.BOMRef {
				// Note: This is a forward reference check, might be valid in some cases
				// We'll just warn about it rather than error
			}
		}
	}
	
	return ValidationResult{
		Valid:  len(errors) == 0,
		Errors: errors,
	}
}