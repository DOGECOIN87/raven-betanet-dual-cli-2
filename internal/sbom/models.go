package sbom

import (
	"time"
)

// SBOMGenerator defines the interface for generating SBOMs in different formats
type SBOMGenerator interface {
	// Generate creates an SBOM from the provided components and metadata
	Generate(components []Component, metadata GenerationMetadata) ([]byte, error)
	
	// Validate checks if the provided SBOM data is valid according to the format schema
	Validate(sbomData []byte) error
	
	// Format returns the format identifier (e.g., "cyclonedx", "spdx")
	Format() string
}

// ComponentType represents the type of a software component
type ComponentType string

const (
	ComponentTypeApplication      ComponentType = "application"
	ComponentTypeLibrary          ComponentType = "library"
	ComponentTypeFramework        ComponentType = "framework"
	ComponentTypeContainer        ComponentType = "container"
	ComponentTypeOS               ComponentType = "operating-system"
	ComponentTypeOperatingSystem  ComponentType = "operating-system"  // Alias for compatibility
	ComponentTypeDevice           ComponentType = "device"
	ComponentTypeFirmware         ComponentType = "firmware"
	ComponentTypeFile             ComponentType = "file"
)

// Component represents a software component in an SBOM
type Component struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Type         ComponentType     `json:"type"`
	BOMRef       string            `json:"bom_ref,omitempty"`      // For compatibility with existing code
	Supplier     string            `json:"supplier,omitempty"`
	Author       string            `json:"author,omitempty"`
	Publisher    string            `json:"publisher,omitempty"`
	Group        string            `json:"group,omitempty"`
	Description  string            `json:"description,omitempty"`
	Copyright    string            `json:"copyright,omitempty"`    // For compatibility with existing code
	Scope        string            `json:"scope,omitempty"`
	Licenses     []License         `json:"licenses,omitempty"`
	Hashes       map[string]string `json:"hashes,omitempty"`
	Dependencies []string          `json:"dependencies,omitempty"`
	PURL         string            `json:"purl,omitempty"`
	CPE          string            `json:"cpe,omitempty"`
	ExternalRefs []ExternalRef     `json:"external_refs,omitempty"`
	Properties   []Property        `json:"properties,omitempty"`   // Changed to []Property for compatibility
	Evidence     *Evidence         `json:"evidence,omitempty"`     // For compatibility with existing code
}

// License represents license information for a component
type License struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Text string `json:"text,omitempty"`
	URL  string `json:"url,omitempty"`
}

// ExternalRef represents an external reference for a component
type ExternalRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
	Comment string `json:"comment,omitempty"`
}

// GenerationMetadata contains metadata about the SBOM generation process
type GenerationMetadata struct {
	Timestamp    time.Time         `json:"timestamp"`
	ToolName     string            `json:"tool_name"`
	ToolVersion  string            `json:"tool_version"`
	ToolVendor   string            `json:"tool_vendor"`
	Subject      string            `json:"subject"`      // The binary being analyzed
	Authors      []string          `json:"authors"`
	Supplier     string            `json:"supplier,omitempty"`
	Manufacturer string            `json:"manufacturer,omitempty"`
	Properties   map[string]string `json:"properties,omitempty"`
	SerialNumber string            `json:"serial_number,omitempty"` // For compatibility with existing code
	Tool         ToolInfo          `json:"tool"`                    // For compatibility with existing code
	Target       Target            `json:"target"`                  // For compatibility with existing code
}

// ToolInfo contains information about the tool that generated the SBOM
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Vendor  string `json:"vendor,omitempty"`
}

// SBOMInfo contains information about a generated SBOM
type SBOMInfo struct {
	Format      string    `json:"format"`
	Version     string    `json:"version"`
	FilePath    string    `json:"file_path"`
	Size        int64     `json:"size"`
	Components  int       `json:"components"`
	Generated   time.Time `json:"generated"`
	Valid       bool      `json:"valid"`
	Checksum    string    `json:"checksum"`
}

// ComponentExtractor defines the interface for extracting components from binaries
type ComponentExtractor interface {
	// ExtractComponents analyzes a binary and extracts software components
	ExtractComponents(binaryPath string) ([]Component, error)
	
	// GetSupportedFormats returns the binary formats this extractor supports
	GetSupportedFormats() []string
}

// HashAlgorithm represents supported hash algorithms for components
type HashAlgorithm string

const (
	HashSHA1   HashAlgorithm = "sha1"
	HashSHA256 HashAlgorithm = "sha256"
	HashSHA512 HashAlgorithm = "sha512"
	HashMD5    HashAlgorithm = "md5"
)

// ValidationResult contains the result of SBOM validation
type ValidationResult struct {
	Valid   bool     `json:"valid"`
	Errors  []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// SBOMFormat represents the format of an SBOM
type SBOMFormat string

const (
	FormatCycloneDX SBOMFormat = "cyclonedx"
	FormatSPDX      SBOMFormat = "spdx"
)

// SBOM represents a Software Bill of Materials
type SBOM struct {
	Format      SBOMFormat            `json:"format"`
	Version     string                `json:"version"`
	SerialNumber string               `json:"serial_number"`
	Metadata    GenerationMetadata    `json:"metadata"`
	Components  []Component           `json:"components"`
	Services    []Service             `json:"services,omitempty"`
	Dependencies []Dependency         `json:"dependencies,omitempty"`
	Properties  map[string]string     `json:"properties,omitempty"`
	GeneratedAt time.Time             `json:"generated_at"`  // For compatibility with existing code
}

// Service represents a service component in an SBOM
type Service struct {
	Name         string            `json:"name"`
	Version      string            `json:"version,omitempty"`
	Description  string            `json:"description,omitempty"`
	Endpoints    []string          `json:"endpoints,omitempty"`
	Authenticated bool             `json:"authenticated,omitempty"`
	Data         []DataFlow        `json:"data,omitempty"`
	Licenses     []License         `json:"licenses,omitempty"`
	ExternalRefs []ExternalRef     `json:"external_refs,omitempty"`
	Properties   map[string]string `json:"properties,omitempty"`
}

// DataFlow represents data flow information for services
type DataFlow struct {
	Flow         string `json:"flow"`          // inbound, outbound, bi-directional, unknown
	Classification string `json:"classification"` // public, restricted, confidential, secret
}

// Dependency represents a dependency relationship between components
type Dependency struct {
	Ref          string   `json:"ref"`
	DependsOn    []string `json:"depends_on,omitempty"`
	Scope        string   `json:"scope,omitempty"`
	Relationship string   `json:"relationship,omitempty"`
}

// Property represents a name-value property pair
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Evidence represents evidence supporting the identification of a component
type Evidence struct {
	Identity    *EvidenceIdentity `json:"identity,omitempty"`
	Occurrences []Occurrence      `json:"occurrences,omitempty"`
	Callstack   *Callstack        `json:"callstack,omitempty"`
}

// EvidenceIdentity represents identity evidence for a component
type EvidenceIdentity struct {
	Field      string `json:"field"`
	Confidence float64 `json:"confidence"`
	Methods    []EvidenceMethod `json:"methods,omitempty"`
}

// EvidenceMethod represents a method used to identify a component
type EvidenceMethod struct {
	Technique   string  `json:"technique"`
	Confidence  float64 `json:"confidence"`
	Value       string  `json:"value,omitempty"`
}

// Occurrence represents an occurrence of a component
type Occurrence struct {
	BomRef   string `json:"bom-ref,omitempty"`
	Location string `json:"location"`
	Line     int    `json:"line,omitempty"`
	Offset   int64  `json:"offset,omitempty"`  // Changed to int64 for compatibility
	Symbol   string `json:"symbol,omitempty"`
}

// Callstack represents a callstack for evidence
type Callstack struct {
	Frames []CallstackFrame `json:"frames,omitempty"`
}

// CallstackFrame represents a frame in a callstack
type CallstackFrame struct {
	Package    string            `json:"package,omitempty"`
	Module     string            `json:"module,omitempty"`
	Function   string            `json:"function,omitempty"`
	Parameters []string          `json:"parameters,omitempty"`
	Line       int               `json:"line,omitempty"`
	Column     int               `json:"column,omitempty"`
	FullFilename string          `json:"fullFilename,omitempty"`
}

// Target represents the target binary being analyzed
type Target struct {
	Name         string            `json:"name"`
	Version      string            `json:"version,omitempty"`
	Path         string            `json:"path"`
	Size         int64             `json:"size"`
	Checksum     string            `json:"checksum,omitempty"`
	Format       string            `json:"format,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Hashes       map[string]string `json:"hashes,omitempty"`       // For compatibility with existing code
	Architecture string            `json:"architecture,omitempty"` // For compatibility with existing code
}

// Component scope constants
const (
	ScopeRequired = "required"
	ScopeOptional = "optional"
	ScopeExcluded = "excluded"
)

// NewComponent creates a new component with the specified type, name, and version
func NewComponent(componentType ComponentType, name, version string) Component {
	return Component{
		Name:    name,
		Version: version,
		Type:    componentType,
		Properties: []Property{},
	}
}

// AddProperty adds a property to the component
func (c *Component) AddProperty(name, value string) {
	if c.Properties == nil {
		c.Properties = []Property{}
	}
	c.Properties = append(c.Properties, Property{
		Name:  name,
		Value: value,
	})
}

// AddDependency adds a dependency to the component
func (c *Component) AddDependency(dependency string) {
	if c.Dependencies == nil {
		c.Dependencies = []string{}
	}
	c.Dependencies = append(c.Dependencies, dependency)
}

// Format constants for compatibility with existing code
const (
	CycloneDX = FormatCycloneDX
	SPDX      = FormatSPDX
)

// NewSBOM creates a new SBOM with the specified format (single parameter version for compatibility)
func NewSBOM(format SBOMFormat) *SBOM {
	return &SBOM{
		Format:     format,
		Version:    "1.0",
		Components: []Component{},
		Properties: make(map[string]string),
	}
}

// SetVersion sets the SBOM version
func (s *SBOM) SetVersion() {
	s.Version = "1.0"
}

// AddComponent adds a component to the SBOM
func (s *SBOM) AddComponent(component Component) {
	s.Components = append(s.Components, component)
}

// SetTarget sets target information for the SBOM
func (s *SBOM) SetTarget(name, path string, size int64, hashes map[string]string, architecture, format string) {
	// Create target information
	target := Target{
		Name:     name,
		Path:     path,
		Size:     size,
		Format:   format,
		Metadata: map[string]string{"architecture": architecture},
	}
	
	// Store target information in metadata
	if s.Metadata.Properties == nil {
		s.Metadata.Properties = make(map[string]string)
	}
	s.Metadata.Properties["target.name"] = target.Name
	s.Metadata.Properties["target.path"] = target.Path
	s.Metadata.Properties["target.format"] = target.Format
	s.Metadata.Subject = target.Name
	s.Metadata.Target = target
}

// Validate validates the SBOM structure
func (s *SBOM) Validate() ValidationResult {
	result := ValidationResult{Valid: true}
	
	if s.Format == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "SBOM format is required")
	}
	if s.Version == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "SBOM version is required")
	}
	
	return result
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

// EvidenceOccurrence is an alias for Occurrence for compatibility
type EvidenceOccurrence = Occurrence