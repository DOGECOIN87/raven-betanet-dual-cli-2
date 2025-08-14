package sbom

import (
	"encoding/json"
	"fmt"
	"time"
)

// CycloneDXGenerator implements CycloneDX v1.5 JSON schema compliance
type CycloneDXGenerator struct {
	extractor ComponentExtractor
}

// NewCycloneDXGenerator creates a new CycloneDX generator
func NewCycloneDXGenerator() *CycloneDXGenerator {
	return &CycloneDXGenerator{
		extractor: NewBinaryComponentExtractor(),
	}
}

// NewCycloneDXGeneratorWithExtractor creates a new CycloneDX generator with custom extractor
func NewCycloneDXGeneratorWithExtractor(extractor ComponentExtractor) *CycloneDXGenerator {
	return &CycloneDXGenerator{
		extractor: extractor,
	}
}

// CycloneDXDocument represents the complete CycloneDX document structure
type CycloneDXDocument struct {
	BOMFormat     string                 `json:"bomFormat"`
	SpecVersion   string                 `json:"specVersion"`
	SerialNumber  string                 `json:"serialNumber"`
	Version       int                    `json:"version"`
	Metadata      CycloneDXMetadata      `json:"metadata"`
	Components    []CycloneDXComponent   `json:"components,omitempty"`
	Dependencies  []CycloneDXDependency  `json:"dependencies,omitempty"`
	Compositions  []CycloneDXComposition `json:"compositions,omitempty"`
}

// CycloneDXMetadata represents the metadata section of CycloneDX
type CycloneDXMetadata struct {
	Timestamp string                `json:"timestamp"`
	Tools     []CycloneDXTool       `json:"tools"`
	Authors   []CycloneDXAuthor     `json:"authors,omitempty"`
	Component *CycloneDXComponent   `json:"component,omitempty"`
	Supplier  *CycloneDXOrganization `json:"supplier,omitempty"`
	Licenses  []CycloneDXLicense    `json:"licenses,omitempty"`
	Properties []CycloneDXProperty  `json:"properties,omitempty"`
}

// CycloneDXTool represents a tool in CycloneDX format
type CycloneDXTool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// CycloneDXAuthor represents an author in CycloneDX format
type CycloneDXAuthor struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
}

// CycloneDXOrganization represents an organization in CycloneDX format
type CycloneDXOrganization struct {
	Name    string              `json:"name"`
	URL     []string            `json:"url,omitempty"`
	Contact []CycloneDXContact  `json:"contact,omitempty"`
}

// CycloneDXContact represents contact information in CycloneDX format
type CycloneDXContact struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
}

// CycloneDXComponent represents a component in CycloneDX format
type CycloneDXComponent struct {
	Type         string                  `json:"type"`
	BOMRef       string                  `json:"bom-ref"`
	Supplier     *CycloneDXOrganization  `json:"supplier,omitempty"`
	Author       string                  `json:"author,omitempty"`
	Publisher    string                  `json:"publisher,omitempty"`
	Group        string                  `json:"group,omitempty"`
	Name         string                  `json:"name"`
	Version      string                  `json:"version,omitempty"`
	Description  string                  `json:"description,omitempty"`
	Scope        string                  `json:"scope,omitempty"`
	Hashes       []CycloneDXHash         `json:"hashes,omitempty"`
	Licenses     []CycloneDXLicense      `json:"licenses,omitempty"`
	Copyright    string                  `json:"copyright,omitempty"`
	CPE          string                  `json:"cpe,omitempty"`
	PURL         string                  `json:"purl,omitempty"`
	SWID         *CycloneDXSWID          `json:"swid,omitempty"`
	PedigreeInfo *CycloneDXPedigree      `json:"pedigree,omitempty"`
	ExternalRefs []CycloneDXExternalRef  `json:"externalReferences,omitempty"`
	Properties   []CycloneDXProperty     `json:"properties,omitempty"`
	Evidence     *CycloneDXEvidence      `json:"evidence,omitempty"`
	Components   []CycloneDXComponent    `json:"components,omitempty"`
}

// CycloneDXHash represents a hash in CycloneDX format
type CycloneDXHash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

// CycloneDXLicense represents a license in CycloneDX format
type CycloneDXLicense struct {
	License *CycloneDXLicenseChoice `json:"license,omitempty"`
	Expression string                `json:"expression,omitempty"`
}

// CycloneDXLicenseChoice represents a license choice in CycloneDX format
type CycloneDXLicenseChoice struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Text string `json:"text,omitempty"`
	URL  string `json:"url,omitempty"`
}

// CycloneDXSWID represents SWID tag information
type CycloneDXSWID struct {
	TagID   string `json:"tagId"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	TagVersion int `json:"tagVersion,omitempty"`
	Patch   bool   `json:"patch,omitempty"`
}

// CycloneDXPedigree represents pedigree information
type CycloneDXPedigree struct {
	Ancestors   []CycloneDXComponent `json:"ancestors,omitempty"`
	Descendants []CycloneDXComponent `json:"descendants,omitempty"`
	Variants    []CycloneDXComponent `json:"variants,omitempty"`
	Commits     []CycloneDXCommit    `json:"commits,omitempty"`
	Patches     []CycloneDXPatch     `json:"patches,omitempty"`
	Notes       string               `json:"notes,omitempty"`
}

// CycloneDXCommit represents commit information
type CycloneDXCommit struct {
	UID       string                `json:"uid,omitempty"`
	URL       string                `json:"url,omitempty"`
	Author    *CycloneDXIdentity    `json:"author,omitempty"`
	Committer *CycloneDXIdentity    `json:"committer,omitempty"`
	Message   string                `json:"message,omitempty"`
}

// CycloneDXIdentity represents identity information
type CycloneDXIdentity struct {
	Timestamp string `json:"timestamp,omitempty"`
	Name      string `json:"name,omitempty"`
	Email     string `json:"email,omitempty"`
}

// CycloneDXPatch represents patch information
type CycloneDXPatch struct {
	Type     string                 `json:"type"`
	Diff     *CycloneDXDiff         `json:"diff,omitempty"`
	Resolves []CycloneDXIssue       `json:"resolves,omitempty"`
}

// CycloneDXDiff represents diff information
type CycloneDXDiff struct {
	Text string `json:"text,omitempty"`
	URL  string `json:"url,omitempty"`
}

// CycloneDXIssue represents issue information
type CycloneDXIssue struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Source      *CycloneDXSource `json:"source,omitempty"`
	References  []string `json:"references,omitempty"`
}

// CycloneDXSource represents source information
type CycloneDXSource struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

// CycloneDXExternalRef represents external reference
type CycloneDXExternalRef struct {
	Type    string              `json:"type"`
	URL     string              `json:"url"`
	Comment string              `json:"comment,omitempty"`
	Hashes  []CycloneDXHash     `json:"hashes,omitempty"`
}

// CycloneDXProperty represents a property in CycloneDX format
type CycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CycloneDXEvidence represents evidence in CycloneDX format
type CycloneDXEvidence struct {
	Identity    *CycloneDXEvidenceIdentity    `json:"identity,omitempty"`
	Occurrences []CycloneDXEvidenceOccurrence `json:"occurrences,omitempty"`
	Callstack   *CycloneDXCallstack           `json:"callstack,omitempty"`
}

// CycloneDXEvidenceIdentity represents identity evidence
type CycloneDXEvidenceIdentity struct {
	Field      string                     `json:"field"`
	Confidence float64                    `json:"confidence"`
	Methods    []CycloneDXEvidenceMethod  `json:"methods,omitempty"`
	Tools      []string                   `json:"tools,omitempty"`
}

// CycloneDXEvidenceMethod represents evidence method
type CycloneDXEvidenceMethod struct {
	Technique  string  `json:"technique"`
	Confidence float64 `json:"confidence"`
	Value      string  `json:"value,omitempty"`
}

// CycloneDXEvidenceOccurrence represents evidence occurrence
type CycloneDXEvidenceOccurrence struct {
	BOMRef   string `json:"bom-ref,omitempty"`
	Location string `json:"location"`
	Line     int    `json:"line,omitempty"`
	Offset   int64  `json:"offset,omitempty"`
	Symbol   string `json:"symbol,omitempty"`
	AdditionalContext string `json:"additionalContext,omitempty"`
}

// CycloneDXCallstack represents callstack information
type CycloneDXCallstack struct {
	Frames []CycloneDXFrame `json:"frames,omitempty"`
}

// CycloneDXFrame represents a callstack frame
type CycloneDXFrame struct {
	Package    string            `json:"package,omitempty"`
	Module     string            `json:"module,omitempty"`
	Function   string            `json:"function,omitempty"`
	Parameters []string          `json:"parameters,omitempty"`
	Line       int               `json:"line,omitempty"`
	Column     int               `json:"column,omitempty"`
	FullFilename string          `json:"fullFilename,omitempty"`
}

// CycloneDXDependency represents a dependency relationship
type CycloneDXDependency struct {
	Ref          string   `json:"ref"`
	DependsOn    []string `json:"dependsOn,omitempty"`
}

// CycloneDXComposition represents composition information
type CycloneDXComposition struct {
	Aggregate    string   `json:"aggregate"`
	Assemblies   []string `json:"assemblies,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
}

// Generate creates a CycloneDX SBOM from a binary file
func (g *CycloneDXGenerator) Generate(binaryPath string) (*CycloneDXDocument, error) {
	// Extract components using the extractor
	components, err := g.extractor.ExtractComponents(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to extract components: %w", err)
	}
	
	// Create CycloneDX document
	doc := &CycloneDXDocument{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: CycloneDXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []CycloneDXTool{
				{
					Vendor:  "Raven Betanet",
					Name:    "raven-linter",
					Version: "1.0.0", // This should be injected at build time
				},
			},
		},
	}
	
	// Generate serial number
	doc.SerialNumber = g.generateSerialNumber(binaryPath)
	
	// Convert components
	doc.Components = g.convertComponents(components)
	
	// Set main component in metadata (first application component)
	for _, comp := range components {
		if comp.Type == ComponentTypeApplication {
			mainComp := g.convertComponent(comp)
			doc.Metadata.Component = &mainComp
			break
		}
	}
	
	// Generate dependencies
	doc.Dependencies = g.generateDependencies(components)
	
	// Generate compositions
	doc.Compositions = g.generateCompositions(components)
	
	return doc, nil
}

// GenerateJSON creates a CycloneDX SBOM in JSON format
func (g *CycloneDXGenerator) GenerateJSON(binaryPath string) ([]byte, error) {
	doc, err := g.Generate(binaryPath)
	if err != nil {
		return nil, err
	}
	
	return json.MarshalIndent(doc, "", "  ")
}

// convertComponents converts internal components to CycloneDX format
func (g *CycloneDXGenerator) convertComponents(components []Component) []CycloneDXComponent {
	var cyclonComponents []CycloneDXComponent
	
	for _, comp := range components {
		// Skip application components as they go in metadata
		if comp.Type == ComponentTypeApplication {
			continue
		}
		
		cyclonComp := g.convertComponent(comp)
		cyclonComponents = append(cyclonComponents, cyclonComp)
	}
	
	return cyclonComponents
}

// convertComponent converts a single component to CycloneDX format
func (g *CycloneDXGenerator) convertComponent(comp Component) CycloneDXComponent {
	cyclonComp := CycloneDXComponent{
		Type:        string(comp.Type),
		BOMRef:      comp.BOMRef,
		Name:        comp.Name,
		Description: comp.Description,
		Publisher:   comp.Publisher,
		Group:       comp.Group,
		Copyright:   comp.Copyright,
	}
	
	// Set version if not unknown
	if comp.Version != "" && comp.Version != "unknown" {
		cyclonComp.Version = comp.Version
	}
	
	// Set scope
	if comp.Scope != "" {
		cyclonComp.Scope = string(comp.Scope)
	}
	
	// Convert hashes
	if len(comp.Hashes) > 0 {
		cyclonComp.Hashes = g.convertHashes(comp.Hashes)
	}
	
	// Convert licenses
	if len(comp.Licenses) > 0 {
		cyclonComp.Licenses = g.convertLicenses(comp.Licenses)
	}
	
	// Convert properties
	if len(comp.Properties) > 0 {
		cyclonComp.Properties = g.convertProperties(comp.Properties)
	}
	
	// Convert evidence
	if comp.Evidence != nil {
		cyclonComp.Evidence = g.convertEvidence(comp.Evidence)
	}
	
	return cyclonComp
}

// convertHashes converts hashes to CycloneDX format
func (g *CycloneDXGenerator) convertHashes(hashes map[string]string) []CycloneDXHash {
	var cyclonHashes []CycloneDXHash
	
	for alg, content := range hashes {
		cyclonHashes = append(cyclonHashes, CycloneDXHash{
			Algorithm: alg,
			Content:   content,
		})
	}
	
	return cyclonHashes
}

// convertLicenses converts licenses to CycloneDX format
func (g *CycloneDXGenerator) convertLicenses(licenses []License) []CycloneDXLicense {
	var cyclonLicenses []CycloneDXLicense
	
	for _, license := range licenses {
		cyclonLicense := CycloneDXLicense{}
		
		if license.ID != "" || license.Name != "" || license.Text != "" || license.URL != "" {
			cyclonLicense.License = &CycloneDXLicenseChoice{
				ID:   license.ID,
				Name: license.Name,
				Text: license.Text,
				URL:  license.URL,
			}
		}
		
		cyclonLicenses = append(cyclonLicenses, cyclonLicense)
	}
	
	return cyclonLicenses
}

// convertProperties converts properties to CycloneDX format
func (g *CycloneDXGenerator) convertProperties(properties []Property) []CycloneDXProperty {
	var cyclonProperties []CycloneDXProperty
	
	for _, prop := range properties {
		cyclonProperties = append(cyclonProperties, CycloneDXProperty{
			Name:  prop.Name,
			Value: prop.Value,
		})
	}
	
	return cyclonProperties
}

// convertEvidence converts evidence to CycloneDX format
func (g *CycloneDXGenerator) convertEvidence(evidence *Evidence) *CycloneDXEvidence {
	cyclonEvidence := &CycloneDXEvidence{}
	
	// Convert identity evidence
	if evidence.Identity != nil {
		cyclonEvidence.Identity = &CycloneDXEvidenceIdentity{
			Field:      evidence.Identity.Field,
			Confidence: evidence.Identity.Confidence,
		}
		
		// Convert methods
		if len(evidence.Identity.Methods) > 0 {
			var methods []CycloneDXEvidenceMethod
			for _, method := range evidence.Identity.Methods {
				methods = append(methods, CycloneDXEvidenceMethod{
					Technique:  method.Technique,
					Confidence: method.Confidence,
					Value:      method.Value,
				})
			}
			cyclonEvidence.Identity.Methods = methods
		}
	}
	
	// Convert occurrences
	if len(evidence.Occurrences) > 0 {
		var occurrences []CycloneDXEvidenceOccurrence
		for _, occ := range evidence.Occurrences {
			occurrence := CycloneDXEvidenceOccurrence{
				Location: occ.Location,
			}
			
			if occ.Line > 0 {
				occurrence.Line = occ.Line
			}
			
			if occ.Offset > 0 {
				occurrence.Offset = occ.Offset
			}
			
			occurrences = append(occurrences, occurrence)
		}
		cyclonEvidence.Occurrences = occurrences
	}
	
	return cyclonEvidence
}

// generateDependencies generates dependency relationships
func (g *CycloneDXGenerator) generateDependencies(components []Component) []CycloneDXDependency {
	var dependencies []CycloneDXDependency
	
	// Find main component
	var mainBOMRef string
	for _, comp := range components {
		if comp.Type == ComponentTypeApplication {
			mainBOMRef = comp.BOMRef
			break
		}
	}
	
	if mainBOMRef == "" {
		return dependencies
	}
	
	// Create main component dependencies
	var dependsOn []string
	for _, comp := range components {
		if comp.Type != ComponentTypeApplication {
			dependsOn = append(dependsOn, comp.BOMRef)
		}
	}
	
	if len(dependsOn) > 0 {
		dependencies = append(dependencies, CycloneDXDependency{
			Ref:       mainBOMRef,
			DependsOn: dependsOn,
		})
	}
	
	// Add individual component dependencies
	for _, comp := range components {
		if len(comp.Dependencies) > 0 {
			dependencies = append(dependencies, CycloneDXDependency{
				Ref:       comp.BOMRef,
				DependsOn: comp.Dependencies,
			})
		}
	}
	
	return dependencies
}

// generateCompositions generates composition information
func (g *CycloneDXGenerator) generateCompositions(components []Component) []CycloneDXComposition {
	var compositions []CycloneDXComposition
	
	// Create a complete composition
	var assemblies []string
	for _, comp := range components {
		assemblies = append(assemblies, comp.BOMRef)
	}
	
	if len(assemblies) > 0 {
		compositions = append(compositions, CycloneDXComposition{
			Aggregate:  "complete",
			Assemblies: assemblies,
		})
	}
	
	return compositions
}

// generateSerialNumber generates a unique serial number for the SBOM
func (g *CycloneDXGenerator) generateSerialNumber(binaryPath string) string {
	// Create a unique identifier based on binary path and timestamp
	timestamp := time.Now().Unix()
	return fmt.Sprintf("urn:uuid:%s-%d", 
		fmt.Sprintf("%x", []byte(binaryPath))[:8], timestamp)
}

// ValidateSchema validates the CycloneDX document against the schema
func (g *CycloneDXGenerator) ValidateSchema(doc *CycloneDXDocument) ValidationResult {
	var errors []string
	
	// Validate required fields
	if doc.BOMFormat != "CycloneDX" {
		errors = append(errors, "bomFormat must be 'CycloneDX'")
	}
	
	if doc.SpecVersion == "" {
		errors = append(errors, "specVersion is required")
	}
	
	if doc.SerialNumber == "" {
		errors = append(errors, "serialNumber is required")
	}
	
	if doc.Version <= 0 {
		errors = append(errors, "version must be positive")
	}
	
	// Validate metadata
	if len(doc.Metadata.Tools) == 0 {
		errors = append(errors, "at least one tool is required in metadata")
	}
	
	for i, tool := range doc.Metadata.Tools {
		if tool.Name == "" {
			errors = append(errors, fmt.Sprintf("tool %d: name is required", i))
		}
	}
	
	// Validate components
	bomRefs := make(map[string]bool)
	for i, comp := range doc.Components {
		if comp.BOMRef == "" {
			errors = append(errors, fmt.Sprintf("component %d: bom-ref is required", i))
		} else {
			if bomRefs[comp.BOMRef] {
				errors = append(errors, fmt.Sprintf("duplicate bom-ref: %s", comp.BOMRef))
			}
			bomRefs[comp.BOMRef] = true
		}
		
		if comp.Name == "" {
			errors = append(errors, fmt.Sprintf("component %d: name is required", i))
		}
		
		if comp.Type == "" {
			errors = append(errors, fmt.Sprintf("component %d: type is required", i))
		}
	}
	
	// Validate dependencies reference existing components
	for i, dep := range doc.Dependencies {
		if dep.Ref == "" {
			errors = append(errors, fmt.Sprintf("dependency %d: ref is required", i))
		}
		
		for j, depRef := range dep.DependsOn {
			if !bomRefs[depRef] {
				errors = append(errors, fmt.Sprintf("dependency %d.%d: references non-existent component %s", i, j, depRef))
			}
		}
	}
	
	return ValidationResult{
		Valid:  len(errors) == 0,
		Errors: errors,
	}
}