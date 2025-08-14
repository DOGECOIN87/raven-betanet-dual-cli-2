package sbom

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SPDXGenerator implements SPDX 2.3 JSON schema compliance
type SPDXGenerator struct {
	extractor ComponentExtractor
}

// NewSPDXGenerator creates a new SPDX generator
func NewSPDXGenerator() *SPDXGenerator {
	return &SPDXGenerator{
		extractor: NewBinaryComponentExtractor(),
	}
}

// NewSPDXGeneratorWithExtractor creates a new SPDX generator with custom extractor
func NewSPDXGeneratorWithExtractor(extractor ComponentExtractor) *SPDXGenerator {
	return &SPDXGenerator{
		extractor: extractor,
	}
}

// SPDXDocument represents the complete SPDX document structure
type SPDXDocument struct {
	SPDXVersion       string                 `json:"spdxVersion"`
	DataLicense       string                 `json:"dataLicense"`
	SPDXID           string                 `json:"SPDXID"`
	Name             string                 `json:"name"`
	DocumentNamespace string                 `json:"documentNamespace"`
	CreationInfo     SPDXCreationInfo       `json:"creationInfo"`
	Packages         []SPDXPackage          `json:"packages"`
	Files            []SPDXFile             `json:"files,omitempty"`
	Snippets         []SPDXSnippet          `json:"snippets,omitempty"`
	ExtractedLicenses []SPDXExtractedLicense `json:"hasExtractedLicensingInfos,omitempty"`
	Relationships    []SPDXRelationship     `json:"relationships"`
	Annotations      []SPDXAnnotation       `json:"annotations,omitempty"`
}

// SPDXCreationInfo represents SPDX creation information
type SPDXCreationInfo struct {
	Created            string   `json:"created"`
	Creators           []string `json:"creators"`
	LicenseListVersion string   `json:"licenseListVersion,omitempty"`
	Comment            string   `json:"comment,omitempty"`
}

// SPDXPackage represents an SPDX package
type SPDXPackage struct {
	SPDXID               string              `json:"SPDXID"`
	Name                 string              `json:"name"`
	DownloadLocation     string              `json:"downloadLocation"`
	FilesAnalyzed        bool                `json:"filesAnalyzed"`
	LicenseConcluded     string              `json:"licenseConcluded"`
	LicenseDeclared      string              `json:"licenseDeclared"`
	LicenseInfoFromFiles []string            `json:"licenseInfoFromFiles,omitempty"`
	LicenseComments      string              `json:"licenseComments,omitempty"`
	CopyrightText        string              `json:"copyrightText"`
	Summary              string              `json:"summary,omitempty"`
	Description          string              `json:"description,omitempty"`
	Comment              string              `json:"comment,omitempty"`
	Homepage             string              `json:"homepage,omitempty"`
	SourceInfo           string              `json:"sourceInfo,omitempty"`
	VersionInfo          string              `json:"versionInfo,omitempty"`
	PackageFileName      string              `json:"packageFileName,omitempty"`
	Supplier             string              `json:"supplier,omitempty"`
	Originator           string              `json:"originator,omitempty"`
	Checksums            []SPDXChecksum      `json:"checksums,omitempty"`
	PackageVerificationCode *SPDXVerificationCode `json:"packageVerificationCode,omitempty"`
	ExternalRefs         []SPDXExternalRef   `json:"externalRefs,omitempty"`
	AttributionTexts     []string            `json:"attributionTexts,omitempty"`
	PrimaryPackagePurpose string             `json:"primaryPackagePurpose,omitempty"`
	ReleaseDate          string              `json:"releaseDate,omitempty"`
	BuiltDate            string              `json:"builtDate,omitempty"`
	ValidUntilDate       string              `json:"validUntilDate,omitempty"`
}

// SPDXFile represents an SPDX file
type SPDXFile struct {
	SPDXID               string         `json:"SPDXID"`
	FileName             string         `json:"fileName"`
	Checksums            []SPDXChecksum `json:"checksums"`
	LicenseConcluded     string         `json:"licenseConcluded"`
	LicenseInfoInFiles   []string       `json:"licenseInfoInFiles"`
	LicenseComments      string         `json:"licenseComments,omitempty"`
	CopyrightText        string         `json:"copyrightText"`
	Comment              string         `json:"comment,omitempty"`
	NoticeText           string         `json:"noticeText,omitempty"`
	Contributors         []string       `json:"contributors,omitempty"`
	AttributionTexts     []string       `json:"attributionTexts,omitempty"`
	FileTypes            []string       `json:"fileTypes,omitempty"`
}

// SPDXSnippet represents an SPDX snippet
type SPDXSnippet struct {
	SPDXID               string              `json:"SPDXID"`
	SnippetFromFile      string              `json:"snippetFromFile"`
	Ranges               []SPDXRange         `json:"ranges"`
	LicenseConcluded     string              `json:"licenseConcluded"`
	LicenseInfoInSnippets []string           `json:"licenseInfoInSnippets"`
	LicenseComments      string              `json:"licenseComments,omitempty"`
	CopyrightText        string              `json:"copyrightText"`
	Comment              string              `json:"comment,omitempty"`
	Name                 string              `json:"name,omitempty"`
	AttributionTexts     []string            `json:"attributionTexts,omitempty"`
}

// SPDXRange represents a range in an SPDX snippet
type SPDXRange struct {
	StartPointer SPDXPointer `json:"startPointer"`
	EndPointer   SPDXPointer `json:"endPointer"`
}

// SPDXPointer represents a pointer in SPDX
type SPDXPointer struct {
	Offset    int    `json:"offset,omitempty"`
	LineNumber int   `json:"lineNumber,omitempty"`
	Reference string `json:"reference,omitempty"`
}

// SPDXChecksum represents an SPDX checksum
type SPDXChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

// SPDXVerificationCode represents SPDX package verification code
type SPDXVerificationCode struct {
	PackageVerificationCodeValue         string   `json:"packageVerificationCodeValue"`
	PackageVerificationCodeExcludedFiles []string `json:"packageVerificationCodeExcludedFiles,omitempty"`
}

// SPDXExternalRef represents an SPDX external reference
type SPDXExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
	Comment           string `json:"comment,omitempty"`
}

// SPDXExtractedLicense represents an SPDX extracted license
type SPDXExtractedLicense struct {
	LicenseID      string   `json:"licenseId"`
	ExtractedText  string   `json:"extractedText"`
	Name           string   `json:"name,omitempty"`
	SeeAlsos       []string `json:"seeAlsos,omitempty"`
	Comment        string   `json:"comment,omitempty"`
}

// SPDXRelationship represents an SPDX relationship
type SPDXRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	Comment            string `json:"comment,omitempty"`
}

// SPDXAnnotation represents an SPDX annotation
type SPDXAnnotation struct {
	SPDXRef          string `json:"spdxRef"`
	AnnotationType   string `json:"annotationType"`
	Annotator        string `json:"annotator"`
	AnnotationDate   string `json:"annotationDate"`
	AnnotationComment string `json:"annotationComment"`
}

// Generate creates an SPDX SBOM from a binary file
func (g *SPDXGenerator) Generate(binaryPath string) (*SPDXDocument, error) {
	// Extract components using the extractor
	components, err := g.extractor.ExtractComponents(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to extract components: %w", err)
	}
	
	// Create SPDX document
	doc := &SPDXDocument{
		SPDXVersion:   "SPDX-2.3",
		DataLicense:   "CC0-1.0",
		SPDXID:       "SPDXRef-DOCUMENT",
		Name:         fmt.Sprintf("SBOM for %s", extractFileName(binaryPath)),
		CreationInfo: SPDXCreationInfo{
			Created: time.Now().UTC().Format(time.RFC3339),
			Creators: []string{
				"Tool: raven-linter-1.0.0", // This should be injected at build time
			},
		},
	}
	
	// Generate document namespace
	doc.DocumentNamespace = g.generateDocumentNamespace(binaryPath)
	
	// Convert components to packages
	doc.Packages = g.convertComponentsToPackages(components, binaryPath)
	
	// Generate relationships
	doc.Relationships = g.generateRelationships(components)
	
	return doc, nil
}

// GenerateJSON creates an SPDX SBOM in JSON format
func (g *SPDXGenerator) GenerateJSON(binaryPath string) ([]byte, error) {
	doc, err := g.Generate(binaryPath)
	if err != nil {
		return nil, err
	}
	
	return json.MarshalIndent(doc, "", "  ")
}

// convertComponentsToPackages converts internal components to SPDX packages
func (g *SPDXGenerator) convertComponentsToPackages(components []Component, binaryPath string) []SPDXPackage {
	var packages []SPDXPackage
	
	// Create main package first
	mainPackage := g.createMainPackage(binaryPath, components)
	packages = append(packages, mainPackage)
	
	// Convert component packages
	for _, comp := range components {
		// Skip application components as they are the main package
		if comp.Type == ComponentTypeApplication {
			continue
		}
		
		pkg := g.convertComponentToPackage(comp)
		packages = append(packages, pkg)
	}
	
	return packages
}

// createMainPackage creates the main package from the binary
func (g *SPDXGenerator) createMainPackage(binaryPath string, components []Component) SPDXPackage {
	fileName := extractFileName(binaryPath)
	
	// Find main application component for details
	var mainComp *Component
	for _, comp := range components {
		if comp.Type == ComponentTypeApplication {
			mainComp = &comp
			break
		}
	}
	
	pkg := SPDXPackage{
		SPDXID:           "SPDXRef-Package-" + sanitizeID(fileName),
		Name:             fileName,
		DownloadLocation: "NOASSERTION",
		FilesAnalyzed:    false,
		LicenseConcluded: "NOASSERTION",
		LicenseDeclared:  "NOASSERTION",
		CopyrightText:    "NOASSERTION",
		Description:      fmt.Sprintf("Binary application: %s", fileName),
	}
	
	// Add details from main component if available
	if mainComp != nil {
		if mainComp.Version != "" && mainComp.Version != "unknown" {
			pkg.VersionInfo = mainComp.Version
		}
		
		if mainComp.Description != "" {
			pkg.Description = mainComp.Description
		}
		
		if mainComp.Publisher != "" {
			pkg.Supplier = "Organization: " + mainComp.Publisher
		}
		
		if mainComp.Copyright != "" {
			pkg.CopyrightText = mainComp.Copyright
		}
		
		// Convert hashes to checksums
		if len(mainComp.Hashes) > 0 {
			pkg.Checksums = g.convertHashesToChecksums(mainComp.Hashes)
		}
		
		// Set license information
		if len(mainComp.Licenses) > 0 {
			license := mainComp.Licenses[0] // Use first license
			if license.ID != "" {
				pkg.LicenseConcluded = license.ID
				pkg.LicenseDeclared = license.ID
			} else if license.Name != "" {
				pkg.LicenseConcluded = license.Name
				pkg.LicenseDeclared = license.Name
			}
		}
		
		// Set primary package purpose based on component type
		pkg.PrimaryPackagePurpose = g.mapComponentTypeToPurpose(mainComp.Type)
	}
	
	return pkg
}

// convertComponentToPackage converts a component to an SPDX package
func (g *SPDXGenerator) convertComponentToPackage(comp Component) SPDXPackage {
	pkg := SPDXPackage{
		SPDXID:           "SPDXRef-Package-" + sanitizeID(comp.BOMRef),
		Name:             comp.Name,
		DownloadLocation: "NOASSERTION",
		FilesAnalyzed:    false,
		LicenseConcluded: "NOASSERTION",
		LicenseDeclared:  "NOASSERTION",
		CopyrightText:    "NOASSERTION",
	}
	
	// Set version if available
	if comp.Version != "" && comp.Version != "unknown" {
		pkg.VersionInfo = comp.Version
	}
	
	// Set description
	if comp.Description != "" {
		pkg.Description = comp.Description
	}
	
	// Set supplier
	if comp.Publisher != "" {
		pkg.Supplier = "Organization: " + comp.Publisher
	}
	
	// Set copyright
	if comp.Copyright != "" {
		pkg.CopyrightText = comp.Copyright
	}
	
	// Convert hashes to checksums
	if len(comp.Hashes) > 0 {
		pkg.Checksums = g.convertHashesToChecksums(comp.Hashes)
	}
	
	// Set license information
	if len(comp.Licenses) > 0 {
		license := comp.Licenses[0] // Use first license
		if license.ID != "" {
			pkg.LicenseConcluded = license.ID
			pkg.LicenseDeclared = license.ID
		} else if license.Name != "" {
			pkg.LicenseConcluded = license.Name
			pkg.LicenseDeclared = license.Name
		}
	}
	
	// Set primary package purpose
	pkg.PrimaryPackagePurpose = g.mapComponentTypeToPurpose(comp.Type)
	
	// Add source info from properties
	var sourceInfoParts []string
	for _, prop := range comp.Properties {
		if strings.HasPrefix(prop.Name, "binary.") {
			sourceInfoParts = append(sourceInfoParts, fmt.Sprintf("%s: %s", prop.Name, prop.Value))
		}
	}
	if len(sourceInfoParts) > 0 {
		pkg.SourceInfo = strings.Join(sourceInfoParts, "; ")
	}
	
	return pkg
}

// convertHashesToChecksums converts hashes to SPDX checksums
func (g *SPDXGenerator) convertHashesToChecksums(hashes map[string]string) []SPDXChecksum {
	var checksums []SPDXChecksum
	
	for alg, value := range hashes {
		checksums = append(checksums, SPDXChecksum{
			Algorithm:     strings.ToUpper(alg),
			ChecksumValue: value,
		})
	}
	
	return checksums
}

// mapComponentTypeToPurpose maps component types to SPDX package purposes
func (g *SPDXGenerator) mapComponentTypeToPurpose(componentType ComponentType) string {
	switch componentType {
	case ComponentTypeApplication:
		return "APPLICATION"
	case ComponentTypeLibrary:
		return "LIBRARY"
	case ComponentTypeFramework:
		return "FRAMEWORK"
	case ComponentTypeContainer:
		return "CONTAINER"
	case ComponentTypeOperatingSystem:
		return "OPERATING-SYSTEM"
	case ComponentTypeDevice:
		return "DEVICE"
	case ComponentTypeFirmware:
		return "FIRMWARE"
	case ComponentTypeFile:
		return "FILE"
	default:
		return "OTHER"
	}
}

// generateRelationships generates SPDX relationships
func (g *SPDXGenerator) generateRelationships(components []Component) []SPDXRelationship {
	var relationships []SPDXRelationship
	
	// Find main component
	var mainSPDXID string
	for _, comp := range components {
		if comp.Type == ComponentTypeApplication {
			mainSPDXID = "SPDXRef-Package-" + sanitizeID(comp.BOMRef)
			break
		}
	}
	
	if mainSPDXID == "" {
		return relationships
	}
	
	// Create DESCRIBES relationship from document to main package
	relationships = append(relationships, SPDXRelationship{
		SPDXElementID:      "SPDXRef-DOCUMENT",
		RelationshipType:   "DESCRIBES",
		RelatedSPDXElement: mainSPDXID,
	})
	
	// Create dependency relationships
	for _, comp := range components {
		if comp.Type != ComponentTypeApplication {
			relationships = append(relationships, SPDXRelationship{
				SPDXElementID:      mainSPDXID,
				RelationshipType:   "DEPENDS_ON",
				RelatedSPDXElement: "SPDXRef-Package-" + sanitizeID(comp.BOMRef),
			})
		}
		
		// Add component-specific dependencies
		for _, depRef := range comp.Dependencies {
			relationships = append(relationships, SPDXRelationship{
				SPDXElementID:      "SPDXRef-Package-" + sanitizeID(comp.BOMRef),
				RelationshipType:   "DEPENDS_ON",
				RelatedSPDXElement: "SPDXRef-Package-" + sanitizeID(depRef),
			})
		}
	}
	
	return relationships
}

// generateDocumentNamespace generates a unique document namespace
func (g *SPDXGenerator) generateDocumentNamespace(binaryPath string) string {
	timestamp := time.Now().Unix()
	fileName := extractFileName(binaryPath)
	return fmt.Sprintf("https://raven-betanet.com/spdx/%s-%d", sanitizeID(fileName), timestamp)
}

// extractFileName extracts the filename from a path
func extractFileName(path string) string {
	if path == "" {
		return "unknown"
	}
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return "unknown"
	}
	filename := parts[len(parts)-1]
	if filename == "" {
		return "unknown"
	}
	return filename
}

// sanitizeID sanitizes a string to be used as an SPDX ID
func sanitizeID(id string) string {
	// Replace invalid characters with hyphens
	result := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			return r
		}
		return '-'
	}, id)
	
	// Ensure it doesn't start with a number or hyphen
	if len(result) > 0 && (result[0] >= '0' && result[0] <= '9' || result[0] == '-') {
		result = "pkg-" + result
	}
	
	return result
}

// ValidateSchema validates the SPDX document against the schema
func (g *SPDXGenerator) ValidateSchema(doc *SPDXDocument) ValidationResult {
	var errors []string
	
	// Validate required fields
	if doc.SPDXVersion == "" {
		errors = append(errors, "spdxVersion is required")
	} else if !strings.HasPrefix(doc.SPDXVersion, "SPDX-") {
		errors = append(errors, "spdxVersion must start with 'SPDX-'")
	}
	
	if doc.DataLicense != "CC0-1.0" {
		errors = append(errors, "dataLicense must be 'CC0-1.0'")
	}
	
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		errors = append(errors, "SPDXID must be 'SPDXRef-DOCUMENT'")
	}
	
	if doc.Name == "" {
		errors = append(errors, "name is required")
	}
	
	if doc.DocumentNamespace == "" {
		errors = append(errors, "documentNamespace is required")
	}
	
	// Validate creation info
	if doc.CreationInfo.Created == "" {
		errors = append(errors, "creationInfo.created is required")
	} else {
		_, err := time.Parse(time.RFC3339, doc.CreationInfo.Created)
		if err != nil {
			errors = append(errors, "creationInfo.created must be in RFC3339 format")
		}
	}
	
	if len(doc.CreationInfo.Creators) == 0 {
		errors = append(errors, "at least one creator is required")
	}
	
	// Validate packages
	spdxIDs := make(map[string]bool)
	spdxIDs[doc.SPDXID] = true
	
	for i, pkg := range doc.Packages {
		if pkg.SPDXID == "" {
			errors = append(errors, fmt.Sprintf("package %d: SPDXID is required", i))
		} else {
			if spdxIDs[pkg.SPDXID] {
				errors = append(errors, fmt.Sprintf("duplicate SPDXID: %s", pkg.SPDXID))
			}
			spdxIDs[pkg.SPDXID] = true
		}
		
		if pkg.Name == "" {
			errors = append(errors, fmt.Sprintf("package %d: name is required", i))
		}
		
		if pkg.DownloadLocation == "" {
			errors = append(errors, fmt.Sprintf("package %d: downloadLocation is required", i))
		}
		
		if pkg.LicenseConcluded == "" {
			errors = append(errors, fmt.Sprintf("package %d: licenseConcluded is required", i))
		}
		
		if pkg.LicenseDeclared == "" {
			errors = append(errors, fmt.Sprintf("package %d: licenseDeclared is required", i))
		}
		
		if pkg.CopyrightText == "" {
			errors = append(errors, fmt.Sprintf("package %d: copyrightText is required", i))
		}
	}
	
	// Validate relationships reference existing SPDX IDs
	for i, rel := range doc.Relationships {
		if rel.SPDXElementID == "" {
			errors = append(errors, fmt.Sprintf("relationship %d: spdxElementId is required", i))
		} else if !spdxIDs[rel.SPDXElementID] {
			errors = append(errors, fmt.Sprintf("relationship %d: references non-existent SPDX ID %s", i, rel.SPDXElementID))
		}
		
		if rel.RelationshipType == "" {
			errors = append(errors, fmt.Sprintf("relationship %d: relationshipType is required", i))
		}
		
		if rel.RelatedSPDXElement == "" {
			errors = append(errors, fmt.Sprintf("relationship %d: relatedSpdxElement is required", i))
		} else if !spdxIDs[rel.RelatedSPDXElement] {
			errors = append(errors, fmt.Sprintf("relationship %d: references non-existent SPDX ID %s", i, rel.RelatedSPDXElement))
		}
	}
	
	return ValidationResult{
		Valid:  len(errors) == 0,
		Errors: errors,
	}
}