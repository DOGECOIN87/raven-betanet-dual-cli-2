package sbom

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Generator implements the SBOMGenerator interface
type Generator struct {
	extractor ComponentExtractor
}

// NewGenerator creates a new SBOM generator
func NewGenerator() *Generator {
	return &Generator{
		extractor: NewBinaryComponentExtractor(),
	}
}

// NewGeneratorWithExtractor creates a new SBOM generator with a custom extractor
func NewGeneratorWithExtractor(extractor ComponentExtractor) *Generator {
	return &Generator{
		extractor: extractor,
	}
}

// Generate creates an SBOM from a binary file
func (g *Generator) Generate(binaryPath string, format SBOMFormat) (*SBOM, error) {
	// Validate input
	if _, err := os.Stat(binaryPath); err != nil {
		return nil, fmt.Errorf("binary file not found: %w", err)
	}
	
	// Create new SBOM
	sbom := NewSBOM(format)
	sbom.SetVersion()
	
	// Set target information
	err := g.setTargetInfo(sbom, binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to set target info: %w", err)
	}
	
	// Extract components
	components, err := g.extractor.ExtractComponents(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to extract components: %w", err)
	}
	
	// Add components to SBOM
	for _, component := range components {
		sbom.AddComponent(component)
	}
	
	// Set serial number for uniqueness
	sbom.Metadata.SerialNumber = g.generateSerialNumber(binaryPath, sbom.GeneratedAt)
	
	// Validate the generated SBOM
	validation := sbom.Validate()
	if !validation.Valid {
		return nil, fmt.Errorf("generated SBOM is invalid: %v", validation.Errors)
	}
	
	return sbom, nil
}

// WriteToFile writes an SBOM to a file
func (g *Generator) WriteToFile(sbom *SBOM, outputPath string) error {
	// Create output directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	
	// Generate format-specific output
	var data []byte
	var err error
	
	switch sbom.Format {
	case CycloneDX:
		data, err = g.generateCycloneDXJSON(sbom)
	case SPDX:
		data, err = g.generateSPDXJSON(sbom)
	default:
		return fmt.Errorf("unsupported SBOM format: %s", sbom.Format)
	}
	
	if err != nil {
		return fmt.Errorf("failed to generate %s output: %w", sbom.Format, err)
	}
	
	// Write to file
	err = os.WriteFile(outputPath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write SBOM file: %w", err)
	}
	
	return nil
}

// GetSupportedFormats returns the SBOM formats this generator supports
func (g *Generator) GetSupportedFormats() []SBOMFormat {
	return []SBOMFormat{CycloneDX, SPDX}
}

// setTargetInfo sets the target information in the SBOM metadata
func (g *Generator) setTargetInfo(sbom *SBOM, binaryPath string) error {
	// Get file info
	fileInfo, err := os.Stat(binaryPath)
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}
	
	// Calculate file hash
	hash, err := g.calculateFileHash(binaryPath)
	if err != nil {
		return fmt.Errorf("failed to calculate file hash: %w", err)
	}
	
	// Get binary format info (basic detection)
	format, architecture, err := g.detectBinaryInfo(binaryPath)
	if err != nil {
		// Don't fail on detection error, just use unknown values
		format = "unknown"
		architecture = "unknown"
	}
	
	// Set target info
	hashes := map[string]string{
		"sha256": hash,
	}
	
	sbom.SetTarget(
		filepath.Base(binaryPath),
		binaryPath,
		fileInfo.Size(),
		hashes,
		architecture,
		format,
	)
	
	return nil
}

// generateSerialNumber generates a unique serial number for the SBOM
func (g *Generator) generateSerialNumber(binaryPath string, timestamp time.Time) string {
	// Create a unique identifier based on binary path and timestamp
	data := fmt.Sprintf("%s:%d", binaryPath, timestamp.Unix())
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x",
		hash[0:4], hash[4:6], hash[6:8], hash[8:10], hash[10:16])
}

// calculateFileHash calculates SHA256 hash of a file
func (g *Generator) calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	hasher := sha256.New()
	_, err = io.Copy(hasher, file)
	if err != nil {
		return "", err
	}
	
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

// detectBinaryInfo performs basic binary format and architecture detection
func (g *Generator) detectBinaryInfo(binaryPath string) (format, architecture string, err error) {
	file, err := os.Open(binaryPath)
	if err != nil {
		return "", "", err
	}
	defer file.Close()
	
	// Read first 20 bytes to detect format and architecture
	header := make([]byte, 20)
	_, err = file.ReadAt(header, 0)
	if err != nil {
		return "", "", err
	}
	
	// Detect format
	if len(header) >= 4 && header[0] == 0x7F && header[1] == 'E' && header[2] == 'L' && header[3] == 'F' {
		format = "ELF"
		// Basic architecture detection for ELF
		if len(header) >= 20 {
			// ELF machine type is at offset 18-19 (little endian)
			machine := uint16(header[18]) | uint16(header[19])<<8
			switch machine {
			case 0x3e:
				architecture = "x86_64"
			case 0x03:
				architecture = "i386"
			case 0x28:
				architecture = "arm"
			case 0xb7:
				architecture = "aarch64"
			default:
				architecture = "unknown"
			}
		} else {
			architecture = "unknown"
		}
	} else if len(header) >= 2 && header[0] == 'M' && header[1] == 'Z' {
		format = "PE"
		architecture = "x86" // Default, would need more parsing for accurate detection
	} else if len(header) >= 4 {
		magic := uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16 | uint32(header[3])<<24
		switch magic {
		case 0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcffaedfe, 0xcefaedfe:
			format = "Mach-O"
			architecture = "unknown" // Would need more parsing
		default:
			format = "unknown"
			architecture = "unknown"
		}
	} else {
		format = "unknown"
		architecture = "unknown"
	}
	
	return format, architecture, nil
}

// generateCycloneDXJSON generates CycloneDX JSON format
func (g *Generator) generateCycloneDXJSON(sbom *SBOM) ([]byte, error) {
	// Create CycloneDX structure
	cycloneDX := map[string]interface{}{
		"bomFormat":    "CycloneDX",
		"specVersion":  sbom.Version,
		"serialNumber": sbom.Metadata.SerialNumber,
		"version":      1,
		"metadata": map[string]interface{}{
			"timestamp": sbom.Metadata.Timestamp,
			"tools": []map[string]interface{}{
				{
					"vendor":  sbom.Metadata.Tool.Vendor,
					"name":    sbom.Metadata.Tool.Name,
					"version": sbom.Metadata.Tool.Version,
				},
			},
			"component": map[string]interface{}{
				"type":         "application",
				"bom-ref":      "main-component",
				"name":         sbom.Metadata.Target.Name,
				"version":      "1.0.0",
				"description":  fmt.Sprintf("Binary application (%s)", sbom.Metadata.Target.Format),
				"hashes":       g.convertHashesForCycloneDX(sbom.Metadata.Target.Hashes),
				"properties": []map[string]string{
					{"name": "binary:architecture", "value": sbom.Metadata.Target.Architecture},
					{"name": "binary:format", "value": sbom.Metadata.Target.Format},
					{"name": "binary:size", "value": fmt.Sprintf("%d", sbom.Metadata.Target.Size)},
				},
			},
		},
		"components": g.convertComponentsForCycloneDX(sbom.Components),
	}
	
	return json.MarshalIndent(cycloneDX, "", "  ")
}

// generateSPDXJSON generates SPDX JSON format
func (g *Generator) generateSPDXJSON(sbom *SBOM) ([]byte, error) {
	// Create SPDX structure
	spdx := map[string]interface{}{
		"spdxVersion":       "SPDX-" + sbom.Version,
		"dataLicense":       "CC0-1.0",
		"SPDXID":           "SPDXRef-DOCUMENT",
		"name":             fmt.Sprintf("SBOM for %s", sbom.Metadata.Target.Name),
		"documentNamespace": sbom.Metadata.SerialNumber,
		"creationInfo": map[string]interface{}{
			"created": sbom.Metadata.Timestamp,
			"creators": []string{
				fmt.Sprintf("Tool: %s-%s", sbom.Metadata.Tool.Name, sbom.Metadata.Tool.Version),
			},
		},
		"packages":      g.convertComponentsForSPDX(sbom.Components, sbom.Metadata.Target),
		"relationships": g.generateSPDXRelationships(sbom.Components),
	}
	
	return json.MarshalIndent(spdx, "", "  ")
}

// convertHashesForCycloneDX converts hashes to CycloneDX format
func (g *Generator) convertHashesForCycloneDX(hashes map[string]string) []map[string]string {
	var result []map[string]string
	for alg, value := range hashes {
		result = append(result, map[string]string{
			"alg":     alg,
			"content": value,
		})
	}
	return result
}

// convertComponentsForCycloneDX converts components to CycloneDX format
func (g *Generator) convertComponentsForCycloneDX(components []Component) []map[string]interface{} {
	var result []map[string]interface{}
	
	for _, comp := range components {
		component := map[string]interface{}{
			"type":    string(comp.Type),
			"bom-ref": comp.BOMRef,
			"name":    comp.Name,
		}
		
		if comp.Version != "" && comp.Version != "unknown" {
			component["version"] = comp.Version
		}
		
		if comp.Description != "" {
			component["description"] = comp.Description
		}
		
		if comp.Publisher != "" {
			component["publisher"] = comp.Publisher
		}
		
		if comp.Group != "" {
			component["group"] = comp.Group
		}
		
		if comp.Scope != "" {
			component["scope"] = string(comp.Scope)
		}
		
		if len(comp.Hashes) > 0 {
			component["hashes"] = g.convertHashesForCycloneDX(comp.Hashes)
		}
		
		if len(comp.Licenses) > 0 {
			var licenses []map[string]interface{}
			for _, license := range comp.Licenses {
				licenseMap := make(map[string]interface{})
				if license.ID != "" {
					licenseMap["license"] = map[string]string{"id": license.ID}
				} else if license.Name != "" {
					licenseMap["license"] = map[string]string{"name": license.Name}
				}
				licenses = append(licenses, licenseMap)
			}
			component["licenses"] = licenses
		}
		
		if len(comp.Properties) > 0 {
			var properties []map[string]string
			for _, prop := range comp.Properties {
				properties = append(properties, map[string]string{
					"name":  prop.Name,
					"value": prop.Value,
				})
			}
			component["properties"] = properties
		}
		
		if comp.Evidence != nil {
			component["evidence"] = g.convertEvidenceForCycloneDX(comp.Evidence)
		}
		
		result = append(result, component)
	}
	
	return result
}

// convertEvidenceForCycloneDX converts evidence to CycloneDX format
func (g *Generator) convertEvidenceForCycloneDX(evidence *Evidence) map[string]interface{} {
	result := make(map[string]interface{})
	
	if evidence.Identity != nil {
		result["identity"] = map[string]interface{}{
			"field":      evidence.Identity.Field,
			"confidence": evidence.Identity.Confidence,
		}
		
		if len(evidence.Identity.Methods) > 0 {
			var methods []map[string]interface{}
			for _, method := range evidence.Identity.Methods {
				methodMap := map[string]interface{}{
					"technique":  method.Technique,
					"confidence": method.Confidence,
				}
				if method.Value != "" {
					methodMap["value"] = method.Value
				}
				methods = append(methods, methodMap)
			}
			result["identity"].(map[string]interface{})["methods"] = methods
		}
	}
	
	if len(evidence.Occurrences) > 0 {
		var occurrences []map[string]interface{}
		for _, occ := range evidence.Occurrences {
			occMap := map[string]interface{}{
				"location": occ.Location,
			}
			if occ.Line > 0 {
				occMap["line"] = occ.Line
			}
			if occ.Offset > 0 {
				occMap["offset"] = occ.Offset
			}
			occurrences = append(occurrences, occMap)
		}
		result["occurrences"] = occurrences
	}
	
	return result
}

// convertComponentsForSPDX converts components to SPDX format
func (g *Generator) convertComponentsForSPDX(components []Component, target Target) []map[string]interface{} {
	var result []map[string]interface{}
	
	// Add main package first
	mainPackage := map[string]interface{}{
		"SPDXID":           "SPDXRef-Package-" + target.Name,
		"name":             target.Name,
		"downloadLocation": "NOASSERTION",
		"filesAnalyzed":    false,
		"copyrightText":    "NOASSERTION",
	}
	
	if len(target.Hashes) > 0 {
		var checksums []map[string]string
		for alg, value := range target.Hashes {
			checksums = append(checksums, map[string]string{
				"algorithm":     strings.ToUpper(alg),
				"checksumValue": value,
			})
		}
		mainPackage["checksums"] = checksums
	}
	
	result = append(result, mainPackage)
	
	// Add component packages
	for _, comp := range components {
		pkg := map[string]interface{}{
			"SPDXID":           "SPDXRef-Package-" + comp.BOMRef,
			"name":             comp.Name,
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed":    false,
			"copyrightText":    "NOASSERTION",
		}
		
		if comp.Version != "" && comp.Version != "unknown" {
			pkg["versionInfo"] = comp.Version
		}
		
		if comp.Description != "" {
			pkg["description"] = comp.Description
		}
		
		if comp.Publisher != "" {
			pkg["supplier"] = "Organization: " + comp.Publisher
		}
		
		if len(comp.Hashes) > 0 {
			var checksums []map[string]string
			for alg, value := range comp.Hashes {
				checksums = append(checksums, map[string]string{
					"algorithm":     strings.ToUpper(alg),
					"checksumValue": value,
				})
			}
			pkg["checksums"] = checksums
		}
		
		if len(comp.Licenses) > 0 {
			// Use first license for SPDX
			license := comp.Licenses[0]
			if license.ID != "" {
				pkg["licenseConcluded"] = license.ID
				pkg["licenseDeclared"] = license.ID
			} else if license.Name != "" {
				pkg["licenseConcluded"] = license.Name
				pkg["licenseDeclared"] = license.Name
			}
		} else {
			pkg["licenseConcluded"] = "NOASSERTION"
			pkg["licenseDeclared"] = "NOASSERTION"
		}
		
		result = append(result, pkg)
	}
	
	return result
}

// generateSPDXRelationships generates SPDX relationships
func (g *Generator) generateSPDXRelationships(components []Component) []map[string]string {
	var relationships []map[string]string
	
	// Find main component (application type)
	var mainBOMRef string
	for _, comp := range components {
		if comp.Type == ComponentTypeApplication {
			mainBOMRef = comp.BOMRef
			break
		}
	}
	
	if mainBOMRef == "" {
		return relationships
	}
	
	// Create dependency relationships
	for _, comp := range components {
		if comp.Type != ComponentTypeApplication {
			relationships = append(relationships, map[string]string{
				"spdxElementId":      "SPDXRef-Package-" + mainBOMRef,
				"relationshipType":   "DEPENDS_ON",
				"relatedSpdxElement": "SPDXRef-Package-" + comp.BOMRef,
			})
		}
	}
	
	return relationships
}