package sbom

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/raven-betanet/dual-cli/internal/checks"
)

// BinaryComponentExtractor extracts components from binary files using binary analysis
type BinaryComponentExtractor struct {
	parser *checks.BinaryParser
}

// NewBinaryComponentExtractor creates a new binary component extractor
func NewBinaryComponentExtractor() *BinaryComponentExtractor {
	return &BinaryComponentExtractor{
		parser: checks.NewBinaryParser(),
	}
}

// ExtractComponents extracts components from a binary file
func (e *BinaryComponentExtractor) ExtractComponents(binaryPath string) ([]Component, error) {
	var components []Component
	
	// Parse the binary to get metadata
	binaryInfo, err := e.parser.ParseBinary(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse binary: %w", err)
	}
	
	// Create the main application component
	mainComponent, err := e.createMainComponent(binaryPath, binaryInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to create main component: %w", err)
	}
	components = append(components, mainComponent)
	
	// Extract dependency components
	depComponents, err := e.extractDependencyComponents(binaryInfo, mainComponent.BOMRef)
	if err != nil {
		return nil, fmt.Errorf("failed to extract dependency components: %w", err)
	}
	components = append(components, depComponents...)
	
	// Extract symbol-based components (libraries identified through symbols)
	symbolComponents, err := e.extractSymbolComponents(binaryInfo, mainComponent.BOMRef)
	if err != nil {
		return nil, fmt.Errorf("failed to extract symbol components: %w", err)
	}
	components = append(components, symbolComponents...)
	
	return components, nil
}

// GetSupportedFormats returns the binary formats this extractor supports
func (e *BinaryComponentExtractor) GetSupportedFormats() []string {
	return []string{"ELF", "PE", "Mach-O"}
}

// createMainComponent creates the main application component
func (e *BinaryComponentExtractor) createMainComponent(binaryPath string, binaryInfo *checks.BinaryInfo) (Component, error) {
	
	// Calculate file hash
	hash, err := e.calculateFileHash(binaryPath)
	if err != nil {
		return Component{}, fmt.Errorf("failed to calculate file hash: %w", err)
	}
	
	// Create the main component
	fileName := filepath.Base(binaryPath)
	component := NewComponent(ComponentTypeApplication, fileName, "unknown")
	
	// Set basic properties
	component.Description = fmt.Sprintf("%s binary (%s %d-bit)", 
		binaryInfo.Format, binaryInfo.Architecture, binaryInfo.Bitness)
	component.Scope = ScopeRequired
	
	// Add hash
	component.AddHash("sha256", hash)
	
	// Add properties from binary analysis
	component.AddProperty("binary.format", string(binaryInfo.Format))
	component.AddProperty("binary.architecture", binaryInfo.Architecture)
	component.AddProperty("binary.bitness", fmt.Sprintf("%d", binaryInfo.Bitness))
	component.AddProperty("binary.endianness", binaryInfo.Endianness)
	component.AddProperty("binary.entry_point", fmt.Sprintf("0x%x", binaryInfo.EntryPoint))
	component.AddProperty("binary.file_size", fmt.Sprintf("%d", binaryInfo.FileSize))
	component.AddProperty("binary.section_count", fmt.Sprintf("%d", len(binaryInfo.Sections)))
	
	// Add sections as properties
	if len(binaryInfo.Sections) > 0 {
		component.AddProperty("binary.sections", strings.Join(binaryInfo.Sections, ","))
	}
	
	// Add evidence
	component.Evidence = &Evidence{
		Identity: &EvidenceIdentity{
			Field:      "binary_analysis",
			Confidence: 1.0,
			Methods: []EvidenceMethod{
				{
					Technique:  "binary_parsing",
					Confidence: 1.0,
					Value:      string(binaryInfo.Format),
				},
			},
		},
		Occurrences: []EvidenceOccurrence{
			{
				Location: binaryPath,
			},
		},
	}
	
	return component, nil
}

// extractDependencyComponents extracts components from binary dependencies
func (e *BinaryComponentExtractor) extractDependencyComponents(binaryInfo *checks.BinaryInfo, mainBOMRef string) ([]Component, error) {
	var components []Component
	
	for _, dep := range binaryInfo.Dependencies {
		component := e.createDependencyComponent(dep, binaryInfo.Format)
		
		// Add dependency relationship to main component
		component.AddProperty("dependency.type", "runtime")
		component.AddProperty("dependency.scope", "required")
		
		// Add evidence
		component.Evidence = &Evidence{
			Identity: &EvidenceIdentity{
				Field:      "dependency_analysis",
				Confidence: 0.9,
				Methods: []EvidenceMethod{
					{
						Technique:  "dynamic_linking_analysis",
						Confidence: 0.9,
						Value:      dep,
					},
				},
			},
		}
		
		components = append(components, component)
	}
	
	return components, nil
}

// createDependencyComponent creates a component for a dependency
func (e *BinaryComponentExtractor) createDependencyComponent(depName string, binaryFormat checks.BinaryFormat) Component {
	// Determine component type based on dependency name and format
	componentType := e.inferComponentType(depName, binaryFormat)
	
	// Extract version if present in dependency name
	name, version := e.parseNameVersion(depName)
	
	component := NewComponent(componentType, name, version)
	component.Scope = ScopeRequired
	
	// Add format-specific properties
	switch binaryFormat {
	case checks.FormatELF:
		component.AddProperty("dependency.format", "shared_library")
		if strings.HasPrefix(depName, "lib") && strings.HasSuffix(depName, ".so") {
			component.AddProperty("dependency.type", "shared_object")
		}
	case checks.FormatPE:
		component.AddProperty("dependency.format", "dll")
		if strings.HasSuffix(strings.ToLower(depName), ".dll") {
			component.AddProperty("dependency.type", "dynamic_link_library")
		}
	case checks.FormatMachO:
		component.AddProperty("dependency.format", "dylib")
		if strings.HasSuffix(depName, ".dylib") {
			component.AddProperty("dependency.type", "dynamic_library")
		}
	}
	
	return component
}

// extractSymbolComponents extracts components based on symbol analysis
func (e *BinaryComponentExtractor) extractSymbolComponents(binaryInfo *checks.BinaryInfo, mainBOMRef string) ([]Component, error) {
	var components []Component
	
	// Group symbols by potential library/framework
	librarySymbols := e.groupSymbolsByLibrary(binaryInfo.Symbols)
	
	for library, symbols := range librarySymbols {
		if len(symbols) < 3 { // Only consider libraries with multiple symbols
			continue
		}
		
		component := NewComponent(ComponentTypeLibrary, library, "unknown")
		component.Scope = ScopeRequired
		component.Description = fmt.Sprintf("Library identified through symbol analysis (%d symbols)", len(symbols))
		
		// Add symbol information as properties
		component.AddProperty("symbols.count", fmt.Sprintf("%d", len(symbols)))
		component.AddProperty("symbols.detection_method", "symbol_analysis")
		
		// Add a sample of symbols (limit to avoid huge properties)
		sampleSize := 10
		if len(symbols) < sampleSize {
			sampleSize = len(symbols)
		}
		component.AddProperty("symbols.sample", strings.Join(symbols[:sampleSize], ","))
		
		// Add evidence
		component.Evidence = &Evidence{
			Identity: &EvidenceIdentity{
				Field:      "symbol_analysis",
				Confidence: 0.7, // Lower confidence as this is heuristic
				Methods: []EvidenceMethod{
					{
						Technique:  "symbol_pattern_matching",
						Confidence: 0.7,
						Value:      library,
					},
				},
			},
		}
		
		components = append(components, component)
	}
	
	return components, nil
}

// inferComponentType infers the component type based on dependency name and format
func (e *BinaryComponentExtractor) inferComponentType(depName string, binaryFormat checks.BinaryFormat) ComponentType {
	depLower := strings.ToLower(depName)
	
	// Check for common frameworks
	frameworks := []string{"qt", "gtk", "wxwidgets", "fltk", "sdl", "opengl", "directx", "vulkan"}
	for _, framework := range frameworks {
		if strings.Contains(depLower, framework) {
			return ComponentTypeFramework
		}
	}
	
	// Check for system libraries
	systemLibs := []string{"libc", "libm", "libpthread", "libdl", "librt", "kernel32", "user32", "gdi32", "advapi32"}
	for _, sysLib := range systemLibs {
		if strings.Contains(depLower, sysLib) {
			return ComponentTypeOperatingSystem
		}
	}
	
	// Default to library
	return ComponentTypeLibrary
}

// parseNameVersion attempts to parse name and version from a dependency string
func (e *BinaryComponentExtractor) parseNameVersion(depName string) (name, version string) {
	// Handle common versioning patterns
	
	// Pattern: libname.so.1.2.3
	if strings.Contains(depName, ".so.") {
		parts := strings.Split(depName, ".so.")
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
	}
	
	// Pattern: libname-1.2.3.dll
	if strings.Contains(depName, "-") && (strings.HasSuffix(depName, ".dll") || strings.HasSuffix(depName, ".dylib")) {
		parts := strings.Split(depName, "-")
		if len(parts) >= 2 {
			name = strings.Join(parts[:len(parts)-1], "-")
			version = strings.TrimSuffix(strings.TrimSuffix(parts[len(parts)-1], ".dll"), ".dylib")
			// Check if version looks like a version number
			if e.looksLikeVersion(version) {
				return name, version
			}
		}
	}
	
	// Pattern: name.1.2.3.dylib
	if strings.HasSuffix(depName, ".dylib") {
		withoutExt := strings.TrimSuffix(depName, ".dylib")
		parts := strings.Split(withoutExt, ".")
		if len(parts) > 1 {
			// Check if last parts look like version numbers
			versionParts := []string{}
			nameParts := []string{}
			
			for i := len(parts) - 1; i >= 0; i-- {
				if e.looksLikeVersionPart(parts[i]) {
					versionParts = append([]string{parts[i]}, versionParts...)
				} else {
					nameParts = parts[:i+1]
					break
				}
			}
			
			if len(versionParts) > 0 && len(nameParts) > 0 {
				return strings.Join(nameParts, "."), strings.Join(versionParts, ".")
			}
		}
	}
	
	// No version found, return name as-is
	return depName, "unknown"
}

// looksLikeVersion checks if a string looks like a version number
func (e *BinaryComponentExtractor) looksLikeVersion(s string) bool {
	// Simple heuristic: contains digits and valid version characters
	hasDigit := false
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '.' || r == '-' || r == '_'
	})
	
	for _, part := range parts {
		partHasDigit := false
		for _, r := range part {
			if r >= '0' && r <= '9' {
				partHasDigit = true
				hasDigit = true
			} else if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') {
				return false
			}
		}
		// Each part should have at least one digit or be a known version suffix
		if !partHasDigit && part != "alpha" && part != "beta" && part != "rc" && 
		   part != "a" && part != "b" && part != "c" {
			return false
		}
	}
	return hasDigit
}

// looksLikeVersionPart checks if a string looks like part of a version number
func (e *BinaryComponentExtractor) looksLikeVersionPart(s string) bool {
	// Must be all digits or contain digits with minimal other characters
	hasDigit := false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			hasDigit = true
		} else if r != 'a' && r != 'b' && r != 'r' && r != 'c' { // alpha, beta, rc
			return false
		}
	}
	return hasDigit
}

// groupSymbolsByLibrary groups symbols by potential library based on naming patterns
func (e *BinaryComponentExtractor) groupSymbolsByLibrary(symbols []string) map[string][]string {
	librarySymbols := make(map[string][]string)
	
	for _, symbol := range symbols {
		library := e.inferLibraryFromSymbol(symbol)
		if library != "" {
			librarySymbols[library] = append(librarySymbols[library], symbol)
		}
	}
	
	return librarySymbols
}

// inferLibraryFromSymbol infers library name from symbol name
func (e *BinaryComponentExtractor) inferLibraryFromSymbol(symbol string) string {
	// Common library prefixes
	prefixes := map[string]string{
		"std::":     "libstdc++",
		"boost::":   "boost",
		"Qt":        "Qt",
		"gtk_":      "GTK",
		"g_":        "GLib",
		"cairo_":    "Cairo",
		"png_":      "libpng",
		"jpeg_":     "libjpeg",
		"ssl_":      "OpenSSL",
		"crypto_":   "OpenSSL",
		"curl_":     "libcurl",
		"sqlite3_":  "SQLite",
		"mysql_":    "MySQL",
		"postgres_": "PostgreSQL",
		"xml":       "libxml2",
		"json":      "JSON library",
		"deflate":   "zlib",
		"BZ2_":      "bzip2",
	}
	
	for prefix, library := range prefixes {
		if strings.HasPrefix(symbol, prefix) {
			return library
		}
	}
	
	// Check for C++ standard library symbols
	if strings.Contains(symbol, "std::") {
		return "libstdc++"
	}
	
	// Check for zlib functions that don't have prefixes
	if symbol == "deflate" || symbol == "inflate" || strings.HasPrefix(symbol, "z_") {
		return "zlib"
	}
	
	// Check for bzip2 functions
	if strings.HasPrefix(symbol, "BZ2_") {
		return "bzip2"
	}
	
	// Check for common function patterns
	if strings.HasPrefix(symbol, "__") {
		// Compiler/runtime symbols, skip
		return ""
	}
	
	return ""
}

// calculateFileHash calculates SHA256 hash of a file
func (e *BinaryComponentExtractor) calculateFileHash(filePath string) (string, error) {
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