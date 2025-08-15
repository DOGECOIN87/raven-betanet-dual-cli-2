package sbom

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// BinaryComponentExtractor extracts components from binary files
type BinaryComponentExtractor struct{}

// NewBinaryComponentExtractor creates a new binary component extractor
func NewBinaryComponentExtractor() *BinaryComponentExtractor {
	return &BinaryComponentExtractor{}
}

// ExtractComponents extracts components from a binary file
func (e *BinaryComponentExtractor) ExtractComponents(binaryPath string) ([]Component, error) {
	var components []Component

	// Detect binary format
	format, err := e.detectBinaryFormat(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to detect binary format: %w", err)
	}

	// Extract components based on format
	switch format {
	case "ELF":
		elfComponents, err := e.extractELFComponents(binaryPath)
		if err != nil {
			return nil, fmt.Errorf("failed to extract ELF components: %w", err)
		}
		components = append(components, elfComponents...)
	case "PE":
		peComponents, err := e.extractPEComponents(binaryPath)
		if err != nil {
			return nil, fmt.Errorf("failed to extract PE components: %w", err)
		}
		components = append(components, peComponents...)
	case "Mach-O":
		machoComponents, err := e.extractMachOComponents(binaryPath)
		if err != nil {
			return nil, fmt.Errorf("failed to extract Mach-O components: %w", err)
		}
		components = append(components, machoComponents...)
	default:
		// For unknown formats, create a basic component
		basicComponent := e.createBasicComponent(binaryPath)
		components = append(components, basicComponent)
	}

	// Extract embedded components (strings, licenses, etc.)
	embeddedComponents, err := e.extractEmbeddedComponents(binaryPath)
	if err != nil {
		// Don't fail on embedded component extraction errors, just log
		// In a real implementation, you'd use a logger here
	} else {
		components = append(components, embeddedComponents...)
	}

	return components, nil
}

// GetSupportedFormats returns the binary formats this extractor supports
func (e *BinaryComponentExtractor) GetSupportedFormats() []string {
	return []string{"ELF", "PE", "Mach-O"}
}

// detectBinaryFormat detects the format of a binary file
func (e *BinaryComponentExtractor) detectBinaryFormat(binaryPath string) (string, error) {
	file, err := os.Open(binaryPath)
	if err != nil {
		return "", fmt.Errorf("failed to open binary file: %w", err)
	}
	defer file.Close()

	// Read first 16 bytes to detect format
	header := make([]byte, 16)
	_, err = file.Read(header)
	if err != nil {
		return "", fmt.Errorf("failed to read file header: %w", err)
	}

	// ELF magic: 0x7F 'E' 'L' 'F'
	if len(header) >= 4 && header[0] == 0x7F && header[1] == 'E' && header[2] == 'L' && header[3] == 'F' {
		return "ELF", nil
	}

	// PE magic: 'M' 'Z'
	if len(header) >= 2 && header[0] == 'M' && header[1] == 'Z' {
		return "PE", nil
	}

	// Mach-O magic numbers
	if len(header) >= 4 {
		magic := uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16 | uint32(header[3])<<24
		switch magic {
		case 0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcffaedfe, 0xcefaedfe:
			return "Mach-O", nil
		}
	}

	return "Unknown", nil
}

// extractELFComponents extracts components from ELF binaries
func (e *BinaryComponentExtractor) extractELFComponents(binaryPath string) ([]Component, error) {
	var components []Component

	elfFile, err := elf.Open(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF file: %w", err)
	}
	defer elfFile.Close()

	// Create main application component
	mainComponent := NewComponent(ComponentTypeApplication, filepath.Base(binaryPath), "1.0.0")
	mainComponent.Description = fmt.Sprintf("ELF binary (%s)", elfFile.Machine.String())
	mainComponent.AddProperty("binary.format", "ELF")
	mainComponent.AddProperty("binary.architecture", elfFile.Machine.String())
	mainComponent.AddProperty("binary.class", e.getELFClass(elfFile.Class))
	mainComponent.AddProperty("binary.data", e.getELFData(elfFile.Data))
	mainComponent.AddProperty("binary.type", e.getELFType(elfFile.Type))
	components = append(components, mainComponent)

	// Extract dynamic dependencies
	deps, err := e.extractELFDependencies(elfFile)
	if err == nil {
		for _, dep := range deps {
			depComponent := NewComponent(ComponentTypeLibrary, dep, "unknown")
			depComponent.Description = "Dynamic library dependency"
			depComponent.Scope = ScopeRequired
			depComponent.AddProperty("dependency.type", "dynamic")
			depComponent.AddProperty("source.binary", "ELF")
			components = append(components, depComponent)

			// Add dependency relationship
			mainComponent.AddDependency(depComponent.BOMRef)
		}
	}

	// Extract symbols and create library components
	symbols, err := e.extractELFSymbols(elfFile)
	if err == nil {
		libraryComponents := e.inferLibrariesFromSymbols(symbols)
		for _, libComp := range libraryComponents {
			libComp.AddProperty("source.binary", "ELF")
			components = append(components, libComp)
			mainComponent.AddDependency(libComp.BOMRef)
		}
	}

	return components, nil
}

// extractPEComponents extracts components from PE binaries
func (e *BinaryComponentExtractor) extractPEComponents(binaryPath string) ([]Component, error) {
	var components []Component

	peFile, err := pe.Open(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open PE file: %w", err)
	}
	defer peFile.Close()

	// Create main application component
	mainComponent := NewComponent(ComponentTypeApplication, filepath.Base(binaryPath), "1.0.0")
	mainComponent.Description = fmt.Sprintf("PE binary (%s)", e.getPEMachine(peFile.Machine))
	mainComponent.AddProperty("binary.format", "PE")
	mainComponent.AddProperty("binary.machine", e.getPEMachine(peFile.Machine))
	mainComponent.AddProperty("binary.characteristics", fmt.Sprintf("0x%x", peFile.Characteristics))
	components = append(components, mainComponent)

	// Extract imported libraries
	imports, err := peFile.ImportedLibraries()
	if err == nil {
		for _, imp := range imports {
			impComponent := NewComponent(ComponentTypeLibrary, imp, "unknown")
			impComponent.Description = "Imported library"
			impComponent.Scope = ScopeRequired
			impComponent.AddProperty("dependency.type", "import")
			impComponent.AddProperty("source.binary", "PE")
			components = append(components, impComponent)

			// Add dependency relationship
			mainComponent.AddDependency(impComponent.BOMRef)
		}
	}

	// Extract imported symbols
	symbols, err := peFile.ImportedSymbols()
	if err == nil {
		libraryComponents := e.inferLibrariesFromSymbols(symbols)
		for _, libComp := range libraryComponents {
			libComp.AddProperty("source.binary", "PE")
			components = append(components, libComp)
			mainComponent.AddDependency(libComp.BOMRef)
		}
	}

	return components, nil
}

// extractMachOComponents extracts components from Mach-O binaries
func (e *BinaryComponentExtractor) extractMachOComponents(binaryPath string) ([]Component, error) {
	var components []Component

	machoFile, err := macho.Open(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open Mach-O file: %w", err)
	}
	defer machoFile.Close()

	// Create main application component
	mainComponent := NewComponent(ComponentTypeApplication, filepath.Base(binaryPath), "1.0.0")
	mainComponent.Description = fmt.Sprintf("Mach-O binary (%s)", e.getMachOCPU(machoFile.Cpu))
	mainComponent.AddProperty("binary.format", "Mach-O")
	mainComponent.AddProperty("binary.cpu", e.getMachOCPU(machoFile.Cpu))
	mainComponent.AddProperty("binary.subcpu", fmt.Sprintf("0x%x", machoFile.SubCpu))
	mainComponent.AddProperty("binary.type", e.getMachOType(machoFile.Type))
	components = append(components, mainComponent)

	// Extract dynamic libraries from load commands
	deps, err := e.extractMachODependencies(machoFile)
	if err == nil {
		for _, dep := range deps {
			depComponent := NewComponent(ComponentTypeLibrary, dep, "unknown")
			depComponent.Description = "Dynamic library dependency"
			depComponent.Scope = ScopeRequired
			depComponent.AddProperty("dependency.type", "dynamic")
			depComponent.AddProperty("source.binary", "Mach-O")
			components = append(components, depComponent)

			// Add dependency relationship
			mainComponent.AddDependency(depComponent.BOMRef)
		}
	}

	// Extract symbols
	if machoFile.Symtab != nil {
		symbols := make([]string, len(machoFile.Symtab.Syms))
		for i, sym := range machoFile.Symtab.Syms {
			symbols[i] = sym.Name
		}

		libraryComponents := e.inferLibrariesFromSymbols(symbols)
		for _, libComp := range libraryComponents {
			libComp.AddProperty("source.binary", "Mach-O")
			components = append(components, libComp)
			mainComponent.AddDependency(libComp.BOMRef)
		}
	}

	return components, nil
}

// createBasicComponent creates a basic component for unknown binary formats
func (e *BinaryComponentExtractor) createBasicComponent(binaryPath string) Component {
	component := NewComponent(ComponentTypeApplication, filepath.Base(binaryPath), "unknown")
	component.Description = "Binary application (unknown format)"
	component.AddProperty("binary.format", "unknown")
	component.AddProperty("binary.path", binaryPath)

	// Get file size
	if fileInfo, err := os.Stat(binaryPath); err == nil {
		component.AddProperty("binary.size", fmt.Sprintf("%d", fileInfo.Size()))
	}

	return component
}

// extractEmbeddedComponents extracts components from embedded strings and patterns
func (e *BinaryComponentExtractor) extractEmbeddedComponents(binaryPath string) ([]Component, error) {
	var components []Component

	// Read file content
	content, err := os.ReadFile(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read binary file: %w", err)
	}

	contentStr := string(content)

	// Extract Go modules
	goModules := e.extractGoModules(contentStr)
	for _, module := range goModules {
		component := NewComponent(ComponentTypeLibrary, module.Name, module.Version)
		component.Description = "Go module"
		component.AddProperty("language", "go")
		component.AddProperty("module.path", module.Path)
		components = append(components, component)
	}

	// Extract Rust crates
	rustCrates := e.extractRustCrates(contentStr)
	for _, crate := range rustCrates {
		component := NewComponent(ComponentTypeLibrary, crate.Name, crate.Version)
		component.Description = "Rust crate"
		component.AddProperty("language", "rust")
		components = append(components, component)
	}

	// Extract Node.js packages
	nodePackages := e.extractNodePackages(contentStr)
	for _, pkg := range nodePackages {
		component := NewComponent(ComponentTypeLibrary, pkg.Name, pkg.Version)
		component.Description = "Node.js package"
		component.AddProperty("language", "javascript")
		components = append(components, component)
	}

	// Extract Python packages
	pythonPackages := e.extractPythonPackages(contentStr)
	for _, pkg := range pythonPackages {
		component := NewComponent(ComponentTypeLibrary, pkg.Name, pkg.Version)
		component.Description = "Python package"
		component.AddProperty("language", "python")
		components = append(components, component)
	}

	return components, nil
}

// ModuleInfo represents information about a module/package
type ModuleInfo struct {
	Name    string
	Version string
	Path    string
}

// extractGoModules extracts Go module information from binary strings
func (e *BinaryComponentExtractor) extractGoModules(content string) []ModuleInfo {
	var modules []ModuleInfo

	// Go module pattern: module_name@version
	goModulePattern := regexp.MustCompile(`([a-zA-Z0-9\-_.]+/[a-zA-Z0-9\-_./]+)@v([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9\-_.]+)?)`)
	matches := goModulePattern.FindAllStringSubmatch(content, -1)

	seen := make(map[string]bool)
	for _, match := range matches {
		if len(match) >= 3 {
			modulePath := match[1]
			version := match[2]
			
			// Extract module name from path
			parts := strings.Split(modulePath, "/")
			moduleName := parts[len(parts)-1]
			
			key := moduleName + "@" + version
			if !seen[key] {
				seen[key] = true
				modules = append(modules, ModuleInfo{
					Name:    moduleName,
					Version: version,
					Path:    modulePath,
				})
			}
		}
	}

	return modules
}

// extractRustCrates extracts Rust crate information from binary strings
func (e *BinaryComponentExtractor) extractRustCrates(content string) []ModuleInfo {
	var crates []ModuleInfo

	// Rust crate pattern: crate-name-version
	rustCratePattern := regexp.MustCompile(`([a-zA-Z0-9\-_]+)-([0-9]+\.[0-9]+\.[0-9]+)`)
	matches := rustCratePattern.FindAllStringSubmatch(content, -1)

	seen := make(map[string]bool)
	for _, match := range matches {
		if len(match) >= 3 {
			crateName := match[1]
			version := match[2]
			
			// Filter out common false positives
			if e.isValidRustCrateName(crateName) {
				key := crateName + "@" + version
				if !seen[key] {
					seen[key] = true
					crates = append(crates, ModuleInfo{
						Name:    crateName,
						Version: version,
					})
				}
			}
		}
	}

	return crates
}

// extractNodePackages extracts Node.js package information from binary strings
func (e *BinaryComponentExtractor) extractNodePackages(content string) []ModuleInfo {
	var packages []ModuleInfo

	// Node.js package pattern: package@version
	nodePackagePattern := regexp.MustCompile(`([a-zA-Z0-9\-_.@/]+)@([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9\-_.]+)?)`)
	matches := nodePackagePattern.FindAllStringSubmatch(content, -1)

	seen := make(map[string]bool)
	for _, match := range matches {
		if len(match) >= 3 {
			packageName := match[1]
			version := match[2]
			
			// Filter out common false positives
			if e.isValidNodePackageName(packageName) {
				key := packageName + "@" + version
				if !seen[key] {
					seen[key] = true
					packages = append(packages, ModuleInfo{
						Name:    packageName,
						Version: version,
					})
				}
			}
		}
	}

	return packages
}

// extractPythonPackages extracts Python package information from binary strings
func (e *BinaryComponentExtractor) extractPythonPackages(content string) []ModuleInfo {
	var packages []ModuleInfo

	// Python package pattern: package==version or package-version
	pythonPackagePattern := regexp.MustCompile(`([a-zA-Z0-9\-_.]+)(?:==|-)([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[a-zA-Z0-9\-_.]+)?)`)
	matches := pythonPackagePattern.FindAllStringSubmatch(content, -1)

	seen := make(map[string]bool)
	for _, match := range matches {
		if len(match) >= 3 {
			packageName := match[1]
			version := match[2]
			
			// Filter out common false positives
			if e.isValidPythonPackageName(packageName) {
				key := packageName + "@" + version
				if !seen[key] {
					seen[key] = true
					packages = append(packages, ModuleInfo{
						Name:    packageName,
						Version: version,
					})
				}
			}
		}
	}

	return packages
}

// Helper functions for binary format parsing

func (e *BinaryComponentExtractor) getELFClass(class elf.Class) string {
	switch class {
	case elf.ELFCLASS32:
		return "32-bit"
	case elf.ELFCLASS64:
		return "64-bit"
	default:
		return "unknown"
	}
}

func (e *BinaryComponentExtractor) getELFData(data elf.Data) string {
	switch data {
	case elf.ELFDATA2LSB:
		return "little-endian"
	case elf.ELFDATA2MSB:
		return "big-endian"
	default:
		return "unknown"
	}
}

func (e *BinaryComponentExtractor) getELFType(elfType elf.Type) string {
	switch elfType {
	case elf.ET_EXEC:
		return "executable"
	case elf.ET_DYN:
		return "shared-object"
	case elf.ET_REL:
		return "relocatable"
	case elf.ET_CORE:
		return "core-dump"
	default:
		return "unknown"
	}
}

func (e *BinaryComponentExtractor) getPEMachine(machine uint16) string {
	switch machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		return "i386"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64"
	case pe.IMAGE_FILE_MACHINE_ARM:
		return "arm"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	default:
		return fmt.Sprintf("unknown(0x%x)", machine)
	}
}

func (e *BinaryComponentExtractor) getMachOCPU(cpu macho.Cpu) string {
	switch cpu {
	case macho.Cpu386:
		return "i386"
	case macho.CpuAmd64:
		return "amd64"
	case macho.CpuArm:
		return "arm"
	case macho.CpuArm64:
		return "arm64"
	default:
		return fmt.Sprintf("unknown(0x%x)", cpu)
	}
}

func (e *BinaryComponentExtractor) getMachOType(fileType macho.Type) string {
	switch fileType {
	case macho.TypeExec:
		return "executable"
	case macho.TypeDylib:
		return "dynamic-library"
	case macho.TypeBundle:
		return "bundle"
	default:
		return "unknown"
	}
}

// Validation functions for package names

func (e *BinaryComponentExtractor) isValidRustCrateName(name string) bool {
	// Filter out common false positives
	invalidNames := []string{"lib", "std", "core", "alloc", "test", "main", "src", "target"}
	for _, invalid := range invalidNames {
		if name == invalid {
			return false
		}
	}
	return len(name) > 2 && len(name) < 50
}

func (e *BinaryComponentExtractor) isValidNodePackageName(name string) bool {
	// Filter out common false positives
	if strings.Contains(name, "..") || strings.HasPrefix(name, ".") {
		return false
	}
	return len(name) > 1 && len(name) < 100
}

func (e *BinaryComponentExtractor) isValidPythonPackageName(name string) bool {
	// Filter out common false positives
	invalidNames := []string{"lib", "src", "test", "main", "bin", "usr", "var", "tmp"}
	for _, invalid := range invalidNames {
		if name == invalid {
			return false
		}
	}
	return len(name) > 2 && len(name) < 50
}

// Additional helper functions (simplified implementations)

func (e *BinaryComponentExtractor) extractELFDependencies(elfFile *elf.File) ([]string, error) {
	// This is a simplified implementation
	// Real implementation would parse the dynamic section properly
	var deps []string
	
	// Try to get imported libraries using the ImportedLibraries method if available
	// Note: This method doesn't exist in the standard library, so we'll simulate it
	
	return deps, nil
}

func (e *BinaryComponentExtractor) extractELFSymbols(elfFile *elf.File) ([]string, error) {
	symbols, err := elfFile.Symbols()
	if err != nil {
		return nil, err
	}
	
	var symbolNames []string
	for _, sym := range symbols {
		if sym.Name != "" {
			symbolNames = append(symbolNames, sym.Name)
		}
	}
	
	return symbolNames, nil
}

func (e *BinaryComponentExtractor) extractMachODependencies(machoFile *macho.File) ([]string, error) {
	var deps []string
	
	for _, load := range machoFile.Loads {
		if dylib, ok := load.(*macho.Dylib); ok {
			deps = append(deps, dylib.Name)
		}
	}
	
	return deps, nil
}

func (e *BinaryComponentExtractor) inferLibrariesFromSymbols(symbols []string) []Component {
	var components []Component
	
	// This is a simplified implementation that infers libraries from symbol prefixes
	libraryPrefixes := map[string]string{
		"ssl_":     "openssl",
		"SSL_":     "openssl",
		"crypto_":  "libcrypto",
		"CRYPTO_":  "libcrypto",
		"z_":       "zlib",
		"deflate":  "zlib",
		"inflate":  "zlib",
		"curl_":    "libcurl",
		"sqlite3_": "sqlite3",
		"json_":    "json-c",
		"xml":      "libxml2",
		"pthread_": "pthread",
	}
	
	found := make(map[string]bool)
	
	for _, symbol := range symbols {
		for prefix, library := range libraryPrefixes {
			if strings.HasPrefix(symbol, prefix) && !found[library] {
				found[library] = true
				component := NewComponent(ComponentTypeLibrary, library, "unknown")
				component.Description = fmt.Sprintf("Inferred from symbols (prefix: %s)", prefix)
				component.Scope = ScopeRequired
				component.AddProperty("inference.method", "symbol-prefix")
				component.AddProperty("inference.symbol", symbol)
				components = append(components, component)
			}
		}
	}
	
	return components
}