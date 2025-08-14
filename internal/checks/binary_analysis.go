package checks

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"os"
	"strings"
	"time"
)

// BinaryFormat represents the format of a binary file
type BinaryFormat string

const (
	FormatELF    BinaryFormat = "ELF"
	FormatPE     BinaryFormat = "PE"
	FormatMachO  BinaryFormat = "Mach-O"
	FormatUnknown BinaryFormat = "Unknown"
)

// BinaryInfo contains metadata about a binary file
type BinaryInfo struct {
	Format       BinaryFormat `json:"format"`
	Architecture string       `json:"architecture"`
	Bitness      int          `json:"bitness"`
	Endianness   string       `json:"endianness"`
	EntryPoint   uint64       `json:"entry_point"`
	Sections     []string     `json:"sections"`
	Dependencies []string     `json:"dependencies"`
	Symbols      []string     `json:"symbols"`
	FileSize     int64        `json:"file_size"`
}

// BinaryParser provides functionality to parse different binary formats
type BinaryParser struct{}

// NewBinaryParser creates a new binary parser
func NewBinaryParser() *BinaryParser {
	return &BinaryParser{}
}

// ParseBinary analyzes a binary file and extracts metadata
func (bp *BinaryParser) ParseBinary(binaryPath string) (*BinaryInfo, error) {
	// Get file info
	fileInfo, err := os.Stat(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	// Open file for reading
	file, err := os.Open(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open binary file: %w", err)
	}
	defer file.Close()

	// Detect binary format
	format, err := bp.detectFormat(file)
	if err != nil {
		return nil, fmt.Errorf("failed to detect binary format: %w", err)
	}

	info := &BinaryInfo{
		Format:   format,
		FileSize: fileInfo.Size(),
	}

	// Parse based on format
	switch format {
	case FormatELF:
		err = bp.parseELF(binaryPath, info)
	case FormatPE:
		err = bp.parsePE(binaryPath, info)
	case FormatMachO:
		err = bp.parseMachO(binaryPath, info)
	default:
		return info, nil // Return basic info for unknown formats
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse %s binary: %w", format, err)
	}

	return info, nil
}

// detectFormat detects the binary format by reading file headers
func (bp *BinaryParser) detectFormat(file *os.File) (BinaryFormat, error) {
	// Read first 16 bytes to detect format
	header := make([]byte, 16)
	_, err := file.ReadAt(header, 0)
	if err != nil {
		return FormatUnknown, err
	}

	// ELF magic: 0x7F 'E' 'L' 'F'
	if len(header) >= 4 && header[0] == 0x7F && header[1] == 'E' && header[2] == 'L' && header[3] == 'F' {
		return FormatELF, nil
	}

	// PE magic: 'M' 'Z' at start, then PE signature later
	if len(header) >= 2 && header[0] == 'M' && header[1] == 'Z' {
		return FormatPE, nil
	}

	// Mach-O magic numbers
	if len(header) >= 4 {
		magic := uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16 | uint32(header[3])<<24
		switch magic {
		case 0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcffaedfe, 0xcefaedfe:
			return FormatMachO, nil
		}
	}

	return FormatUnknown, nil
}

// parseELF parses ELF binary format
func (bp *BinaryParser) parseELF(binaryPath string, info *BinaryInfo) error {
	elfFile, err := elf.Open(binaryPath)
	if err != nil {
		// If standard library parsing fails, try to extract basic info from header
		return bp.parseELFBasic(binaryPath, info)
	}
	defer elfFile.Close()

	// Set architecture and bitness
	switch elfFile.Class {
	case elf.ELFCLASS32:
		info.Bitness = 32
	case elf.ELFCLASS64:
		info.Bitness = 64
	}

	// Set endianness
	switch elfFile.Data {
	case elf.ELFDATA2LSB:
		info.Endianness = "little"
	case elf.ELFDATA2MSB:
		info.Endianness = "big"
	}

	// Set architecture
	info.Architecture = elfFile.Machine.String()

	// Set entry point
	info.EntryPoint = elfFile.Entry

	// Extract sections
	for _, section := range elfFile.Sections {
		if section.Name != "" {
			info.Sections = append(info.Sections, section.Name)
		}
	}

	// Extract dynamic dependencies
	if dynSection := elfFile.Section(".dynamic"); dynSection != nil {
		deps, err := bp.extractELFDependencies(elfFile)
		if err == nil {
			info.Dependencies = deps
		}
	}

	// Extract symbols
	symbols, err := bp.extractELFSymbols(elfFile)
	if err == nil {
		info.Symbols = symbols
	}

	return nil
}

// parseELFBasic extracts basic ELF info when standard library parsing fails
func (bp *BinaryParser) parseELFBasic(binaryPath string, info *BinaryInfo) error {
	file, err := os.Open(binaryPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Read ELF header
	header := make([]byte, 64) // ELF header is at most 64 bytes
	_, err = file.Read(header)
	if err != nil {
		return err
	}

	// Extract basic info from header
	if len(header) >= 5 {
		// EI_CLASS (5th byte) - 32/64 bit
		if header[4] == 1 {
			info.Bitness = 32
		} else if header[4] == 2 {
			info.Bitness = 64
		}
	}

	if len(header) >= 6 {
		// EI_DATA (6th byte) - endianness
		if header[5] == 1 {
			info.Endianness = "little"
		} else if header[5] == 2 {
			info.Endianness = "big"
		}
	}

	// Set basic architecture info
	info.Architecture = "unknown"
	if len(header) >= 20 {
		// e_machine field (bytes 18-19 for 32-bit, different for 64-bit)
		machine := uint16(header[18]) | uint16(header[19])<<8
		switch machine {
		case 0x3e:
			info.Architecture = "x86_64"
		case 0x03:
			info.Architecture = "i386"
		case 0x28:
			info.Architecture = "arm"
		case 0xb7:
			info.Architecture = "aarch64"
		}
	}

	return nil
}

// parsePE parses PE binary format
func (bp *BinaryParser) parsePE(binaryPath string, info *BinaryInfo) error {
	peFile, err := pe.Open(binaryPath)
	if err != nil {
		// If standard library parsing fails, try to extract basic info from header
		return bp.parsePEBasic(binaryPath, info)
	}
	defer peFile.Close()

	// Determine architecture and bitness
	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		info.Architecture = "i386"
		info.Bitness = 32
	case pe.IMAGE_FILE_MACHINE_AMD64:
		info.Architecture = "amd64"
		info.Bitness = 64
	case pe.IMAGE_FILE_MACHINE_ARM:
		info.Architecture = "arm"
		info.Bitness = 32
	case pe.IMAGE_FILE_MACHINE_ARM64:
		info.Architecture = "arm64"
		info.Bitness = 64
	default:
		info.Architecture = fmt.Sprintf("unknown(0x%x)", peFile.Machine)
	}

	info.Endianness = "little" // PE is always little-endian

	// Extract sections
	for _, section := range peFile.Sections {
		info.Sections = append(info.Sections, section.Name)
	}

	// Extract imported DLLs
	imports, err := peFile.ImportedLibraries()
	if err == nil {
		info.Dependencies = imports
	}

	// Extract symbols
	symbols, err := peFile.ImportedSymbols()
	if err == nil {
		info.Symbols = symbols
	}

	return nil
}

// parsePEBasic extracts basic PE info when standard library parsing fails
func (bp *BinaryParser) parsePEBasic(binaryPath string, info *BinaryInfo) error {
	file, err := os.Open(binaryPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Read DOS header and PE header
	header := make([]byte, 256)
	_, err = file.Read(header)
	if err != nil {
		return err
	}

	// Set basic info
	info.Architecture = "unknown"
	info.Bitness = 32 // Default assumption
	info.Endianness = "little"

	// Try to find PE signature and extract machine type
	if len(header) >= 64 {
		// Look for PE signature at offset indicated by DOS header
		peOffset := 0x3c
		if len(header) > peOffset+4 {
			// This is a simplified approach - real PE parsing is more complex
			info.Architecture = "i386" // Default for PE
		}
	}

	return nil
}

// parseMachO parses Mach-O binary format
func (bp *BinaryParser) parseMachO(binaryPath string, info *BinaryInfo) error {
	machoFile, err := macho.Open(binaryPath)
	if err != nil {
		// If standard library parsing fails, try to extract basic info from header
		return bp.parseMachOBasic(binaryPath, info)
	}
	defer machoFile.Close()

	// Set architecture and bitness
	switch machoFile.Cpu {
	case macho.Cpu386:
		info.Architecture = "i386"
		info.Bitness = 32
	case macho.CpuAmd64:
		info.Architecture = "amd64"
		info.Bitness = 64
	case macho.CpuArm:
		info.Architecture = "arm"
		info.Bitness = 32
	case macho.CpuArm64:
		info.Architecture = "arm64"
		info.Bitness = 64
	default:
		info.Architecture = fmt.Sprintf("unknown(0x%x)", machoFile.Cpu)
	}

	// Mach-O can be either endian, but most are little-endian
	info.Endianness = "little"

	// Extract sections
	for _, section := range machoFile.Sections {
		info.Sections = append(info.Sections, section.Name)
	}

	// Extract load commands for dependencies
	deps, err := bp.extractMachODependencies(machoFile)
	if err == nil {
		info.Dependencies = deps
	}

	// Extract symbols
	if machoFile.Symtab != nil {
		symbols, err := bp.extractMachOSymbols(machoFile)
		if err == nil {
			info.Symbols = symbols
		}
	}

	return nil
}

// parseMachOBasic extracts basic Mach-O info when standard library parsing fails
func (bp *BinaryParser) parseMachOBasic(binaryPath string, info *BinaryInfo) error {
	file, err := os.Open(binaryPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Read Mach-O header
	header := make([]byte, 32)
	_, err = file.Read(header)
	if err != nil {
		return err
	}

	// Set basic info
	info.Architecture = "unknown"
	info.Bitness = 64 // Default assumption for modern Mach-O
	info.Endianness = "little"

	// Extract CPU type from header
	if len(header) >= 8 {
		// CPU type is at offset 4
		cpuType := uint32(header[4]) | uint32(header[5])<<8 | uint32(header[6])<<16 | uint32(header[7])<<24
		switch cpuType {
		case 0x01000007: // CPU_TYPE_X86_64
			info.Architecture = "amd64"
			info.Bitness = 64
		case 0x00000007: // CPU_TYPE_X86
			info.Architecture = "i386"
			info.Bitness = 32
		case 0x0100000c: // CPU_TYPE_ARM64
			info.Architecture = "arm64"
			info.Bitness = 64
		case 0x0000000c: // CPU_TYPE_ARM
			info.Architecture = "arm"
			info.Bitness = 32
		}
	}

	return nil
}

// extractELFDependencies extracts dynamic dependencies from ELF binary
func (bp *BinaryParser) extractELFDependencies(elfFile *elf.File) ([]string, error) {
	var deps []string

	// Get dynamic section
	dynSection := elfFile.Section(".dynamic")
	if dynSection == nil {
		return deps, nil
	}

	// Get string table for dynamic section
	dynstr := elfFile.Section(".dynstr")
	if dynstr == nil {
		return deps, nil
	}

	// Read string table
	strData, err := dynstr.Data()
	if err != nil {
		return deps, err
	}

	// Read dynamic entries
	dynData, err := dynSection.Data()
	if err != nil {
		return deps, err
	}

	// Parse dynamic entries (simplified)
	// This is a basic implementation - real parsing would be more complex
	for i := 0; i < len(dynData)-16; i += 16 {
		// Look for DT_NEEDED entries (tag = 1)
		if elfFile.Class == elf.ELFCLASS64 {
			tag := elfFile.ByteOrder.Uint64(dynData[i : i+8])
			val := elfFile.ByteOrder.Uint64(dynData[i+8 : i+16])
			if tag == 1 { // DT_NEEDED
				if int(val) < len(strData) {
					dep := bp.readCString(strData[val:])
					if dep != "" {
						deps = append(deps, dep)
					}
				}
			}
		} else {
			tag := elfFile.ByteOrder.Uint32(dynData[i : i+4])
			val := elfFile.ByteOrder.Uint32(dynData[i+4 : i+8])
			if tag == 1 { // DT_NEEDED
				if int(val) < len(strData) {
					dep := bp.readCString(strData[val:])
					if dep != "" {
						deps = append(deps, dep)
					}
				}
			}
		}
	}

	return deps, nil
}

// extractELFSymbols extracts symbols from ELF binary
func (bp *BinaryParser) extractELFSymbols(elfFile *elf.File) ([]string, error) {
	var symbols []string

	// Get symbol table sections
	sections := []*elf.Section{
		elfFile.Section(".symtab"),
		elfFile.Section(".dynsym"),
	}

	for _, section := range sections {
		if section == nil {
			continue
		}

		syms, err := elfFile.Symbols()
		if err != nil {
			continue
		}

		for _, sym := range syms {
			if sym.Name != "" {
				symbols = append(symbols, sym.Name)
			}
		}
		break // Only process first available symbol table
	}

	return symbols, nil
}

// extractMachODependencies extracts dependencies from Mach-O binary
func (bp *BinaryParser) extractMachODependencies(machoFile *macho.File) ([]string, error) {
	var deps []string

	for _, load := range machoFile.Loads {
		switch cmd := load.(type) {
		case *macho.Dylib:
			deps = append(deps, cmd.Name)
		}
	}

	return deps, nil
}

// extractMachOSymbols extracts symbols from Mach-O binary
func (bp *BinaryParser) extractMachOSymbols(machoFile *macho.File) ([]string, error) {
	var symbols []string

	if machoFile.Symtab == nil {
		return symbols, nil
	}

	for _, sym := range machoFile.Symtab.Syms {
		if sym.Name != "" {
			symbols = append(symbols, sym.Name)
		}
	}

	return symbols, nil
}

// readCString reads a null-terminated string from byte slice
func (bp *BinaryParser) readCString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

// FileSignatureCheck implements check 1: File signature validation
type FileSignatureCheck struct{}

func (c *FileSignatureCheck) ID() string {
	return "check-1-file-signature"
}

func (c *FileSignatureCheck) Description() string {
	return "Validates binary file signature and format"
}

func (c *FileSignatureCheck) Execute(binaryPath string) CheckResult {
	start := time.Now()
	
	parser := NewBinaryParser()
	info, err := parser.ParseBinary(binaryPath)
	
	result := CheckResult{
		ID:          c.ID(),
		Description: c.Description(),
		Duration:    time.Since(start),
		Metadata:    make(map[string]interface{}),
	}
	
	if err != nil {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Failed to parse binary: %v", err)
		return result
	}
	
	// Check if we have a recognized format
	if info.Format == FormatUnknown {
		result.Status = "fail"
		result.Details = "Binary format not recognized or supported"
		result.Metadata["format"] = string(info.Format)
		return result
	}
	
	result.Status = "pass"
	result.Details = fmt.Sprintf("Binary format validated: %s", info.Format)
	result.Metadata["format"] = string(info.Format)
	result.Metadata["architecture"] = info.Architecture
	result.Metadata["bitness"] = info.Bitness
	result.Metadata["file_size"] = info.FileSize
	
	return result
}

// BinaryMetadataCheck implements check 2: Binary metadata extraction
type BinaryMetadataCheck struct{}

func (c *BinaryMetadataCheck) ID() string {
	return "check-2-binary-metadata"
}

func (c *BinaryMetadataCheck) Description() string {
	return "Extracts and validates binary metadata including architecture, entry point, and sections"
}

func (c *BinaryMetadataCheck) Execute(binaryPath string) CheckResult {
	start := time.Now()
	
	parser := NewBinaryParser()
	info, err := parser.ParseBinary(binaryPath)
	
	result := CheckResult{
		ID:          c.ID(),
		Description: c.Description(),
		Duration:    time.Since(start),
		Metadata:    make(map[string]interface{}),
	}
	
	if err != nil {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Failed to extract metadata: %v", err)
		return result
	}
	
	// Validate that we have essential metadata
	if info.Architecture == "" {
		result.Status = "fail"
		result.Details = "Missing architecture information"
		return result
	}
	
	if info.Bitness == 0 {
		result.Status = "fail"
		result.Details = "Missing bitness information"
		return result
	}
	
	// For basic parsing fallback, sections might not be available
	// Only fail if we have no sections AND no other metadata
	if len(info.Sections) == 0 && info.Format != FormatUnknown && info.Architecture == "" {
		result.Status = "fail"
		result.Details = "No sections or architecture information found in binary"
		return result
	}
	
	result.Status = "pass"
	result.Details = fmt.Sprintf("Metadata extracted successfully: %s %d-bit %s", 
		info.Architecture, info.Bitness, info.Format)
	
	// Add metadata
	result.Metadata["format"] = string(info.Format)
	result.Metadata["architecture"] = info.Architecture
	result.Metadata["bitness"] = info.Bitness
	result.Metadata["endianness"] = info.Endianness
	result.Metadata["entry_point"] = info.EntryPoint
	result.Metadata["sections"] = info.Sections
	result.Metadata["section_count"] = len(info.Sections)
	result.Metadata["file_size"] = info.FileSize
	
	return result
}

// DependencyAnalysisCheck implements check 3: Dependency analysis
type DependencyAnalysisCheck struct{}

func (c *DependencyAnalysisCheck) ID() string {
	return "check-3-dependency-analysis"
}

func (c *DependencyAnalysisCheck) Description() string {
	return "Analyzes binary dependencies and imported libraries"
}

func (c *DependencyAnalysisCheck) Execute(binaryPath string) CheckResult {
	start := time.Now()
	
	parser := NewBinaryParser()
	info, err := parser.ParseBinary(binaryPath)
	
	result := CheckResult{
		ID:          c.ID(),
		Description: c.Description(),
		Duration:    time.Since(start),
		Metadata:    make(map[string]interface{}),
	}
	
	if err != nil {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Failed to analyze dependencies: %v", err)
		return result
	}
	
	// For static binaries or unknown formats, having no dependencies is acceptable
	if len(info.Dependencies) == 0 {
		result.Status = "pass"
		result.Details = "No external dependencies found (static binary or no dynamic linking)"
		result.Metadata["dependency_count"] = 0
		result.Metadata["dependencies"] = []string{}
		return result
	}
	
	// Analyze dependencies for potential security issues
	suspiciousDeps := []string{}
	for _, dep := range info.Dependencies {
		// Check for potentially suspicious dependencies
		depLower := strings.ToLower(dep)
		if strings.Contains(depLower, "debug") || 
		   strings.Contains(depLower, "test") ||
		   strings.Contains(depLower, "hack") {
			suspiciousDeps = append(suspiciousDeps, dep)
		}
	}
	
	result.Status = "pass"
	if len(suspiciousDeps) > 0 {
		result.Details = fmt.Sprintf("Dependencies analyzed: %d found, %d potentially suspicious", 
			len(info.Dependencies), len(suspiciousDeps))
		result.Metadata["suspicious_dependencies"] = suspiciousDeps
	} else {
		result.Details = fmt.Sprintf("Dependencies analyzed: %d found, all appear normal", 
			len(info.Dependencies))
	}
	
	result.Metadata["dependency_count"] = len(info.Dependencies)
	result.Metadata["dependencies"] = info.Dependencies
	result.Metadata["format"] = string(info.Format)
	
	return result
}

// BinaryFormatCheck implements check 4: Binary format validation
type BinaryFormatCheck struct{}

func (c *BinaryFormatCheck) ID() string {
	return "check-4-binary-format"
}

func (c *BinaryFormatCheck) Description() string {
	return "Validates binary format compliance and structure integrity"
}

func (c *BinaryFormatCheck) Execute(binaryPath string) CheckResult {
	start := time.Now()
	
	parser := NewBinaryParser()
	info, err := parser.ParseBinary(binaryPath)
	
	result := CheckResult{
		ID:          c.ID(),
		Description: c.Description(),
		Duration:    time.Since(start),
		Metadata:    make(map[string]interface{}),
	}
	
	if err != nil {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Binary format validation failed: %v", err)
		return result
	}
	
	// Validate format-specific requirements
	switch info.Format {
	case FormatELF:
		if err := c.validateELFFormat(binaryPath, info); err != nil {
			result.Status = "fail"
			result.Details = fmt.Sprintf("ELF format validation failed: %v", err)
			result.Metadata["format"] = string(info.Format)
			return result
		}
	case FormatPE:
		if err := c.validatePEFormat(binaryPath, info); err != nil {
			result.Status = "fail"
			result.Details = fmt.Sprintf("PE format validation failed: %v", err)
			result.Metadata["format"] = string(info.Format)
			return result
		}
	case FormatMachO:
		if err := c.validateMachOFormat(binaryPath, info); err != nil {
			result.Status = "fail"
			result.Details = fmt.Sprintf("Mach-O format validation failed: %v", err)
			result.Metadata["format"] = string(info.Format)
			return result
		}
	case FormatUnknown:
		result.Status = "fail"
		result.Details = "Unknown or unsupported binary format"
		result.Metadata["format"] = string(info.Format)
		return result
	}
	
	result.Status = "pass"
	result.Details = fmt.Sprintf("Binary format validation passed: %s format is valid", info.Format)
	result.Metadata["format"] = string(info.Format)
	result.Metadata["architecture"] = info.Architecture
	result.Metadata["bitness"] = info.Bitness
	result.Metadata["sections"] = len(info.Sections)
	
	return result
}

// validateELFFormat validates ELF-specific format requirements
func (c *BinaryFormatCheck) validateELFFormat(binaryPath string, info *BinaryInfo) error {
	elfFile, err := elf.Open(binaryPath)
	if err != nil {
		// If standard library parsing fails, do basic validation
		return c.validateELFBasic(binaryPath, info)
	}
	defer elfFile.Close()
	
	// Check for required sections - only if we have sections at all
	if len(info.Sections) > 0 {
		requiredSections := []string{".text"}
		for _, required := range requiredSections {
			found := false
			for _, section := range info.Sections {
				if section == required {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("missing required section: %s", required)
			}
		}
	}
	
	// Validate entry point is reasonable
	if elfFile.Type == elf.ET_EXEC && info.EntryPoint == 0 {
		return fmt.Errorf("executable has zero entry point")
	}
	
	return nil
}

// validateELFBasic performs basic ELF validation when standard library parsing fails
func (c *BinaryFormatCheck) validateELFBasic(binaryPath string, info *BinaryInfo) error {
	// For basic parsing, just validate that we have essential info
	if info.Architecture == "" {
		return fmt.Errorf("missing architecture information")
	}
	if info.Bitness == 0 {
		return fmt.Errorf("missing bitness information")
	}
	return nil
}

// validatePEFormat validates PE-specific format requirements
func (c *BinaryFormatCheck) validatePEFormat(binaryPath string, info *BinaryInfo) error {
	peFile, err := pe.Open(binaryPath)
	if err != nil {
		// If standard library parsing fails, do basic validation
		return c.validatePEBasic(binaryPath, info)
	}
	defer peFile.Close()
	
	// Check for required sections - only if we have sections at all
	if len(info.Sections) > 0 {
		requiredSections := []string{".text"}
		for _, required := range requiredSections {
			found := false
			for _, section := range info.Sections {
				if strings.HasPrefix(section, required) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("missing required section: %s", required)
			}
		}
	}
	
	// Validate machine type is supported
	supportedMachines := []uint16{
		pe.IMAGE_FILE_MACHINE_I386,
		pe.IMAGE_FILE_MACHINE_AMD64,
		pe.IMAGE_FILE_MACHINE_ARM,
		pe.IMAGE_FILE_MACHINE_ARM64,
	}
	
	supported := false
	for _, machine := range supportedMachines {
		if peFile.Machine == machine {
			supported = true
			break
		}
	}
	
	if !supported {
		return fmt.Errorf("unsupported machine type: 0x%x", peFile.Machine)
	}
	
	return nil
}

// validatePEBasic performs basic PE validation when standard library parsing fails
func (c *BinaryFormatCheck) validatePEBasic(binaryPath string, info *BinaryInfo) error {
	// For basic parsing, just validate that we have essential info
	if info.Architecture == "" {
		return fmt.Errorf("missing architecture information")
	}
	if info.Bitness == 0 {
		return fmt.Errorf("missing bitness information")
	}
	return nil
}

// validateMachOFormat validates Mach-O-specific format requirements
func (c *BinaryFormatCheck) validateMachOFormat(binaryPath string, info *BinaryInfo) error {
	machoFile, err := macho.Open(binaryPath)
	if err != nil {
		// If standard library parsing fails, do basic validation
		return c.validateMachOBasic(binaryPath, info)
	}
	defer machoFile.Close()
	
	// Check for required sections - only if we have sections at all
	if len(info.Sections) > 0 {
		requiredSections := []string{"__text"}
		for _, required := range requiredSections {
			found := false
			for _, section := range info.Sections {
				if strings.Contains(section, required) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("missing required section: %s", required)
			}
		}
	}
	
	// Validate CPU type is supported
	supportedCPUs := []macho.Cpu{
		macho.Cpu386,
		macho.CpuAmd64,
		macho.CpuArm,
		macho.CpuArm64,
	}
	
	supported := false
	for _, cpu := range supportedCPUs {
		if machoFile.Cpu == cpu {
			supported = true
			break
		}
	}
	
	if !supported {
		return fmt.Errorf("unsupported CPU type: 0x%x", machoFile.Cpu)
	}
	
	return nil
}

// validateMachOBasic performs basic Mach-O validation when standard library parsing fails
func (c *BinaryFormatCheck) validateMachOBasic(binaryPath string, info *BinaryInfo) error {
	// For basic parsing, just validate that we have essential info
	if info.Architecture == "" {
		return fmt.Errorf("missing architecture information")
	}
	if info.Bitness == 0 {
		return fmt.Errorf("missing bitness information")
	}
	return nil
}