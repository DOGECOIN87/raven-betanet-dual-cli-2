package checks

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// SecurityFlagValidationCheck implements check 9: Security flag validation
type SecurityFlagValidationCheck struct{}

func (c *SecurityFlagValidationCheck) ID() string {
	return "check-9-security-flags"
}

func (c *SecurityFlagValidationCheck) Description() string {
	return "Validates security flags and compiler protections in binary"
}

func (c *SecurityFlagValidationCheck) Execute(binaryPath string) CheckResult {
	start := time.Now()
	
	result := CheckResult{
		ID:          c.ID(),
		Description: c.Description(),
		Duration:    time.Since(start),
		Metadata:    make(map[string]interface{}),
	}
	
	// Determine binary format
	parser := NewBinaryParser()
	info, err := parser.ParseBinary(binaryPath)
	if err != nil {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Failed to parse binary for security analysis: %v", err)
		return result
	}
	
	// Analyze security flags based on format
	var securityFlags map[string]interface{}
	var issues []string
	
	switch info.Format {
	case FormatELF:
		securityFlags, issues = c.analyzeELFSecurityFlags(binaryPath)
	case FormatPE:
		securityFlags, issues = c.analyzePESecurityFlags(binaryPath)
	case FormatMachO:
		securityFlags, issues = c.analyzeMachOSecurityFlags(binaryPath)
	default:
		result.Status = "fail"
		result.Details = "Unsupported binary format for security flag analysis"
		return result
	}
	
	result.Metadata["security_flags"] = securityFlags
	result.Metadata["format"] = string(info.Format)
	
	if len(issues) > 0 {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Security flag validation failed: %d issues found", len(issues))
		result.Metadata["security_issues"] = issues
	} else {
		result.Status = "pass"
		result.Details = "Security flag validation passed - all recommended protections enabled"
		result.Metadata["security_issues"] = []string{}
	}
	
	result.Duration = time.Since(start)
	return result
}

// analyzeELFSecurityFlags analyzes security flags in ELF binaries
func (c *SecurityFlagValidationCheck) analyzeELFSecurityFlags(binaryPath string) (map[string]interface{}, []string) {
	flags := map[string]interface{}{
		"nx_bit":           false,
		"stack_canary":     false,
		"fortify_source":   false,
		"relro":           "none",
		"pie":             false,
		"stripped":        false,
	}
	var issues []string
	
	elfFile, err := elf.Open(binaryPath)
	if err != nil {
		issues = append(issues, fmt.Sprintf("Failed to open ELF file: %v", err))
		return flags, issues
	}
	defer elfFile.Close()
	
	// Check for NX bit (GNU_STACK segment)
	for _, prog := range elfFile.Progs {
		if prog.Type == elf.PT_GNU_STACK {
			flags["nx_bit"] = (prog.Flags & elf.PF_X) == 0
			break
		}
	}
	if !flags["nx_bit"].(bool) {
		issues = append(issues, "NX bit not enabled - stack/heap may be executable")
	}
	
	// Check for RELRO (GNU_RELRO segment and BIND_NOW)
	hasRelro := false
	hasBindNow := false
	
	for _, prog := range elfFile.Progs {
		if prog.Type == elf.PT_GNU_RELRO {
			hasRelro = true
			break
		}
	}
	
	// Check for BIND_NOW in dynamic section
	if dynSection := elfFile.Section(".dynamic"); dynSection != nil {
		dynData, err := dynSection.Data()
		if err == nil {
			// Look for DT_BIND_NOW or DT_FLAGS with DF_BIND_NOW
			hasBindNow = c.checkELFBindNow(dynData, elfFile)
		}
	}
	
	if hasRelro && hasBindNow {
		flags["relro"] = "full"
	} else if hasRelro {
		flags["relro"] = "partial"
	} else {
		flags["relro"] = "none"
		issues = append(issues, "RELRO not enabled - GOT/PLT vulnerable to overwrites")
	}
	
	// Check for PIE (Position Independent Executable)
	flags["pie"] = elfFile.Type == elf.ET_DYN
	if !flags["pie"].(bool) {
		issues = append(issues, "PIE not enabled - binary not position independent")
	}
	
	// Check for stack canary (look for __stack_chk_fail symbol)
	symbols, err := elfFile.Symbols()
	if err == nil {
		for _, sym := range symbols {
			if strings.Contains(sym.Name, "__stack_chk_fail") {
				flags["stack_canary"] = true
				break
			}
		}
	}
	if !flags["stack_canary"].(bool) {
		issues = append(issues, "Stack canary not detected - buffer overflows may not be detected")
	}
	
	// Check for FORTIFY_SOURCE (look for __*_chk symbols)
	if symbols != nil {
		for _, sym := range symbols {
			if strings.Contains(sym.Name, "_chk") && strings.Contains(sym.Name, "__") {
				flags["fortify_source"] = true
				break
			}
		}
	}
	if !flags["fortify_source"].(bool) {
		issues = append(issues, "FORTIFY_SOURCE not detected - buffer overflow protections may be missing")
	}
	
	// Check if binary is stripped (no symbol table)
	flags["stripped"] = elfFile.Section(".symtab") == nil
	
	return flags, issues
}

// checkELFBindNow checks for BIND_NOW flag in ELF dynamic section
func (c *SecurityFlagValidationCheck) checkELFBindNow(dynData []byte, elfFile *elf.File) bool {
	// This is a simplified check for DT_BIND_NOW or DT_FLAGS with DF_BIND_NOW
	// Real implementation would properly parse the dynamic section
	
	// Look for DT_BIND_NOW (tag = 24) or DT_FLAGS (tag = 30) with DF_BIND_NOW (0x8)
	entrySize := 8
	if elfFile.Class == elf.ELFCLASS64 {
		entrySize = 16
	}
	
	for i := 0; i < len(dynData)-entrySize; i += entrySize {
		var tag, val uint64
		
		if elfFile.Class == elf.ELFCLASS64 {
			tag = elfFile.ByteOrder.Uint64(dynData[i : i+8])
			val = elfFile.ByteOrder.Uint64(dynData[i+8 : i+16])
		} else {
			tag = uint64(elfFile.ByteOrder.Uint32(dynData[i : i+4]))
			val = uint64(elfFile.ByteOrder.Uint32(dynData[i+4 : i+8]))
		}
		
		// DT_BIND_NOW
		if tag == 24 {
			return true
		}
		
		// DT_FLAGS with DF_BIND_NOW
		if tag == 30 && (val&0x8) != 0 {
			return true
		}
	}
	
	return false
}

// analyzePESecurityFlags analyzes security flags in PE binaries
func (c *SecurityFlagValidationCheck) analyzePESecurityFlags(binaryPath string) (map[string]interface{}, []string) {
	flags := map[string]interface{}{
		"aslr":                false,
		"dep":                 false,
		"safe_seh":           false,
		"gs":                 false,
		"control_flow_guard": false,
	}
	var issues []string
	
	peFile, err := pe.Open(binaryPath)
	if err != nil {
		issues = append(issues, fmt.Sprintf("Failed to open PE file: %v", err))
		return flags, issues
	}
	defer peFile.Close()
	
	// Check ASLR (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
	if peFile.OptionalHeader != nil {
		switch oh := peFile.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			flags["aslr"] = (oh.DllCharacteristics & 0x0040) != 0
			flags["dep"] = (oh.DllCharacteristics & 0x0100) != 0
			flags["safe_seh"] = (oh.DllCharacteristics & 0x0400) != 0
			flags["control_flow_guard"] = (oh.DllCharacteristics & 0x4000) != 0
		case *pe.OptionalHeader64:
			flags["aslr"] = (oh.DllCharacteristics & 0x0040) != 0
			flags["dep"] = (oh.DllCharacteristics & 0x0100) != 0
			flags["control_flow_guard"] = (oh.DllCharacteristics & 0x4000) != 0
		}
	}
	
	// Check for GS (stack cookies) by looking for __security_cookie
	symbols, err := peFile.ImportedSymbols()
	if err == nil {
		for _, sym := range symbols {
			if strings.Contains(sym, "__security_cookie") || strings.Contains(sym, "__security_check_cookie") {
				flags["gs"] = true
				break
			}
		}
	}
	
	// Report issues
	if !flags["aslr"].(bool) {
		issues = append(issues, "ASLR not enabled - binary not randomized in memory")
	}
	if !flags["dep"].(bool) {
		issues = append(issues, "DEP/NX not enabled - stack/heap may be executable")
	}
	if !flags["safe_seh"].(bool) && peFile.Machine == pe.IMAGE_FILE_MACHINE_I386 {
		issues = append(issues, "Safe SEH not enabled - exception handling vulnerable")
	}
	if !flags["gs"].(bool) {
		issues = append(issues, "GS stack cookies not detected - buffer overflows may not be detected")
	}
	if !flags["control_flow_guard"].(bool) {
		issues = append(issues, "Control Flow Guard not enabled - ROP/JOP attacks not mitigated")
	}
	
	return flags, issues
}

// analyzeMachOSecurityFlags analyzes security flags in Mach-O binaries
func (c *SecurityFlagValidationCheck) analyzeMachOSecurityFlags(binaryPath string) (map[string]interface{}, []string) {
	flags := map[string]interface{}{
		"pie":           false,
		"nx_bit":        false,
		"stack_canary":  false,
		"arc":          false,
		"code_signing": false,
	}
	var issues []string
	
	machoFile, err := macho.Open(binaryPath)
	if err != nil {
		issues = append(issues, fmt.Sprintf("Failed to open Mach-O file: %v", err))
		return flags, issues
	}
	defer machoFile.Close()
	
	// Check for PIE (MH_PIE flag)
	flags["pie"] = (machoFile.Flags & 0x200000) != 0 // MH_PIE
	if !flags["pie"].(bool) {
		issues = append(issues, "PIE not enabled - binary not position independent")
	}
	
	// Check for NX bit (MH_ALLOW_STACK_EXECUTION flag should NOT be set)
	flags["nx_bit"] = (machoFile.Flags & 0x20000) == 0 // MH_ALLOW_STACK_EXECUTION not set
	if !flags["nx_bit"].(bool) {
		issues = append(issues, "NX bit not enabled - stack may be executable")
	}
	
	// Check for stack canary (look for __stack_chk_fail symbol)
	if machoFile.Symtab != nil {
		for _, sym := range machoFile.Symtab.Syms {
			if strings.Contains(sym.Name, "__stack_chk_fail") {
				flags["stack_canary"] = true
				break
			}
		}
	}
	if !flags["stack_canary"].(bool) {
		issues = append(issues, "Stack canary not detected - buffer overflows may not be detected")
	}
	
	// Check for ARC (Automatic Reference Counting) - look for objc_retain/release symbols
	if machoFile.Symtab != nil {
		for _, sym := range machoFile.Symtab.Syms {
			if strings.Contains(sym.Name, "objc_retain") || strings.Contains(sym.Name, "objc_release") {
				flags["arc"] = true
				break
			}
		}
	}
	
	// Check for code signing (LC_CODE_SIGNATURE load command)
	for _, load := range machoFile.Loads {
		// Use type assertion to get the command value
		switch cmd := load.(type) {
		case *macho.Segment:
			if cmd.Cmd == 0x1d { // LC_CODE_SIGNATURE
				flags["code_signing"] = true
			}
		}
	}
	if !flags["code_signing"].(bool) {
		issues = append(issues, "Code signing not detected - binary integrity cannot be verified")
	}
	
	return flags, issues
}

// VersionInformationCheck implements check 10: Version information validation
type VersionInformationCheck struct{}

func (c *VersionInformationCheck) ID() string {
	return "check-10-version-info"
}

func (c *VersionInformationCheck) Description() string {
	return "Extracts and validates version information from binary metadata"
}

func (c *VersionInformationCheck) Execute(binaryPath string) CheckResult {
	start := time.Now()
	
	result := CheckResult{
		ID:          c.ID(),
		Description: c.Description(),
		Duration:    time.Since(start),
		Metadata:    make(map[string]interface{}),
	}
	
	// Determine binary format
	parser := NewBinaryParser()
	info, err := parser.ParseBinary(binaryPath)
	if err != nil {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Failed to parse binary for version analysis: %v", err)
		return result
	}
	
	// Extract version information based on format
	var versionInfo map[string]interface{}
	var issues []string
	
	switch info.Format {
	case FormatELF:
		versionInfo, issues = c.extractELFVersionInfo(binaryPath)
	case FormatPE:
		versionInfo, issues = c.extractPEVersionInfo(binaryPath)
	case FormatMachO:
		versionInfo, issues = c.extractMachOVersionInfo(binaryPath)
	default:
		// For unknown formats, try generic version extraction
		versionInfo, issues = c.extractGenericVersionInfo(binaryPath)
	}
	
	result.Metadata["version_info"] = versionInfo
	result.Metadata["format"] = string(info.Format)
	
	if len(issues) > 0 {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Version information validation failed: %d issues found", len(issues))
		result.Metadata["version_issues"] = issues
	} else {
		result.Status = "pass"
		result.Details = "Version information validation passed"
		result.Metadata["version_issues"] = []string{}
	}
	
	result.Duration = time.Since(start)
	return result
}

// extractELFVersionInfo extracts version information from ELF binaries
func (c *VersionInformationCheck) extractELFVersionInfo(binaryPath string) (map[string]interface{}, []string) {
	versionInfo := map[string]interface{}{
		"build_id":        "",
		"gnu_version":     "",
		"embedded_strings": []string{},
	}
	var issues []string
	
	elfFile, err := elf.Open(binaryPath)
	if err != nil {
		issues = append(issues, fmt.Sprintf("Failed to open ELF file: %v", err))
		return versionInfo, issues
	}
	defer elfFile.Close()
	
	// Extract build ID from .note.gnu.build-id section
	if buildIDSection := elfFile.Section(".note.gnu.build-id"); buildIDSection != nil {
		buildIDData, err := buildIDSection.Data()
		if err == nil && len(buildIDData) > 16 {
			// Skip note header and extract build ID
			buildID := fmt.Sprintf("%x", buildIDData[16:])
			versionInfo["build_id"] = buildID
		}
	}
	
	// Look for version strings in .comment section
	if commentSection := elfFile.Section(".comment"); commentSection != nil {
		commentData, err := commentSection.Data()
		if err == nil {
			comment := strings.TrimSpace(string(commentData))
			if comment != "" {
				versionInfo["gnu_version"] = comment
			}
		}
	}
	
	// Extract version strings from binary content
	versionStrings := c.extractVersionStringsFromBinary(binaryPath)
	versionInfo["embedded_strings"] = versionStrings
	
	// Check for issues
	if versionInfo["build_id"] == "" {
		issues = append(issues, "No build ID found - binary may not be reproducible")
	}
	
	if len(versionStrings) == 0 {
		issues = append(issues, "No version strings found in binary")
	}
	
	return versionInfo, issues
}

// extractPEVersionInfo extracts version information from PE binaries
func (c *VersionInformationCheck) extractPEVersionInfo(binaryPath string) (map[string]interface{}, []string) {
	versionInfo := map[string]interface{}{
		"file_version":     "",
		"product_version":  "",
		"company_name":     "",
		"product_name":     "",
		"embedded_strings": []string{},
	}
	var issues []string
	
	// Extract version strings from binary content
	versionStrings := c.extractVersionStringsFromBinary(binaryPath)
	versionInfo["embedded_strings"] = versionStrings
	
	// Try to extract version resource information (simplified)
	// Real implementation would parse the PE version resource
	file, err := os.Open(binaryPath)
	if err != nil {
		issues = append(issues, fmt.Sprintf("Failed to open PE file: %v", err))
		return versionInfo, issues
	}
	defer file.Close()
	
	content, err := io.ReadAll(file)
	if err != nil {
		issues = append(issues, fmt.Sprintf("Failed to read PE file: %v", err))
		return versionInfo, issues
	}
	
	contentStr := string(content)
	
	// Look for common version resource strings
	if strings.Contains(contentStr, "FileVersion") {
		versionInfo["has_version_resource"] = true
	}
	
	// Check for issues
	if len(versionStrings) == 0 {
		issues = append(issues, "No version strings found in binary")
	}
	
	return versionInfo, issues
}

// extractMachOVersionInfo extracts version information from Mach-O binaries
func (c *VersionInformationCheck) extractMachOVersionInfo(binaryPath string) (map[string]interface{}, []string) {
	versionInfo := map[string]interface{}{
		"min_os_version":   "",
		"sdk_version":      "",
		"embedded_strings": []string{},
	}
	var issues []string
	
	machoFile, err := macho.Open(binaryPath)
	if err != nil {
		issues = append(issues, fmt.Sprintf("Failed to open Mach-O file: %v", err))
		return versionInfo, issues
	}
	defer machoFile.Close()
	
	// Extract version information from load commands
	for _, load := range machoFile.Loads {
		// Use type assertion to get the command value
		switch cmd := load.(type) {
		case *macho.Segment:
			if cmd.Cmd == 0x24 { // LC_VERSION_MIN_MACOSX
				versionInfo["min_os_version"] = "macOS (version info in load command)"
			} else if cmd.Cmd == 0x25 { // LC_VERSION_MIN_IPHONEOS
				versionInfo["min_os_version"] = "iOS (version info in load command)"
			} else if cmd.Cmd == 0x32 { // LC_BUILD_VERSION
				versionInfo["has_build_version"] = true
			}
		}
	}
	
	// Extract version strings from binary content
	versionStrings := c.extractVersionStringsFromBinary(binaryPath)
	versionInfo["embedded_strings"] = versionStrings
	
	// Check for issues
	if versionInfo["min_os_version"] == "" {
		issues = append(issues, "No minimum OS version information found")
	}
	
	if len(versionStrings) == 0 {
		issues = append(issues, "No version strings found in binary")
	}
	
	return versionInfo, issues
}

// extractGenericVersionInfo extracts version information from any binary format
func (c *VersionInformationCheck) extractGenericVersionInfo(binaryPath string) (map[string]interface{}, []string) {
	versionInfo := map[string]interface{}{
		"embedded_strings": []string{},
	}
	var issues []string
	
	// Extract version strings from binary content
	versionStrings := c.extractVersionStringsFromBinary(binaryPath)
	versionInfo["embedded_strings"] = versionStrings
	
	// Check for issues
	if len(versionStrings) == 0 {
		issues = append(issues, "No version strings found in binary")
	}
	
	return versionInfo, issues
}

// extractVersionStringsFromBinary extracts version-like strings from binary content
func (c *VersionInformationCheck) extractVersionStringsFromBinary(binaryPath string) []string {
	var versionStrings []string
	
	file, err := os.Open(binaryPath)
	if err != nil {
		return versionStrings
	}
	defer file.Close()
	
	content, err := io.ReadAll(file)
	if err != nil {
		return versionStrings
	}
	
	// Convert to string and look for version patterns
	contentStr := string(content)
	
	// Common version patterns
	versionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\b\d+\.\d+\.\d+(?:\.\d+)?\b`),                    // x.y.z or x.y.z.w
		regexp.MustCompile(`\bv\d+\.\d+\.\d+(?:\.\d+)?\b`),                  // vx.y.z
		regexp.MustCompile(`\bversion\s+\d+\.\d+\.\d+(?:\.\d+)?\b`),         // version x.y.z
		regexp.MustCompile(`\b\d+\.\d+\b`),                                  // x.y
		regexp.MustCompile(`\b[Vv]ersion:?\s*[\d.]+\b`),                     // Version: x.y.z
		regexp.MustCompile(`\b[Bb]uild:?\s*[\d.]+\b`),                       // Build: x.y.z
		regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`),                         // Date format YYYY-MM-DD
	}
	
	// Find all version-like strings
	foundVersions := make(map[string]bool)
	
	for _, pattern := range versionPatterns {
		matches := pattern.FindAllString(contentStr, -1)
		for _, match := range matches {
			// Clean up the match
			match = strings.TrimSpace(match)
			if len(match) > 0 && !foundVersions[match] {
				foundVersions[match] = true
				versionStrings = append(versionStrings, match)
			}
		}
	}
	
	// Limit to reasonable number of version strings
	if len(versionStrings) > 20 {
		versionStrings = versionStrings[:20]
	}
	
	return versionStrings
}

// LicenseComplianceCheck implements check 11: License compliance validation
type LicenseComplianceCheck struct{}

func (c *LicenseComplianceCheck) ID() string {
	return "check-11-license-compliance"
}

func (c *LicenseComplianceCheck) Description() string {
	return "Validates license compliance and identifies embedded license information"
}

func (c *LicenseComplianceCheck) Execute(binaryPath string) CheckResult {
	start := time.Now()
	
	result := CheckResult{
		ID:          c.ID(),
		Description: c.Description(),
		Duration:    time.Since(start),
		Metadata:    make(map[string]interface{}),
	}
	
	// Look for license files and embedded license information
	licenseInfo, issues := c.analyzeLicenseCompliance(binaryPath)
	
	result.Metadata = licenseInfo
	
	if len(issues) > 0 {
		result.Status = "fail"
		result.Details = fmt.Sprintf("License compliance validation failed: %d issues found", len(issues))
		result.Metadata["license_issues"] = issues
	} else {
		result.Status = "pass"
		result.Details = "License compliance validation passed"
		result.Metadata["license_issues"] = []string{}
	}
	
	result.Duration = time.Since(start)
	return result
}

// analyzeLicenseCompliance analyzes license compliance for the binary
func (c *LicenseComplianceCheck) analyzeLicenseCompliance(binaryPath string) (map[string]interface{}, []string) {
	licenseInfo := map[string]interface{}{
		"license_files":      []string{},
		"embedded_licenses":  []string{},
		"copyright_notices":  []string{},
		"third_party_licenses": []string{},
	}
	var issues []string
	
	// Look for license files in the same directory
	licenseFiles := c.findLicenseFiles(binaryPath)
	licenseInfo["license_files"] = licenseFiles
	
	// Extract embedded license information
	embeddedLicenses := c.extractEmbeddedLicenses(binaryPath)
	licenseInfo["embedded_licenses"] = embeddedLicenses
	
	// Extract copyright notices
	copyrightNotices := c.extractCopyrightNotices(binaryPath)
	licenseInfo["copyright_notices"] = copyrightNotices
	
	// Look for third-party license indicators
	thirdPartyLicenses := c.findThirdPartyLicenses(binaryPath)
	licenseInfo["third_party_licenses"] = thirdPartyLicenses
	
	// Check for compliance issues
	if len(licenseFiles) == 0 && len(embeddedLicenses) == 0 {
		issues = append(issues, "No license information found - license compliance cannot be verified")
	}
	
	if len(copyrightNotices) == 0 {
		issues = append(issues, "No copyright notices found - may indicate missing attribution")
	}
	
	// Check for GPL license without source code availability
	hasGPL := false
	for _, license := range embeddedLicenses {
		if strings.Contains(strings.ToLower(license), "gpl") || 
		   strings.Contains(strings.ToLower(license), "general public license") {
			hasGPL = true
			break
		}
	}
	
	if hasGPL {
		// Look for source code availability notice
		hasSourceNotice := false
		for _, license := range embeddedLicenses {
			if strings.Contains(strings.ToLower(license), "source") && 
			   strings.Contains(strings.ToLower(license), "available") {
				hasSourceNotice = true
				break
			}
		}
		if !hasSourceNotice {
			issues = append(issues, "GPL license detected but no source code availability notice found")
		}
	}
	
	return licenseInfo, issues
}

// findLicenseFiles looks for license files in the same directory as the binary
func (c *LicenseComplianceCheck) findLicenseFiles(binaryPath string) []string {
	var licenseFiles []string
	
	dir := filepath.Dir(binaryPath)
	
	// Common license file names
	licenseFileNames := []string{
		"LICENSE", "LICENSE.txt", "LICENSE.md",
		"LICENCE", "LICENCE.txt", "LICENCE.md",
		"COPYING", "COPYING.txt",
		"COPYRIGHT", "COPYRIGHT.txt",
		"NOTICE", "NOTICE.txt",
		"LEGAL", "LEGAL.txt",
	}
	
	for _, fileName := range licenseFileNames {
		licensePath := filepath.Join(dir, fileName)
		if _, err := os.Stat(licensePath); err == nil {
			licenseFiles = append(licenseFiles, licensePath)
		}
		
		// Also check lowercase versions
		licensePath = filepath.Join(dir, strings.ToLower(fileName))
		if _, err := os.Stat(licensePath); err == nil {
			licenseFiles = append(licenseFiles, licensePath)
		}
	}
	
	return licenseFiles
}

// extractEmbeddedLicenses extracts license text embedded in the binary
func (c *LicenseComplianceCheck) extractEmbeddedLicenses(binaryPath string) []string {
	var licenses []string
	
	file, err := os.Open(binaryPath)
	if err != nil {
		return licenses
	}
	defer file.Close()
	
	content, err := io.ReadAll(file)
	if err != nil {
		return licenses
	}
	
	contentStr := string(content)
	
	// Common license identifiers
	licensePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)MIT License`),
		regexp.MustCompile(`(?i)Apache License`),
		regexp.MustCompile(`(?i)GNU General Public License`),
		regexp.MustCompile(`(?i)GNU Lesser General Public License`),
		regexp.MustCompile(`(?i)BSD License`),
		regexp.MustCompile(`(?i)Mozilla Public License`),
		regexp.MustCompile(`(?i)ISC License`),
		regexp.MustCompile(`(?i)Creative Commons`),
		regexp.MustCompile(`(?i)Unlicense`),
		regexp.MustCompile(`(?i)WTFPL`),
	}
	
	foundLicenses := make(map[string]bool)
	
	for _, pattern := range licensePatterns {
		matches := pattern.FindAllString(contentStr, -1)
		for _, match := range matches {
			if !foundLicenses[match] {
				foundLicenses[match] = true
				licenses = append(licenses, match)
			}
		}
	}
	
	// Look for SPDX license identifiers
	spdxPattern := regexp.MustCompile(`SPDX-License-Identifier:\s*([A-Za-z0-9.-]+)`)
	spdxMatches := spdxPattern.FindAllStringSubmatch(contentStr, -1)
	for _, match := range spdxMatches {
		if len(match) > 1 {
			spdxLicense := "SPDX: " + match[1]
			if !foundLicenses[spdxLicense] {
				foundLicenses[spdxLicense] = true
				licenses = append(licenses, spdxLicense)
			}
		}
	}
	
	return licenses
}

// extractCopyrightNotices extracts copyright notices from the binary
func (c *LicenseComplianceCheck) extractCopyrightNotices(binaryPath string) []string {
	var copyrights []string
	
	file, err := os.Open(binaryPath)
	if err != nil {
		return copyrights
	}
	defer file.Close()
	
	content, err := io.ReadAll(file)
	if err != nil {
		return copyrights
	}
	
	contentStr := string(content)
	
	// Copyright patterns
	copyrightPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)Copyright\s+(?:\(c\)\s*)?(?:19|20)\d{2}(?:-(?:19|20)\d{2})?\s+[^,\n\r]{1,100}`),
		regexp.MustCompile(`(?i)\(c\)\s*(?:19|20)\d{2}(?:-(?:19|20)\d{2})?\s+[^,\n\r]{1,100}`),
		regexp.MustCompile(`(?i)©\s*(?:19|20)\d{2}(?:-(?:19|20)\d{2})?\s+[^,\n\r]{1,100}`),
	}
	
	foundCopyrights := make(map[string]bool)
	
	for _, pattern := range copyrightPatterns {
		matches := pattern.FindAllString(contentStr, -1)
		for _, match := range matches {
			// Clean up the match
			match = strings.TrimSpace(match)
			// Remove null bytes and other binary artifacts
			match = strings.ReplaceAll(match, "\x00", "")
			match = regexp.MustCompile(`[^\x20-\x7E]`).ReplaceAllString(match, "")
			
			if len(match) > 10 && len(match) < 200 && !foundCopyrights[match] {
				foundCopyrights[match] = true
				copyrights = append(copyrights, match)
			}
		}
	}
	
	// Limit to reasonable number of copyright notices
	if len(copyrights) > 50 {
		copyrights = copyrights[:50]
	}
	
	return copyrights
}

// findThirdPartyLicenses identifies third-party library licenses
func (c *LicenseComplianceCheck) findThirdPartyLicenses(binaryPath string) []string {
	var thirdPartyLicenses []string
	
	file, err := os.Open(binaryPath)
	if err != nil {
		return thirdPartyLicenses
	}
	defer file.Close()
	
	content, err := io.ReadAll(file)
	if err != nil {
		return thirdPartyLicenses
	}
	
	contentStr := strings.ToLower(string(content))
	
	// Common third-party library indicators
	thirdPartyIndicators := []string{
		"openssl", "zlib", "libpng", "libjpeg", "sqlite",
		"curl", "boost", "qt", "gtk", "glib",
		"freetype", "harfbuzz", "icu", "pcre",
		"expat", "libxml", "json", "yaml",
	}
	
	foundLibraries := make(map[string]bool)
	
	for _, indicator := range thirdPartyIndicators {
		if strings.Contains(contentStr, indicator) && !foundLibraries[indicator] {
			foundLibraries[indicator] = true
			thirdPartyLicenses = append(thirdPartyLicenses, indicator)
		}
	}
	
	return thirdPartyLicenses
}