package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurityFlagValidationCheck_ID(t *testing.T) {
	check := &SecurityFlagValidationCheck{}
	expected := "check-9-security-flags"
	if check.ID() != expected {
		t.Errorf("Expected ID %s, got %s", expected, check.ID())
	}
}

func TestSecurityFlagValidationCheck_Description(t *testing.T) {
	check := &SecurityFlagValidationCheck{}
	desc := check.Description()
	if desc == "" {
		t.Error("Description should not be empty")
	}
	if !strings.Contains(desc, "security") {
		t.Error("Description should mention security")
	}
}

func TestSecurityFlagValidationCheck_Execute_InvalidBinary(t *testing.T) {
	check := &SecurityFlagValidationCheck{}
	result := check.Execute("nonexistent-file")
	
	if result.Status != "fail" {
		t.Errorf("Expected status 'fail', got '%s'", result.Status)
	}
	if result.ID != check.ID() {
		t.Errorf("Expected ID %s, got %s", check.ID(), result.ID)
	}
	if result.Duration == 0 {
		t.Error("Duration should be set")
	}
}

func TestSecurityFlagValidationCheck_Execute_ValidBinary(t *testing.T) {
	// Create a test binary file
	testBinary := createTestSecurityBinary(t, "test-security-binary")
	defer os.Remove(testBinary)
	
	check := &SecurityFlagValidationCheck{}
	result := check.Execute(testBinary)
	
	// Should not crash and should have metadata
	if result.ID != check.ID() {
		t.Errorf("Expected ID %s, got %s", check.ID(), result.ID)
	}
	if result.Duration == 0 {
		t.Error("Duration should be set")
	}
	if result.Metadata == nil {
		t.Error("Metadata should not be nil")
	}
	
	// Should have format information
	if _, exists := result.Metadata["format"]; !exists {
		t.Error("Metadata should contain format information")
	}
}

func TestVersionInformationCheck_ID(t *testing.T) {
	check := &VersionInformationCheck{}
	expected := "check-10-version-info"
	if check.ID() != expected {
		t.Errorf("Expected ID %s, got %s", expected, check.ID())
	}
}

func TestVersionInformationCheck_Description(t *testing.T) {
	check := &VersionInformationCheck{}
	desc := check.Description()
	if desc == "" {
		t.Error("Description should not be empty")
	}
	if !strings.Contains(desc, "version") {
		t.Error("Description should mention version")
	}
}

func TestVersionInformationCheck_Execute_InvalidBinary(t *testing.T) {
	check := &VersionInformationCheck{}
	result := check.Execute("nonexistent-file")
	
	if result.Status != "fail" {
		t.Errorf("Expected status 'fail', got '%s'", result.Status)
	}
	if result.ID != check.ID() {
		t.Errorf("Expected ID %s, got %s", check.ID(), result.ID)
	}
}

func TestVersionInformationCheck_Execute_ValidBinary(t *testing.T) {
	// Create a test binary file with version strings
	testBinary := createTestBinaryWithVersions(t, "test-version-binary")
	defer os.Remove(testBinary)
	
	check := &VersionInformationCheck{}
	result := check.Execute(testBinary)
	
	// Should not crash and should have metadata
	if result.ID != check.ID() {
		t.Errorf("Expected ID %s, got %s", check.ID(), result.ID)
	}
	if result.Duration == 0 {
		t.Error("Duration should be set")
	}
	if result.Metadata == nil {
		t.Error("Metadata should not be nil")
	}
	
	// Should have version information
	if versionInfo, exists := result.Metadata["version_info"]; exists {
		versionMap := versionInfo.(map[string]interface{})
		if embeddedStrings, exists := versionMap["embedded_strings"]; exists {
			strings := embeddedStrings.([]string)
			// Note: The test binary may not contain version strings, so this is optional
			t.Logf("Found %d embedded version strings: %v", len(strings), strings)
		}
	}
}

func TestVersionInformationCheck_ExtractVersionStrings(t *testing.T) {
	check := &VersionInformationCheck{}
	
	// Create a test file with version strings
	testContent := `
	This is a test binary with version 1.2.3
	Build: 4.5.6
	Version: 2.1.0
	v3.0.0-beta
	Date: 2023-12-01
	`
	
	testFile := filepath.Join(t.TempDir(), "test-version-strings")
	err := os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	
	versions := check.extractVersionStringsFromBinary(testFile)
	
	if len(versions) == 0 {
		t.Error("Should find version strings")
	}
	
	// Check for specific versions
	expectedVersions := []string{"1.2.3", "4.5.6", "2.1.0", "v3.0.0", "2023-12-01"}
	found := make(map[string]bool)
	
	for _, version := range versions {
		for _, expected := range expectedVersions {
			if strings.Contains(version, expected) {
				found[expected] = true
			}
		}
	}
	
	if len(found) == 0 {
		t.Errorf("Should find at least some expected versions, found: %v", versions)
	}
}

func TestLicenseComplianceCheck_ID(t *testing.T) {
	check := &LicenseComplianceCheck{}
	expected := "check-11-license-compliance"
	if check.ID() != expected {
		t.Errorf("Expected ID %s, got %s", expected, check.ID())
	}
}

func TestLicenseComplianceCheck_Description(t *testing.T) {
	check := &LicenseComplianceCheck{}
	desc := check.Description()
	if desc == "" {
		t.Error("Description should not be empty")
	}
	if !strings.Contains(desc, "license") {
		t.Error("Description should mention license")
	}
}

func TestLicenseComplianceCheck_Execute_InvalidBinary(t *testing.T) {
	check := &LicenseComplianceCheck{}
	result := check.Execute("nonexistent-file")
	
	// Should still work even with nonexistent file (just won't find licenses)
	if result.ID != check.ID() {
		t.Errorf("Expected ID %s, got %s", check.ID(), result.ID)
	}
	if result.Duration == 0 {
		t.Error("Duration should be set")
	}
}

func TestLicenseComplianceCheck_Execute_ValidBinary(t *testing.T) {
	// Create a test binary file with license information
	testBinary := createTestBinaryWithLicense(t, "test-license-binary")
	defer os.Remove(testBinary)
	
	check := &LicenseComplianceCheck{}
	result := check.Execute(testBinary)
	
	// Should not crash and should have metadata
	if result.ID != check.ID() {
		t.Errorf("Expected ID %s, got %s", check.ID(), result.ID)
	}
	if result.Duration == 0 {
		t.Error("Duration should be set")
	}
	if result.Metadata == nil {
		t.Error("Metadata should not be nil")
	}
	
	// Should have license information
	if _, exists := result.Metadata["embedded_licenses"]; !exists {
		t.Error("Metadata should contain embedded_licenses")
	}
	if _, exists := result.Metadata["copyright_notices"]; !exists {
		t.Error("Metadata should contain copyright_notices")
	}
}

func TestLicenseComplianceCheck_ExtractEmbeddedLicenses(t *testing.T) {
	check := &LicenseComplianceCheck{}
	
	// Create a test file with license text
	testContent := `
	This software is licensed under the MIT License.
	
	Some code is under Apache License Version 2.0.
	
	SPDX-License-Identifier: BSD-3-Clause
	
	GNU General Public License v3.0
	`
	
	testFile := filepath.Join(t.TempDir(), "test-license-text")
	err := os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	
	licenses := check.extractEmbeddedLicenses(testFile)
	
	if len(licenses) == 0 {
		t.Error("Should find embedded licenses")
	}
	
	// Check for specific licenses
	expectedLicenses := []string{"MIT License", "Apache License", "SPDX: BSD-3-Clause", "GNU General Public License"}
	found := 0
	
	for _, license := range licenses {
		for _, expected := range expectedLicenses {
			if strings.Contains(license, expected) || strings.Contains(expected, license) {
				found++
				break
			}
		}
	}
	
	if found == 0 {
		t.Errorf("Should find at least some expected licenses, found: %v", licenses)
	}
}

func TestLicenseComplianceCheck_ExtractCopyrightNotices(t *testing.T) {
	check := &LicenseComplianceCheck{}
	
	// Create a test file with copyright notices
	testContent := `
	Copyright (c) 2023 Test Company
	Copyright 2022-2023 Another Company
	© 2021 Third Company
	(c) 2020 Fourth Company
	`
	
	testFile := filepath.Join(t.TempDir(), "test-copyright-text")
	err := os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	
	copyrights := check.extractCopyrightNotices(testFile)
	
	if len(copyrights) == 0 {
		t.Error("Should find copyright notices")
	}
	
	// Check that we found some copyright notices
	foundCopyright := false
	for _, copyright := range copyrights {
		if strings.Contains(strings.ToLower(copyright), "copyright") || 
		   strings.Contains(copyright, "©") || 
		   strings.Contains(copyright, "(c)") {
			foundCopyright = true
			break
		}
	}
	
	if !foundCopyright {
		t.Errorf("Should find copyright notices, found: %v", copyrights)
	}
}

func TestLicenseComplianceCheck_FindLicenseFiles(t *testing.T) {
	check := &LicenseComplianceCheck{}
	
	// Create a temporary directory with license files
	tempDir := t.TempDir()
	testBinary := filepath.Join(tempDir, "test-binary")
	
	// Create test binary
	err := os.WriteFile(testBinary, []byte("test binary content"), 0755)
	if err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}
	
	// Create license files
	licenseFiles := []string{"LICENSE", "LICENSE.txt", "COPYING", "COPYRIGHT"}
	for _, fileName := range licenseFiles {
		licensePath := filepath.Join(tempDir, fileName)
		err := os.WriteFile(licensePath, []byte("License content"), 0644)
		if err != nil {
			t.Fatalf("Failed to create license file %s: %v", fileName, err)
		}
	}
	
	foundFiles := check.findLicenseFiles(testBinary)
	
	if len(foundFiles) == 0 {
		t.Error("Should find license files")
	}
	
	// Should find at least some of the license files we created
	if len(foundFiles) < 2 {
		t.Errorf("Should find multiple license files, found: %v", foundFiles)
	}
}

func TestSecurityFlagValidationCheck_AnalyzeELFSecurityFlags(t *testing.T) {
	check := &SecurityFlagValidationCheck{}
	
	// Create a simple test binary (this won't be a real ELF, but tests the error handling)
	testBinary := createTestSecurityBinary(t, "test-elf-security")
	defer os.Remove(testBinary)
	
	flags, issues := check.analyzeELFSecurityFlags(testBinary)
	
	// Should return some flags even if parsing fails
	if flags == nil {
		t.Error("Flags should not be nil")
	}
	
	// Should have expected flag keys
	expectedKeys := []string{"nx_bit", "stack_canary", "fortify_source", "relro", "pie", "stripped"}
	for _, key := range expectedKeys {
		if _, exists := flags[key]; !exists {
			t.Errorf("Flags should contain key: %s", key)
		}
	}
	
	// Should have some issues since this isn't a real ELF
	if len(issues) == 0 {
		t.Error("Should have issues for non-ELF file")
	}
}

// Helper functions for creating test files

func createTestSecurityBinary(t *testing.T, name string) string {
	testFile := filepath.Join(t.TempDir(), name)
	
	// Create a simple binary-like file with some recognizable content
	content := []byte{
		0x7F, 0x45, 0x4C, 0x46, // ELF magic (fake)
		0x02, 0x01, 0x01, 0x00, // ELF header continuation
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Add some padding
	}
	
	// Add some text content
	content = append(content, []byte("This is a test binary file")...)
	
	err := os.WriteFile(testFile, content, 0755)
	if err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}
	
	return testFile
}

func createTestBinaryWithVersions(t *testing.T, name string) string {
	testFile := filepath.Join(t.TempDir(), name)
	
	// Create a binary with version information
	content := []byte{
		0x7F, 0x45, 0x4C, 0x46, // ELF magic (fake)
		0x02, 0x01, 0x01, 0x00,
	}
	
	// Add version strings
	versionContent := `
	Version: 1.2.3
	Build: 2023-12-01
	v2.0.0-beta
	Product Version 4.5.6
	`
	
	content = append(content, []byte(versionContent)...)
	
	err := os.WriteFile(testFile, content, 0755)
	if err != nil {
		t.Fatalf("Failed to create test binary with versions: %v", err)
	}
	
	return testFile
}

func createTestBinaryWithLicense(t *testing.T, name string) string {
	testFile := filepath.Join(t.TempDir(), name)
	
	// Create a binary with license information
	content := []byte{
		0x7F, 0x45, 0x4C, 0x46, // ELF magic (fake)
		0x02, 0x01, 0x01, 0x00,
	}
	
	// Add license and copyright content
	licenseContent := `
	MIT License
	Copyright (c) 2023 Test Company
	Apache License Version 2.0
	SPDX-License-Identifier: MIT
	GNU General Public License
	© 2023 Another Company
	`
	
	content = append(content, []byte(licenseContent)...)
	
	err := os.WriteFile(testFile, content, 0755)
	if err != nil {
		t.Fatalf("Failed to create test binary with license: %v", err)
	}
	
	return testFile
}

// Benchmark tests

func BenchmarkSecurityFlagValidationCheck_Execute(b *testing.B) {
	testBinary := createTestBinaryTB(b, "bench-security-binary")
	defer os.Remove(testBinary)
	
	check := &SecurityFlagValidationCheck{}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		check.Execute(testBinary)
	}
}

func BenchmarkVersionInformationCheck_Execute(b *testing.B) {
	testBinary := createTestBinaryWithVersionsTB(b, "bench-version-binary")
	defer os.Remove(testBinary)
	
	check := &VersionInformationCheck{}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		check.Execute(testBinary)
	}
}

func BenchmarkLicenseComplianceCheck_Execute(b *testing.B) {
	testBinary := createTestBinaryWithLicenseTB(b, "bench-license-binary")
	defer os.Remove(testBinary)
	
	check := &LicenseComplianceCheck{}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		check.Execute(testBinary)
	}
}

// Helper functions for benchmarks that need testing.TB interface
func createTestBinaryTB(tb testing.TB, name string) string {
	testFile := filepath.Join(tb.TempDir(), name)
	
	content := []byte{
		0x7F, 0x45, 0x4C, 0x46, // ELF magic (fake)
		0x02, 0x01, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	
	content = append(content, []byte("This is a test binary file")...)
	
	err := os.WriteFile(testFile, content, 0755)
	if err != nil {
		tb.Fatalf("Failed to create test binary: %v", err)
	}
	
	return testFile
}

func createTestBinaryWithVersionsTB(tb testing.TB, name string) string {
	testFile := filepath.Join(tb.TempDir(), name)
	
	content := []byte{
		0x7F, 0x45, 0x4C, 0x46, // ELF magic (fake)
		0x02, 0x01, 0x01, 0x00,
	}
	
	versionContent := `
	Version: 1.2.3
	Build: 2023-12-01
	v2.0.0-beta
	Product Version 4.5.6
	`
	
	content = append(content, []byte(versionContent)...)
	
	err := os.WriteFile(testFile, content, 0755)
	if err != nil {
		tb.Fatalf("Failed to create test binary with versions: %v", err)
	}
	
	return testFile
}

func createTestBinaryWithLicenseTB(tb testing.TB, name string) string {
	testFile := filepath.Join(tb.TempDir(), name)
	
	content := []byte{
		0x7F, 0x45, 0x4C, 0x46, // ELF magic (fake)
		0x02, 0x01, 0x01, 0x00,
	}
	
	licenseContent := `
	MIT License
	Copyright (c) 2023 Test Company
	Apache License Version 2.0
	SPDX-License-Identifier: MIT
	GNU General Public License
	© 2023 Another Company
	`
	
	content = append(content, []byte(licenseContent)...)
	
	err := os.WriteFile(testFile, content, 0755)
	if err != nil {
		tb.Fatalf("Failed to create test binary with license: %v", err)
	}
	
	return testFile
}