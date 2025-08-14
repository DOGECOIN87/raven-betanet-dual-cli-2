package checks

import (
	"os"
	"strings"
	"testing"
)

// Test data for creating sample binaries
var (
	// ELF header for a simple 64-bit ELF file
	elfHeader64 = []byte{
		0x7f, 0x45, 0x4c, 0x46, // ELF magic
		0x02,                   // 64-bit
		0x01,                   // Little endian
		0x01,                   // ELF version
		0x00,                   // System V ABI
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
		0x02, 0x00, // Executable file
		0x3e, 0x00, // x86-64
		0x01, 0x00, 0x00, 0x00, // Version
		0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // Entry point
		0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Program header offset
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Section header offset
		0x00, 0x00, 0x00, 0x00, // Flags
		0x40, 0x00, // ELF header size
		0x38, 0x00, // Program header size
		0x00, 0x00, // Program header count
		0x40, 0x00, // Section header size
		0x00, 0x00, // Section header count
		0x00, 0x00, // String table index
	}

	// PE header for a simple PE file
	peHeader = []byte{
		0x4d, 0x5a, // MZ signature
		0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
		0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
		0x00, 0x00, 0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c,
		0xcd, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d,
		0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e,
		0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d,
		0x0d, 0x0a, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// PE signature
		0x50, 0x45, 0x00, 0x00,
		// COFF header
		0x64, 0x86, // Machine (x86-64)
		0x01, 0x00, // Number of sections
		0x00, 0x00, 0x00, 0x00, // Timestamp
		0x00, 0x00, 0x00, 0x00, // Symbol table offset
		0x00, 0x00, 0x00, 0x00, // Number of symbols
		0xf0, 0x00, // Optional header size
		0x22, 0x00, // Characteristics
	}

	// Mach-O header for a simple 64-bit Mach-O file
	machoHeader64 = []byte{
		0xcf, 0xfa, 0xed, 0xfe, // Mach-O 64-bit magic (little endian)
		0x07, 0x00, 0x00, 0x01, // CPU type (x86-64)
		0x03, 0x00, 0x00, 0x00, // CPU subtype
		0x02, 0x00, 0x00, 0x00, // File type (executable)
		0x00, 0x00, 0x00, 0x00, // Number of load commands
		0x00, 0x00, 0x00, 0x00, // Size of load commands
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // Reserved
	}
)

// Helper functions for creating test binaries

func createTempBinary(t *testing.T, data []byte, suffix string) string {
	tempFile, err := os.CreateTemp("", "test-binary-*"+suffix)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	
	if _, err := tempFile.Write(data); err != nil {
		tempFile.Close()
		os.Remove(tempFile.Name())
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	
	tempFile.Close()
	return tempFile.Name()
}

func createSimpleELF(t *testing.T) string {
	// Create a minimal ELF file with basic structure
	data := make([]byte, 1024)
	copy(data, elfHeader64)
	return createTempBinary(t, data, ".elf")
}

func createSimplePE(t *testing.T) string {
	// Create a minimal PE file with basic structure - just enough for format detection
	data := make([]byte, 1024)
	copy(data, peHeader)
	return createTempBinary(t, data, ".exe")
}

func createSimpleMachO(t *testing.T) string {
	// Create a minimal Mach-O file with basic structure
	data := make([]byte, 1024)
	copy(data, machoHeader64)
	return createTempBinary(t, data, ".macho")
}

func createUnknownBinary(t *testing.T) string {
	// Create a file with unknown format
	data := []byte("This is not a valid binary format")
	return createTempBinary(t, data, ".unknown")
}

// Tests for BinaryParser

func TestNewBinaryParser(t *testing.T) {
	parser := NewBinaryParser()
	if parser == nil {
		t.Fatal("NewBinaryParser() returned nil")
	}
}

func TestBinaryParser_DetectFormat(t *testing.T) {
	parser := NewBinaryParser()
	
	tests := []struct {
		name     string
		setup    func(t *testing.T) string
		expected BinaryFormat
	}{
		{
			name:     "ELF format",
			setup:    createSimpleELF,
			expected: FormatELF,
		},
		{
			name:     "PE format",
			setup:    createSimplePE,
			expected: FormatPE,
		},
		{
			name:     "Mach-O format",
			setup:    createSimpleMachO,
			expected: FormatMachO,
		},
		{
			name:     "Unknown format",
			setup:    createUnknownBinary,
			expected: FormatUnknown,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binaryPath := tt.setup(t)
			defer os.Remove(binaryPath)
			
			file, err := os.Open(binaryPath)
			if err != nil {
				t.Fatalf("Failed to open test file: %v", err)
			}
			defer file.Close()
			
			format, err := parser.detectFormat(file)
			if err != nil {
				t.Fatalf("detectFormat() error = %v", err)
			}
			
			if format != tt.expected {
				t.Errorf("detectFormat() = %v, want %v", format, tt.expected)
			}
		})
	}
}

func TestBinaryParser_ParseBinary(t *testing.T) {
	parser := NewBinaryParser()
	
	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr bool
		checks  func(t *testing.T, info *BinaryInfo)
	}{
		{
			name:    "ELF binary",
			setup:   createSimpleELF,
			wantErr: false,
			checks: func(t *testing.T, info *BinaryInfo) {
				if info.Format != FormatELF {
					t.Errorf("Expected format ELF, got %v", info.Format)
				}
				if info.FileSize == 0 {
					t.Error("Expected non-zero file size")
				}
			},
		},
		{
			name:    "PE binary",
			setup:   createSimplePE,
			wantErr: false,
			checks: func(t *testing.T, info *BinaryInfo) {
				if info.Format != FormatPE {
					t.Errorf("Expected format PE, got %v", info.Format)
				}
				if info.FileSize == 0 {
					t.Error("Expected non-zero file size")
				}
			},
		},
		{
			name:    "Mach-O binary",
			setup:   createSimpleMachO,
			wantErr: false,
			checks: func(t *testing.T, info *BinaryInfo) {
				if info.Format != FormatMachO {
					t.Errorf("Expected format Mach-O, got %v", info.Format)
				}
				if info.FileSize == 0 {
					t.Error("Expected non-zero file size")
				}
			},
		},
		{
			name:    "Unknown binary",
			setup:   createUnknownBinary,
			wantErr: false,
			checks: func(t *testing.T, info *BinaryInfo) {
				if info.Format != FormatUnknown {
					t.Errorf("Expected format Unknown, got %v", info.Format)
				}
			},
		},
		{
			name: "Non-existent file",
			setup: func(t *testing.T) string {
				return "/non/existent/file"
			},
			wantErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binaryPath := tt.setup(t)
			if !strings.Contains(binaryPath, "/non/existent/") {
				defer os.Remove(binaryPath)
			}
			
			info, err := parser.ParseBinary(binaryPath)
			
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			
			if err != nil {
				t.Fatalf("ParseBinary() error = %v", err)
			}
			
			if info == nil {
				t.Fatal("ParseBinary() returned nil info")
			}
			
			if tt.checks != nil {
				tt.checks(t, info)
			}
		})
	}
}

func TestBinaryParser_ReadCString(t *testing.T) {
	parser := NewBinaryParser()
	
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "simple string",
			data:     []byte("hello\x00world"),
			expected: "hello",
		},
		{
			name:     "empty string",
			data:     []byte("\x00hello"),
			expected: "",
		},
		{
			name:     "no null terminator",
			data:     []byte("hello"),
			expected: "hello",
		},
		{
			name:     "empty data",
			data:     []byte{},
			expected: "",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.readCString(tt.data)
			if result != tt.expected {
				t.Errorf("readCString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// Tests for FileSignatureCheck

func TestFileSignatureCheck_ID(t *testing.T) {
	check := &FileSignatureCheck{}
	expected := "check-1-file-signature"
	if check.ID() != expected {
		t.Errorf("ID() = %v, want %v", check.ID(), expected)
	}
}

func TestFileSignatureCheck_Description(t *testing.T) {
	check := &FileSignatureCheck{}
	desc := check.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
	if !strings.Contains(strings.ToLower(desc), "signature") {
		t.Error("Description() should mention signature")
	}
}

func TestFileSignatureCheck_Execute(t *testing.T) {
	check := &FileSignatureCheck{}
	
	tests := []struct {
		name           string
		setup          func(t *testing.T) string
		expectedStatus string
		checkMetadata  func(t *testing.T, metadata map[string]interface{})
	}{
		{
			name:           "valid ELF binary",
			setup:          createSimpleELF,
			expectedStatus: "pass",
			checkMetadata: func(t *testing.T, metadata map[string]interface{}) {
				if format, ok := metadata["format"]; !ok || format != string(FormatELF) {
					t.Errorf("Expected format ELF in metadata, got %v", format)
				}
			},
		},
		{
			name:           "valid PE binary",
			setup:          createSimplePE,
			expectedStatus: "pass",
			checkMetadata: func(t *testing.T, metadata map[string]interface{}) {
				if format, ok := metadata["format"]; !ok || format != string(FormatPE) {
					t.Errorf("Expected format PE in metadata, got %v", format)
				}
			},
		},
		{
			name:           "unknown format",
			setup:          createUnknownBinary,
			expectedStatus: "fail",
			checkMetadata: func(t *testing.T, metadata map[string]interface{}) {
				if format, ok := metadata["format"]; !ok || format != string(FormatUnknown) {
					t.Errorf("Expected format Unknown in metadata, got %v", format)
				}
			},
		},
		{
			name: "non-existent file",
			setup: func(t *testing.T) string {
				return "/non/existent/file"
			},
			expectedStatus: "fail",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binaryPath := tt.setup(t)
			if !strings.Contains(binaryPath, "/non/existent/") {
				defer os.Remove(binaryPath)
			}
			
			result := check.Execute(binaryPath)
			
			if result.ID != check.ID() {
				t.Errorf("Result ID = %v, want %v", result.ID, check.ID())
			}
			
			if result.Description != check.Description() {
				t.Errorf("Result Description = %v, want %v", result.Description, check.Description())
			}
			
			if result.Status != tt.expectedStatus {
				t.Errorf("Result Status = %v, want %v", result.Status, tt.expectedStatus)
			}
			
			if result.Details == "" {
				t.Error("Result Details should not be empty")
			}
			
			if result.Duration == 0 {
				t.Error("Result Duration should not be zero")
			}
			
			if tt.checkMetadata != nil {
				tt.checkMetadata(t, result.Metadata)
			}
		})
	}
}

// Tests for BinaryMetadataCheck

func TestBinaryMetadataCheck_ID(t *testing.T) {
	check := &BinaryMetadataCheck{}
	expected := "check-2-binary-metadata"
	if check.ID() != expected {
		t.Errorf("ID() = %v, want %v", check.ID(), expected)
	}
}

func TestBinaryMetadataCheck_Description(t *testing.T) {
	check := &BinaryMetadataCheck{}
	desc := check.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
	if !strings.Contains(strings.ToLower(desc), "metadata") {
		t.Error("Description() should mention metadata")
	}
}

func TestBinaryMetadataCheck_Execute(t *testing.T) {
	check := &BinaryMetadataCheck{}
	
	tests := []struct {
		name           string
		setup          func(t *testing.T) string
		expectedStatus string
		checkMetadata  func(t *testing.T, metadata map[string]interface{})
	}{
		{
			name:           "valid ELF binary",
			setup:          createSimpleELF,
			expectedStatus: "pass",
			checkMetadata: func(t *testing.T, metadata map[string]interface{}) {
				if arch, ok := metadata["architecture"]; !ok || arch == "" {
					t.Error("Expected architecture in metadata")
				}
				if bitness, ok := metadata["bitness"]; !ok || bitness == 0 {
					t.Error("Expected bitness in metadata")
				}
			},
		},
		{
			name:           "valid PE binary",
			setup:          createSimplePE,
			expectedStatus: "pass",
			checkMetadata: func(t *testing.T, metadata map[string]interface{}) {
				if arch, ok := metadata["architecture"]; !ok || arch == "" {
					t.Error("Expected architecture in metadata")
				}
			},
		},
		{
			name: "non-existent file",
			setup: func(t *testing.T) string {
				return "/non/existent/file"
			},
			expectedStatus: "fail",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binaryPath := tt.setup(t)
			if !strings.Contains(binaryPath, "/non/existent/") {
				defer os.Remove(binaryPath)
			}
			
			result := check.Execute(binaryPath)
			
			if result.Status != tt.expectedStatus {
				t.Errorf("Result Status = %v, want %v", result.Status, tt.expectedStatus)
			}
			
			if tt.checkMetadata != nil && result.Status == "pass" {
				tt.checkMetadata(t, result.Metadata)
			}
		})
	}
}

// Tests for DependencyAnalysisCheck

func TestDependencyAnalysisCheck_ID(t *testing.T) {
	check := &DependencyAnalysisCheck{}
	expected := "check-3-dependency-analysis"
	if check.ID() != expected {
		t.Errorf("ID() = %v, want %v", check.ID(), expected)
	}
}

func TestDependencyAnalysisCheck_Description(t *testing.T) {
	check := &DependencyAnalysisCheck{}
	desc := check.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
	if !strings.Contains(strings.ToLower(desc), "dependenc") {
		t.Error("Description() should mention dependencies")
	}
}

func TestDependencyAnalysisCheck_Execute(t *testing.T) {
	check := &DependencyAnalysisCheck{}
	
	tests := []struct {
		name           string
		setup          func(t *testing.T) string
		expectedStatus string
		checkMetadata  func(t *testing.T, metadata map[string]interface{})
	}{
		{
			name:           "valid binary with no dependencies",
			setup:          createSimpleELF,
			expectedStatus: "pass",
			checkMetadata: func(t *testing.T, metadata map[string]interface{}) {
				if count, ok := metadata["dependency_count"]; !ok || count != 0 {
					t.Errorf("Expected dependency_count 0, got %v", count)
				}
			},
		},
		{
			name: "non-existent file",
			setup: func(t *testing.T) string {
				return "/non/existent/file"
			},
			expectedStatus: "fail",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binaryPath := tt.setup(t)
			if !strings.Contains(binaryPath, "/non/existent/") {
				defer os.Remove(binaryPath)
			}
			
			result := check.Execute(binaryPath)
			
			if result.Status != tt.expectedStatus {
				t.Errorf("Result Status = %v, want %v", result.Status, tt.expectedStatus)
			}
			
			if tt.checkMetadata != nil && result.Status == "pass" {
				tt.checkMetadata(t, result.Metadata)
			}
		})
	}
}

// Tests for BinaryFormatCheck

func TestBinaryFormatCheck_ID(t *testing.T) {
	check := &BinaryFormatCheck{}
	expected := "check-4-binary-format"
	if check.ID() != expected {
		t.Errorf("ID() = %v, want %v", check.ID(), expected)
	}
}

func TestBinaryFormatCheck_Description(t *testing.T) {
	check := &BinaryFormatCheck{}
	desc := check.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
	if !strings.Contains(strings.ToLower(desc), "format") {
		t.Error("Description() should mention format")
	}
}

func TestBinaryFormatCheck_Execute(t *testing.T) {
	check := &BinaryFormatCheck{}
	
	tests := []struct {
		name           string
		setup          func(t *testing.T) string
		expectedStatus string
	}{
		{
			name:           "valid ELF binary",
			setup:          createSimpleELF,
			expectedStatus: "pass",
		},
		{
			name:           "valid PE binary",
			setup:          createSimplePE,
			expectedStatus: "pass",
		},
		{
			name:           "unknown format",
			setup:          createUnknownBinary,
			expectedStatus: "fail",
		},
		{
			name: "non-existent file",
			setup: func(t *testing.T) string {
				return "/non/existent/file"
			},
			expectedStatus: "fail",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binaryPath := tt.setup(t)
			if !strings.Contains(binaryPath, "/non/existent/") {
				defer os.Remove(binaryPath)
			}
			
			result := check.Execute(binaryPath)
			
			if result.Status != tt.expectedStatus {
				t.Errorf("Result Status = %v, want %v", result.Status, tt.expectedStatus)
			}
		})
	}
}

// Integration tests

func TestBinaryAnalysisIntegration(t *testing.T) {
	// Create a registry and register all binary analysis checks
	registry := NewCheckRegistry()
	
	checks := []ComplianceCheck{
		&FileSignatureCheck{},
		&BinaryMetadataCheck{},
		&DependencyAnalysisCheck{},
		&BinaryFormatCheck{},
	}
	
	for _, check := range checks {
		if err := registry.Register(check); err != nil {
			t.Fatalf("Failed to register check %s: %v", check.ID(), err)
		}
	}
	
	// Test with different binary formats
	testCases := []struct {
		name           string
		setup          func(t *testing.T) string
		expectedPassed int
		expectedFailed int
	}{
		{
			name:           "ELF binary",
			setup:          createSimpleELF,
			expectedPassed: 4,
			expectedFailed: 0,
		},
		{
			name:           "PE binary",
			setup:          createSimplePE,
			expectedPassed: 4,
			expectedFailed: 0,
		},
		{
			name:           "Unknown binary",
			setup:          createUnknownBinary,
			expectedPassed: 1, // Only dependency analysis might pass
			expectedFailed: 3,
		},
	}
	
	runner := NewCheckRunner(registry)
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			binaryPath := tc.setup(t)
			defer os.Remove(binaryPath)
			
			report, err := runner.RunAll(binaryPath)
			if err != nil {
				t.Fatalf("RunAll() error = %v", err)
			}
			
			if report.TotalChecks != 4 {
				t.Errorf("Expected 4 total checks, got %d", report.TotalChecks)
			}
			
			if report.PassedChecks != tc.expectedPassed {
				t.Errorf("Expected %d passed checks, got %d", tc.expectedPassed, report.PassedChecks)
			}
			
			if report.FailedChecks != tc.expectedFailed {
				t.Errorf("Expected %d failed checks, got %d", tc.expectedFailed, report.FailedChecks)
			}
			
			// Verify all results have required fields
			for _, result := range report.Results {
				if result.ID == "" {
					t.Error("Result missing ID")
				}
				if result.Description == "" {
					t.Error("Result missing Description")
				}
				if result.Status != "pass" && result.Status != "fail" {
					t.Errorf("Invalid result status: %s", result.Status)
				}
				if result.Details == "" {
					t.Error("Result missing Details")
				}
				if result.Duration == 0 {
					t.Error("Result missing Duration")
				}
			}
		})
	}
}

// Benchmark tests

func BenchmarkFileSignatureCheck(b *testing.B) {
	check := &FileSignatureCheck{}
	binaryPath := createSimpleELF(&testing.T{})
	defer os.Remove(binaryPath)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		check.Execute(binaryPath)
	}
}

func BenchmarkBinaryMetadataCheck(b *testing.B) {
	check := &BinaryMetadataCheck{}
	binaryPath := createSimpleELF(&testing.T{})
	defer os.Remove(binaryPath)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		check.Execute(binaryPath)
	}
}

func BenchmarkDependencyAnalysisCheck(b *testing.B) {
	check := &DependencyAnalysisCheck{}
	binaryPath := createSimpleELF(&testing.T{})
	defer os.Remove(binaryPath)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		check.Execute(binaryPath)
	}
}

func BenchmarkBinaryFormatCheck(b *testing.B) {
	check := &BinaryFormatCheck{}
	binaryPath := createSimpleELF(&testing.T{})
	defer os.Remove(binaryPath)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		check.Execute(binaryPath)
	}
}