package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	// Create the sample_binaries directory if it doesn't exist
	dir := "."
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	// Create a simple Go program
	goSource := `package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Printf("Hello from test binary! Args: %v\n", os.Args[1:])
}`

	// Write the Go source file
	sourceFile := filepath.Join(dir, "test_program.go")
	err := os.WriteFile(sourceFile, []byte(goSource), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write Go source: %v\n", err)
		os.Exit(1)
	}

	// Build the test binary
	binaryPath := filepath.Join(dir, "valid_elf_binary")
	cmd := exec.Command("go", "build", "-o", binaryPath, sourceFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build test binary: %v\nOutput: %s\n", err, output)
		os.Exit(1)
	}

	// Create an invalid binary (just text)
	invalidBinaryPath := filepath.Join(dir, "invalid_binary")
	invalidContent := "This is not a valid binary file - just plain text content for testing"
	err = os.WriteFile(invalidBinaryPath, []byte(invalidContent), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create invalid binary: %v\n", err)
		os.Exit(1)
	}

	// Create a corrupted ELF binary (starts with ELF magic but is incomplete)
	corruptedBinaryPath := filepath.Join(dir, "corrupted_elf_binary")
	corruptedContent := []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00} // ELF header start
	corruptedContent = append(corruptedContent, []byte("corrupted data follows")...)
	err = os.WriteFile(corruptedBinaryPath, corruptedContent, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create corrupted binary: %v\n", err)
		os.Exit(1)
	}

	// Create a minimal PE header for Windows testing (even on non-Windows systems)
	peBinaryPath := filepath.Join(dir, "minimal_pe_binary")
	peContent := []byte{'M', 'Z'} // PE magic
	peContent = append(peContent, make([]byte, 58)...) // Pad to offset 60
	peContent = append(peContent, []byte{0x40, 0x00, 0x00, 0x00}...) // PE header offset
	peContent = append(peContent, make([]byte, 60)...) // Pad to PE header location
	peContent = append(peContent, []byte{'P', 'E', 0x00, 0x00}...) // PE signature
	peContent = append(peContent, []byte{0x4c, 0x01}...) // Machine type (i386)
	peContent = append(peContent, make([]byte, 100)...) // Minimal PE structure
	err = os.WriteFile(peBinaryPath, peContent, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create PE binary: %v\n", err)
		os.Exit(1)
	}

	// Create a minimal Mach-O header for macOS testing
	machoBinaryPath := filepath.Join(dir, "minimal_macho_binary")
	machoContent := []byte{0xfe, 0xed, 0xfa, 0xce} // Mach-O magic (32-bit big endian)
	machoContent = append(machoContent, []byte{0x00, 0x00, 0x00, 0x07}...) // CPU type (i386)
	machoContent = append(machoContent, []byte{0x00, 0x00, 0x00, 0x03}...) // CPU subtype
	machoContent = append(machoContent, []byte{0x00, 0x00, 0x00, 0x02}...) // File type (executable)
	machoContent = append(machoContent, make([]byte, 100)...) // Minimal Mach-O structure
	err = os.WriteFile(machoBinaryPath, machoContent, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create Mach-O binary: %v\n", err)
		os.Exit(1)
	}

	// Clean up the Go source file
	os.Remove(sourceFile)

	fmt.Println("Created test binaries:")
	fmt.Printf("  - %s (valid ELF binary)\n", binaryPath)
	fmt.Printf("  - %s (invalid binary)\n", invalidBinaryPath)
	fmt.Printf("  - %s (corrupted ELF binary)\n", corruptedBinaryPath)
	fmt.Printf("  - %s (minimal PE binary)\n", peBinaryPath)
	fmt.Printf("  - %s (minimal Mach-O binary)\n", machoBinaryPath)
}