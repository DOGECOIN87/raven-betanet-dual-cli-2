package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	dir := "."
	
	// Generate valid ELF binary
	if err := generateValidELF(filepath.Join(dir, "valid_elf_binary")); err != nil {
		fmt.Printf("Error generating valid ELF: %v\n", err)
	}
	
	// Generate invalid ELF binary
	if err := generateInvalidELF(filepath.Join(dir, "invalid_elf_binary")); err != nil {
		fmt.Printf("Error generating invalid ELF: %v\n", err)
	}
	
	// Generate corrupted binary
	if err := generateCorruptedBinary(filepath.Join(dir, "corrupted_binary")); err != nil {
		fmt.Printf("Error generating corrupted binary: %v\n", err)
	}
	
	// Generate large binary for performance testing
	if err := generateLargeBinary(filepath.Join(dir, "large_binary")); err != nil {
		fmt.Printf("Error generating large binary: %v\n", err)
	}
	
	// Generate platform-specific binaries
	if err := generatePlatformSpecificBinaries(dir); err != nil {
		fmt.Printf("Error generating platform-specific binaries: %v\n", err)
	}
	
	// Generate cross-architecture test binaries
	if err := generateCrossArchBinaries(dir); err != nil {
		fmt.Printf("Error generating cross-architecture binaries: %v\n", err)
	}
	
	fmt.Println("Test binaries generated successfully")
}

func generateValidELF(filename string) error {
	// Create a minimal valid ELF header
	header := elf.Header64{
		Ident:     [16]uint8{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		Type:      uint16(elf.ET_EXEC),
		Machine:   uint16(elf.EM_X86_64),
		Version:   uint32(elf.EV_CURRENT),
		Entry:     0x400000,
		Phoff:     64,
		Shoff:     0,
		Flags:     0,
		Ehsize:    64,
		Phentsize: 56,
		Phnum:     1,
		Shentsize: 0,
		Shnum:     0,
		Shstrndx:  0,
	}
	
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Write ELF header
	if err := binary.Write(file, binary.LittleEndian, header); err != nil {
		return err
	}
	
	// Write minimal program header
	phdr := elf.Prog64{
		Type:   uint32(elf.PT_LOAD),
		Flags:  uint32(elf.PF_X | elf.PF_R),
		Off:    0,
		Vaddr:  0x400000,
		Paddr:  0x400000,
		Filesz: 120,
		Memsz:  120,
		Align:  0x1000,
	}
	
	if err := binary.Write(file, binary.LittleEndian, phdr); err != nil {
		return err
	}
	
	// Make file executable
	return os.Chmod(filename, 0755)
}

func generateInvalidELF(filename string) error {
	// Create an ELF with invalid magic bytes
	header := elf.Header64{
		Ident:     [16]uint8{0x7f, 'X', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // Invalid magic
		Type:      uint16(elf.ET_EXEC),
		Machine:   uint16(elf.EM_X86_64),
		Version:   uint32(elf.EV_CURRENT),
		Entry:     0x400000,
		Phoff:     64,
		Shoff:     0,
		Flags:     0,
		Ehsize:    64,
		Phentsize: 56,
		Phnum:     1,
		Shentsize: 0,
		Shnum:     0,
		Shstrndx:  0,
	}
	
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	return binary.Write(file, binary.LittleEndian, header)
}

func generateCorruptedBinary(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Write random bytes that don't form a valid binary
	corruptedData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
	_, err = file.Write(corruptedData)
	return err
}

func generateLargeBinary(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Start with a valid ELF header
	if err := generateValidELF(filename); err != nil {
		return err
	}
	
	// Reopen and append data to make it large
	file, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Write 1MB of padding data (reduced size for GitHub)
	padding := make([]byte, 1024*1024)
	for i := 0; i < 10; i++ { // 10MB total (within GitHub limits)
		if _, err := file.Write(padding); err != nil {
			return err
		}
	}
	
	return nil
}

// generatePlatformSpecificBinaries generates binaries for different platforms
func generatePlatformSpecificBinaries(dir string) error {
	// Generate PE binary (Windows)
	if err := generateValidPE(filepath.Join(dir, "valid_pe_binary.exe")); err != nil {
		fmt.Printf("Warning: Could not generate PE binary: %v\n", err)
	}
	
	// Generate Mach-O binary (macOS)
	if err := generateValidMachO(filepath.Join(dir, "valid_macho_binary")); err != nil {
		fmt.Printf("Warning: Could not generate Mach-O binary: %v\n", err)
	}
	
	// Generate ELF binaries for different architectures
	if err := generateELFArm64(filepath.Join(dir, "valid_elf_arm64_binary")); err != nil {
		fmt.Printf("Warning: Could not generate ARM64 ELF binary: %v\n", err)
	}
	
	if err := generateELF32(filepath.Join(dir, "valid_elf_32bit_binary")); err != nil {
		fmt.Printf("Warning: Could not generate 32-bit ELF binary: %v\n", err)
	}
	
	return nil
}

// generateCrossArchBinaries generates test binaries for different architectures
func generateCrossArchBinaries(dir string) error {
	architectures := []struct {
		name    string
		machine uint16
		class   uint8
	}{
		{"x86_64", uint16(elf.EM_X86_64), 2}, // 64-bit
		{"i386", uint16(elf.EM_386), 1},      // 32-bit
		{"arm64", uint16(elf.EM_AARCH64), 2}, // ARM 64-bit
		{"arm", uint16(elf.EM_ARM), 1},       // ARM 32-bit
	}
	
	for _, arch := range architectures {
		filename := filepath.Join(dir, fmt.Sprintf("test_%s_binary", arch.name))
		if err := generateELFForArch(filename, arch.machine, arch.class); err != nil {
			fmt.Printf("Warning: Could not generate %s binary: %v\n", arch.name, err)
		}
	}
	
	return nil
}

// generateValidPE generates a minimal valid PE binary
func generateValidPE(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// DOS header
	dosHeader := []byte{
		'M', 'Z',                           // e_magic
		0x90, 0x00,                         // e_cblp
		0x03, 0x00,                         // e_cp
		0x00, 0x00,                         // e_crlc
		0x04, 0x00,                         // e_cparhdr
		0x00, 0x00,                         // e_minalloc
		0xFF, 0xFF,                         // e_maxalloc
		0x00, 0x00,                         // e_ss
		0xB8, 0x00,                         // e_sp
		0x00, 0x00,                         // e_csum
		0x00, 0x00,                         // e_ip
		0x00, 0x00,                         // e_cs
		0x40, 0x00,                         // e_lfarlc
		0x00, 0x00,                         // e_ovno
		0x00, 0x00, 0x00, 0x00,             // e_res[4]
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,                         // e_oemid
		0x00, 0x00,                         // e_oeminfo
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_res2[10]
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x80, 0x00, 0x00, 0x00,             // e_lfanew (PE header offset)
	}
	
	// Pad to 128 bytes
	for len(dosHeader) < 128 {
		dosHeader = append(dosHeader, 0x00)
	}
	
	if _, err := file.Write(dosHeader); err != nil {
		return err
	}
	
	// PE signature
	peSignature := []byte{'P', 'E', 0x00, 0x00}
	if _, err := file.Write(peSignature); err != nil {
		return err
	}
	
	// COFF header
	coffHeader := []byte{
		0x64, 0x86,                         // Machine (IMAGE_FILE_MACHINE_AMD64)
		0x01, 0x00,                         // NumberOfSections
		0x00, 0x00, 0x00, 0x00,             // TimeDateStamp
		0x00, 0x00, 0x00, 0x00,             // PointerToSymbolTable
		0x00, 0x00, 0x00, 0x00,             // NumberOfSymbols
		0xF0, 0x00,                         // SizeOfOptionalHeader
		0x02, 0x00,                         // Characteristics
	}
	
	if _, err := file.Write(coffHeader); err != nil {
		return err
	}
	
	// Optional header (simplified)
	optionalHeader := make([]byte, 240) // SizeOfOptionalHeader
	optionalHeader[0] = 0x0B            // Magic (PE32+)
	optionalHeader[1] = 0x02
	
	if _, err := file.Write(optionalHeader); err != nil {
		return err
	}
	
	// Section header
	sectionHeader := make([]byte, 40)
	copy(sectionHeader[0:8], []byte(".text\x00\x00\x00")) // Name
	
	if _, err := file.Write(sectionHeader); err != nil {
		return err
	}
	
	return os.Chmod(filename, 0755)
}

// generateValidMachO generates a minimal valid Mach-O binary
func generateValidMachO(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Mach-O header (64-bit)
	header := []byte{
		0xFE, 0xED, 0xFA, 0xCF,             // magic (MH_MAGIC_64)
		0x07, 0x00, 0x00, 0x01,             // cputype (CPU_TYPE_X86_64)
		0x03, 0x00, 0x00, 0x00,             // cpusubtype
		0x02, 0x00, 0x00, 0x00,             // filetype (MH_EXECUTE)
		0x01, 0x00, 0x00, 0x00,             // ncmds
		0x38, 0x00, 0x00, 0x00,             // sizeofcmds
		0x00, 0x00, 0x00, 0x00,             // flags
		0x00, 0x00, 0x00, 0x00,             // reserved
	}
	
	if _, err := file.Write(header); err != nil {
		return err
	}
	
	// Load command (LC_SEGMENT_64)
	loadCommand := []byte{
		0x19, 0x00, 0x00, 0x00,             // cmd (LC_SEGMENT_64)
		0x38, 0x00, 0x00, 0x00,             // cmdsize
	}
	
	// Segment name (__TEXT)
	segmentName := make([]byte, 16)
	copy(segmentName, []byte("__TEXT"))
	loadCommand = append(loadCommand, segmentName...)
	
	// VM address and size
	vmAddr := make([]byte, 8)
	binary.LittleEndian.PutUint64(vmAddr, 0x100000000)
	loadCommand = append(loadCommand, vmAddr...)
	
	vmSize := make([]byte, 8)
	binary.LittleEndian.PutUint64(vmSize, 0x1000)
	loadCommand = append(loadCommand, vmSize...)
	
	// File offset and size
	fileOff := make([]byte, 8)
	loadCommand = append(loadCommand, fileOff...)
	
	fileSize := make([]byte, 8)
	binary.LittleEndian.PutUint64(fileSize, 0x1000)
	loadCommand = append(loadCommand, fileSize...)
	
	// Pad to cmdsize
	for len(loadCommand) < 56 {
		loadCommand = append(loadCommand, 0x00)
	}
	
	if _, err := file.Write(loadCommand); err != nil {
		return err
	}
	
	return os.Chmod(filename, 0755)
}

// generateELFArm64 generates an ARM64 ELF binary
func generateELFArm64(filename string) error {
	return generateELFForArch(filename, uint16(elf.EM_AARCH64), 2)
}

// generateELF32 generates a 32-bit ELF binary
func generateELF32(filename string) error {
	return generateELFForArch(filename, uint16(elf.EM_386), 1)
}

// generateELFForArch generates an ELF binary for specific architecture
func generateELFForArch(filename string, machine uint16, class uint8) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	if class == 1 {
		// 32-bit ELF
		header := elf.Header32{
			Ident:     [16]uint8{0x7f, 'E', 'L', 'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Type:      uint16(elf.ET_EXEC),
			Machine:   machine,
			Version:   uint32(elf.EV_CURRENT),
			Entry:     0x8048000,
			Phoff:     52,
			Shoff:     0,
			Flags:     0,
			Ehsize:    52,
			Phentsize: 32,
			Phnum:     1,
			Shentsize: 0,
			Shnum:     0,
			Shstrndx:  0,
		}
		
		if err := binary.Write(file, binary.LittleEndian, header); err != nil {
			return err
		}
		
		// Program header
		phdr := elf.Prog32{
			Type:   uint32(elf.PT_LOAD),
			Off:    0,
			Vaddr:  0x8048000,
			Paddr:  0x8048000,
			Filesz: 84,
			Memsz:  84,
			Flags:  uint32(elf.PF_X | elf.PF_R),
			Align:  0x1000,
		}
		
		if err := binary.Write(file, binary.LittleEndian, phdr); err != nil {
			return err
		}
	} else {
		// 64-bit ELF
		header := elf.Header64{
			Ident:     [16]uint8{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Type:      uint16(elf.ET_EXEC),
			Machine:   machine,
			Version:   uint32(elf.EV_CURRENT),
			Entry:     0x400000,
			Phoff:     64,
			Shoff:     0,
			Flags:     0,
			Ehsize:    64,
			Phentsize: 56,
			Phnum:     1,
			Shentsize: 0,
			Shnum:     0,
			Shstrndx:  0,
		}
		
		if err := binary.Write(file, binary.LittleEndian, header); err != nil {
			return err
		}
		
		// Program header
		phdr := elf.Prog64{
			Type:   uint32(elf.PT_LOAD),
			Flags:  uint32(elf.PF_X | elf.PF_R),
			Off:    0,
			Vaddr:  0x400000,
			Paddr:  0x400000,
			Filesz: 120,
			Memsz:  120,
			Align:  0x1000,
		}
		
		if err := binary.Write(file, binary.LittleEndian, phdr); err != nil {
			return err
		}
	}
	
	return os.Chmod(filename, 0755)
}