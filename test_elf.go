package main

import (
	"debug/elf"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run test_elf.go <elf-file>")
		os.Exit(1)
	}
	
	f, err := elf.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	
	fmt.Printf("ELF file opened successfully:\n")
	fmt.Printf("  Machine: %s\n", f.Machine)
	fmt.Printf("  Class: %s\n", f.Class)
	fmt.Printf("  Data: %s\n", f.Data)
	fmt.Printf("  Type: %s\n", f.Type)
}