package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	
	"github.com/raven-betanet/dual-cli/internal/checks"
	"github.com/raven-betanet/dual-cli/internal/sbom"
	"github.com/raven-betanet/dual-cli/internal/utils"
)

var (
	// Version information (set via ldflags during build)
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "raven-linter",
		Short: "Raven Betanet 1.1 compliance linter",
		Long: `raven-linter validates binaries against all 11 compliance checks from §11 of the 
Raven Betanet 1.1 specification and generates Software Bill of Materials (SBOM) in 
industry-standard formats.

The tool performs comprehensive binary analysis including:
- Binary format validation (ELF, PE, Mach-O)
- Architecture and metadata extraction  
- Dependency analysis
- Cryptographic validation
- Security flag analysis
- License compliance checking

Results can be output in human-readable text or machine-readable JSON formats
for integration with CI/CD pipelines.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, buildDate),
	}

	// Add subcommands
	cmd.AddCommand(newCheckCmd())
	cmd.AddCommand(newVersionCmd())

	return cmd
}

func newCheckCmd() *cobra.Command {
	var (
		outputFormat string
		generateSBOM bool
		sbomFormat   string
		configFile   string
		verbose      bool
	)

	cmd := &cobra.Command{
		Use:   "check <binary>",
		Short: "Run compliance checks against a binary",
		Long: `Run all 11 compliance checks from Raven Betanet 1.1 §11 against the specified binary.

The check command validates:
1. Binary format validation (ELF, PE, Mach-O detection)
2. Architecture validation (extract architecture info)
3. Entry point & section validation (verify .text/.data sections)
4. Dependency analysis (list linked libraries)
5. Certificate presence (extract embedded certificates)
6. Certificate validity (validate against system roots)
7. Digital signature verification (verify binary signatures)
8. Hash verification (SHA256/SHA512 integrity checks)
9. Security flags (NX, RELRO, PIE for ELF; DEP, ASLR for PE)
10. Version metadata (extract version information)
11. License compliance (scan for license information)

Exit codes:
  0 - All checks passed
  1 - One or more checks failed
  2 - Invalid arguments or configuration error`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runComplianceChecks(args[0], outputFormat, generateSBOM, sbomFormat, configFile, verbose)
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format (text, json)")
	cmd.Flags().BoolVar(&generateSBOM, "sbom", false, "Generate SBOM file")
	cmd.Flags().StringVar(&sbomFormat, "sbom-format", "cyclonedx", "SBOM format (cyclonedx, spdx)")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "Configuration file path")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("raven-linter version %s\n", version)
			fmt.Printf("Commit: %s\n", commit)
			fmt.Printf("Built: %s\n", buildDate)
		},
	}
}

// runComplianceChecks executes all compliance checks and generates SBOM if requested
func runComplianceChecks(binaryPath, outputFormat string, generateSBOM bool, sbomFormat, configFile string, verbose bool) error {
	// Load configuration
	var config *utils.Config
	var err error
	
	if configFile != "" {
		config, err = utils.LoadConfigFromFile(configFile)
	} else {
		config, err = utils.LoadDefaultConfig()
	}
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	
	// Create logger
	loggerConfig := utils.LoggerConfig{
		Level:  utils.LogLevel(config.LogLevel),
		Format: utils.LogFormat(config.LogFormat),
	}
	if verbose {
		loggerConfig.Level = utils.LogLevelDebug
	}
	logger := utils.NewLogger(loggerConfig)
	
	// Validate binary file exists
	if _, err := os.Stat(binaryPath); err != nil {
		return fmt.Errorf("binary file not found: %s", binaryPath)
	}
	
	logger.WithComponent("raven-linter").Infof("Starting compliance checks for: %s", binaryPath)
	
	// Create check registry and register all checks
	registry := checks.NewCheckRegistry()
	
	// Register all 11 compliance checks
	allChecks := []checks.ComplianceCheck{
		// Binary analysis checks (1-4)
		&checks.FileSignatureCheck{},
		&checks.BinaryMetadataCheck{},
		&checks.DependencyAnalysisCheck{},
		&checks.BinaryFormatCheck{},
		
		// Cryptographic validation checks (5-8)
		&checks.CertificateValidationCheck{},
		&checks.SignatureVerificationCheck{},
		&checks.HashIntegrityCheck{},
		&checks.EncryptionStandardCheck{},
		
		// Security and metadata checks (9-11)
		&checks.SecurityFlagValidationCheck{},
		&checks.VersionInformationCheck{},
		&checks.LicenseComplianceCheck{},
	}
	
	for _, check := range allChecks {
		if err := registry.Register(check); err != nil {
			return fmt.Errorf("failed to register check %s: %w", check.ID(), err)
		}
	}
	
	// Create check runner and execute all checks
	runner := checks.NewCheckRunner(registry)
	report, err := runner.RunAll(binaryPath)
	if err != nil {
		return fmt.Errorf("failed to run compliance checks: %w", err)
	}
	
	// Generate SBOM if requested
	var sbomInfo *sbom.SBOMInfo
	if generateSBOM {
		sbomInfo, err = generateSBOMFile(binaryPath, sbomFormat, logger)
		if err != nil {
			logger.WithComponent("raven-linter").Warnf("SBOM generation failed: %v", err)
			// Continue with compliance checks even if SBOM fails
		}
	}
	
	// Output results
	if err := outputResults(report, sbomInfo, outputFormat); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}
	
	// Determine exit code based on results
	if report.FailedChecks > 0 {
		logger.WithComponent("raven-linter").Errorf("Compliance checks failed: %d/%d checks passed", 
			report.PassedChecks, report.TotalChecks)
		os.Exit(1)
	}
	
	logger.WithComponent("raven-linter").Infof("All compliance checks passed: %d/%d", 
		report.PassedChecks, report.TotalChecks)
	return nil
}

// generateSBOMFile generates an SBOM file in the specified format
func generateSBOMFile(binaryPath, format string, logger *utils.Logger) (*sbom.SBOMInfo, error) {
	logger.WithComponent("sbom").Infof("Generating SBOM in %s format", format)
	
	// Create SBOM generator
	generator := sbom.NewGenerator()
	
	// Determine SBOM format
	var sbomFormat sbom.SBOMFormat
	switch format {
	case "cyclonedx":
		sbomFormat = sbom.FormatCycloneDX
	case "spdx":
		sbomFormat = sbom.FormatSPDX
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %s", format)
	}
	
	// Generate SBOM
	generatedSBOM, err := generator.Generate(binaryPath, sbomFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SBOM: %w", err)
	}
	
	// Create output filename
	outputPath := fmt.Sprintf("sbom.%s.json", format)
	
	// Write SBOM to file
	if err := generator.WriteToFile(generatedSBOM, outputPath); err != nil {
		return nil, fmt.Errorf("failed to write SBOM file: %w", err)
	}
	
	// Get file info
	fileInfo, err := os.Stat(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get SBOM file info: %w", err)
	}
	
	logger.WithComponent("sbom").Infof("SBOM generated successfully: %s", outputPath)
	
	return &sbom.SBOMInfo{
		Format:     format,
		Version:    "1.0",
		FilePath:   outputPath,
		Size:       fileInfo.Size(),
		Components: len(generatedSBOM.Components),
		Generated:  time.Now(),
		Valid:      true,
	}, nil
}

// outputResults outputs the compliance check results in the specified format
func outputResults(report *checks.CheckReport, sbomInfo *sbom.SBOMInfo, format string) error {
	switch format {
	case "json":
		return outputJSON(report, sbomInfo)
	case "text":
		return outputText(report, sbomInfo)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// outputJSON outputs results in JSON format
func outputJSON(report *checks.CheckReport, sbomInfo *sbom.SBOMInfo) error {
	output := map[string]interface{}{
		"summary": map[string]interface{}{
			"total_checks":  report.TotalChecks,
			"passed_checks": report.PassedChecks,
			"failed_checks": report.FailedChecks,
			"binary_path":   report.BinaryPath,
			"timestamp":     time.Now().Format(time.RFC3339),
		},
		"checks": report.Results,
	}
	
	if sbomInfo != nil {
		output["sbom"] = sbomInfo
	}
	
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// outputText outputs results in human-readable text format
func outputText(report *checks.CheckReport, sbomInfo *sbom.SBOMInfo) error {
	fmt.Printf("Raven Betanet 1.1 Compliance Check Report\n")
	fmt.Printf("========================================\n\n")
	fmt.Printf("Binary: %s\n", report.BinaryPath)
	fmt.Printf("Timestamp: %s\n\n", time.Now().Format(time.RFC3339))
	
	fmt.Printf("Summary:\n")
	fmt.Printf("  Total checks: %d\n", report.TotalChecks)
	fmt.Printf("  Passed: %d\n", report.PassedChecks)
	fmt.Printf("  Failed: %d\n", report.FailedChecks)
	fmt.Printf("  Overall status: ")
	
	if report.FailedChecks == 0 {
		fmt.Printf("✅ PASS\n\n")
	} else {
		fmt.Printf("❌ FAIL\n\n")
	}
	
	fmt.Printf("Check Details:\n")
	fmt.Printf("--------------\n")
	
	for _, result := range report.Results {
		status := "✅ PASS"
		if result.Status == "fail" {
			status = "❌ FAIL"
		} else if result.Status == "skip" {
			status = "⏭️  SKIP"
		} else if result.Status == "error" {
			status = "⚠️  ERROR"
		}
		
		fmt.Printf("%s %s: %s\n", status, result.ID, result.Description)
		if result.Details != nil {
			fmt.Printf("    Details: %v\n", result.Details)
		}
		if result.Duration > 0 {
			fmt.Printf("    Duration: %v\n", result.Duration)
		}
		fmt.Printf("\n")
	}
	
	if sbomInfo != nil {
		fmt.Printf("SBOM Information:\n")
		fmt.Printf("-----------------\n")
		fmt.Printf("  Format: %s\n", sbomInfo.Format)
		fmt.Printf("  File: %s\n", sbomInfo.FilePath)
		fmt.Printf("  Size: %d bytes\n", sbomInfo.Size)
		fmt.Printf("  Components: %d\n", sbomInfo.Components)
		fmt.Printf("  Generated: %s\n", sbomInfo.Generated.Format(time.RFC3339))
		fmt.Printf("\n")
	}
	
	return nil
}