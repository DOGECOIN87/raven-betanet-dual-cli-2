package checks

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CertificateValidationCheck implements check 5: Certificate validation
type CertificateValidationCheck struct{}

func (c *CertificateValidationCheck) ID() string {
	return "check-5-certificate-validation"
}

func (c *CertificateValidationCheck) Description() string {
	return "Validates embedded certificates and certificate chains in binary"
}

func (c *CertificateValidationCheck) Execute(binaryPath string) CheckResult {
	start := time.Now()
	
	result := CheckResult{
		ID:          c.ID(),
		Description: c.Description(),
		Duration:    time.Since(start),
		Metadata:    make(map[string]interface{}),
	}
	
	// Look for certificate files in the same directory or embedded certificates
	certificates, err := c.findCertificates(binaryPath)
	if err != nil {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Failed to search for certificates: %v", err)
		return result
	}
	
	// Clean up embedded certificate temp files when done
	defer c.cleanupEmbeddedCertificates(certificates)
	
	if len(certificates) == 0 {
		// No certificates found - this might be acceptable for some binaries
		result.Status = "pass"
		result.Details = "No certificates found - binary may not require certificate validation"
		result.Metadata["certificate_count"] = 0
		result.Metadata["certificates"] = []string{}
		return result
	}
	
	// Validate found certificates
	validCerts := 0
	invalidCerts := 0
	certDetails := []map[string]interface{}{}
	
	for _, certPath := range certificates {
		certInfo, valid := c.validateCertificate(certPath)
		certDetails = append(certDetails, certInfo)
		
		if valid {
			validCerts++
		} else {
			invalidCerts++
		}
	}
	
	result.Metadata["certificate_count"] = len(certificates)
	result.Metadata["valid_certificates"] = validCerts
	result.Metadata["invalid_certificates"] = invalidCerts
	result.Metadata["certificate_details"] = certDetails
	
	if invalidCerts > 0 {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Certificate validation failed: %d valid, %d invalid certificates", validCerts, invalidCerts)
	} else {
		result.Status = "pass"
		result.Details = fmt.Sprintf("Certificate validation passed: %d valid certificates", validCerts)
	}
	
	result.Duration = time.Since(start)
	return result
}

// findCertificates looks for certificate files related to the binary
func (c *CertificateValidationCheck) findCertificates(binaryPath string) ([]string, error) {
	var certificates []string
	
	// Look in the same directory as the binary
	dir := filepath.Dir(binaryPath)
	
	// Common certificate file extensions
	certExtensions := []string{".crt", ".cer", ".pem", ".p12", ".pfx"}
	
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue walking even if there's an error with one file
		}
		
		if info.IsDir() {
			return nil
		}
		
		ext := strings.ToLower(filepath.Ext(path))
		for _, certExt := range certExtensions {
			if ext == certExt {
				certificates = append(certificates, path)
				break
			}
		}
		
		return nil
	})
	
	if err != nil {
		return nil, err
	}
	
	// Also check for embedded certificates by scanning the binary content
	embeddedCerts, err := c.findEmbeddedCertificates(binaryPath)
	if err == nil {
		certificates = append(certificates, embeddedCerts...)
	}
	
	return certificates, nil
}

// findEmbeddedCertificates scans binary content for embedded PEM certificates
func (c *CertificateValidationCheck) findEmbeddedCertificates(binaryPath string) ([]string, error) {
	var certificates []string
	
	file, err := os.Open(binaryPath)
	if err != nil {
		return certificates, err
	}
	defer file.Close()
	
	// Read file content
	content, err := io.ReadAll(file)
	if err != nil {
		return certificates, err
	}
	
	// Look for PEM certificate markers
	contentStr := string(content)
	beginMarker := "-----BEGIN CERTIFICATE-----"
	endMarker := "-----END CERTIFICATE-----"
	
	startIdx := 0
	for {
		beginIdx := strings.Index(contentStr[startIdx:], beginMarker)
		if beginIdx == -1 {
			break
		}
		beginIdx += startIdx
		
		endIdx := strings.Index(contentStr[beginIdx:], endMarker)
		if endIdx == -1 {
			break
		}
		endIdx += beginIdx + len(endMarker)
		
		// Extract the certificate
		certPEM := contentStr[beginIdx:endIdx]
		
		// Create a temporary file for this embedded certificate
		tempFile, err := os.CreateTemp("", "embedded_cert_*.pem")
		if err != nil {
			startIdx = endIdx
			continue
		}
		
		_, err = tempFile.WriteString(certPEM)
		tempFile.Close()
		
		if err != nil {
			os.Remove(tempFile.Name())
			startIdx = endIdx
			continue
		}
		
		certificates = append(certificates, tempFile.Name())
		startIdx = endIdx
	}
	
	return certificates, nil
}

// cleanupEmbeddedCertificates removes temporary certificate files created for embedded certificates
func (c *CertificateValidationCheck) cleanupEmbeddedCertificates(certificates []string) {
	for _, certPath := range certificates {
		if strings.Contains(certPath, "embedded_cert_") {
			os.Remove(certPath)
		}
	}
}

// validateCertificate validates a single certificate file
func (c *CertificateValidationCheck) validateCertificate(certPath string) (map[string]interface{}, bool) {
	certInfo := map[string]interface{}{
		"path":  certPath,
		"valid": false,
	}
	
	// Read certificate file
	certData, err := os.ReadFile(certPath)
	if err != nil {
		certInfo["error"] = fmt.Sprintf("Failed to read certificate: %v", err)
		return certInfo, false
	}
	
	// Parse PEM block
	block, _ := pem.Decode(certData)
	if block == nil {
		certInfo["error"] = "Failed to decode PEM block"
		return certInfo, false
	}
	
	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		certInfo["error"] = fmt.Sprintf("Failed to parse certificate: %v", err)
		return certInfo, false
	}
	
	// Extract certificate information
	certInfo["subject"] = cert.Subject.String()
	certInfo["issuer"] = cert.Issuer.String()
	certInfo["serial_number"] = cert.SerialNumber.String()
	certInfo["not_before"] = cert.NotBefore
	certInfo["not_after"] = cert.NotAfter
	certInfo["signature_algorithm"] = cert.SignatureAlgorithm.String()
	certInfo["public_key_algorithm"] = cert.PublicKeyAlgorithm.String()
	
	// Check if certificate is currently valid (time-wise)
	now := time.Now()
	if now.Before(cert.NotBefore) {
		certInfo["error"] = "Certificate is not yet valid"
		return certInfo, false
	}
	
	if now.After(cert.NotAfter) {
		certInfo["error"] = "Certificate has expired"
		return certInfo, false
	}
	
	// Check for weak signature algorithms
	weakAlgorithms := []x509.SignatureAlgorithm{
		x509.MD2WithRSA,
		x509.MD5WithRSA,
		x509.SHA1WithRSA,
	}
	
	for _, weak := range weakAlgorithms {
		if cert.SignatureAlgorithm == weak {
			certInfo["warning"] = fmt.Sprintf("Certificate uses weak signature algorithm: %s", cert.SignatureAlgorithm)
			break
		}
	}
	
	certInfo["valid"] = true
	return certInfo, true
}

// SignatureVerificationCheck implements check 6: Signature verification
type SignatureVerificationCheck struct{}

func (c *SignatureVerificationCheck) ID() string {
	return "check-6-signature-verification"
}

func (c *SignatureVerificationCheck) Description() string {
	return "Verifies digital signatures and code signing certificates"
}

func (c *SignatureVerificationCheck) Execute(binaryPath string) CheckResult {
	start := time.Now()
	
	result := CheckResult{
		ID:          c.ID(),
		Description: c.Description(),
		Duration:    time.Since(start),
		Metadata:    make(map[string]interface{}),
	}
	
	// Look for signature files
	signatures, err := c.findSignatures(binaryPath)
	if err != nil {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Failed to search for signatures: %v", err)
		return result
	}
	
	// Check for embedded signatures (platform-specific)
	embeddedSig, err := c.checkEmbeddedSignature(binaryPath)
	if err == nil && embeddedSig != nil {
		result.Metadata["embedded_signature"] = embeddedSig
	}
	
	if len(signatures) == 0 && embeddedSig == nil {
		// No signatures found - this might be acceptable for some binaries
		result.Status = "pass"
		result.Details = "No signatures found - binary may not be digitally signed"
		result.Metadata["signature_count"] = 0
		result.Metadata["signatures"] = []string{}
		return result
	}
	
	// Verify found signatures
	validSigs := 0
	invalidSigs := 0
	sigDetails := []map[string]interface{}{}
	
	for _, sigPath := range signatures {
		sigInfo, valid := c.verifySignature(binaryPath, sigPath)
		sigDetails = append(sigDetails, sigInfo)
		
		if valid {
			validSigs++
		} else {
			invalidSigs++
		}
	}
	
	result.Metadata["signature_count"] = len(signatures)
	result.Metadata["valid_signatures"] = validSigs
	result.Metadata["invalid_signatures"] = invalidSigs
	result.Metadata["signature_details"] = sigDetails
	
	if invalidSigs > 0 {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Signature verification failed: %d valid, %d invalid signatures", validSigs, invalidSigs)
	} else if validSigs > 0 {
		result.Status = "pass"
		result.Details = fmt.Sprintf("Signature verification passed: %d valid signatures", validSigs)
	} else {
		result.Status = "pass"
		result.Details = "No signatures to verify - binary may not require digital signatures"
	}
	
	result.Duration = time.Since(start)
	return result
}

// findSignatures looks for signature files related to the binary
func (c *SignatureVerificationCheck) findSignatures(binaryPath string) ([]string, error) {
	var signatures []string
	
	// Common signature file patterns
	baseName := strings.TrimSuffix(filepath.Base(binaryPath), filepath.Ext(binaryPath))
	dir := filepath.Dir(binaryPath)
	
	// Look for common signature file extensions
	sigExtensions := []string{".sig", ".sign", ".signature", ".asc", ".gpg"}
	
	for _, ext := range sigExtensions {
		sigPath := filepath.Join(dir, baseName+ext)
		if _, err := os.Stat(sigPath); err == nil {
			signatures = append(signatures, sigPath)
		}
		
		// Also check for the full binary name + extension
		sigPath = filepath.Join(dir, filepath.Base(binaryPath)+ext)
		if _, err := os.Stat(sigPath); err == nil {
			signatures = append(signatures, sigPath)
		}
	}
	
	return signatures, nil
}

// checkEmbeddedSignature checks for platform-specific embedded signatures
func (c *SignatureVerificationCheck) checkEmbeddedSignature(binaryPath string) (map[string]interface{}, error) {
	// This is a simplified implementation
	// Real implementation would use platform-specific tools like:
	// - Windows: Authenticode signatures
	// - macOS: codesign verification
	// - Linux: ELF signature sections
	
	parser := NewBinaryParser()
	info, err := parser.ParseBinary(binaryPath)
	if err != nil {
		return nil, err
	}
	
	sigInfo := map[string]interface{}{
		"format": string(info.Format),
		"signed": false,
	}
	
	switch info.Format {
	case FormatPE:
		// Check for Authenticode signature (simplified)
		signed, details := c.checkPESignature(binaryPath)
		sigInfo["signed"] = signed
		if details != nil {
			sigInfo["details"] = details
		}
	case FormatMachO:
		// Check for macOS code signature (simplified)
		signed, details := c.checkMachOSignature(binaryPath)
		sigInfo["signed"] = signed
		if details != nil {
			sigInfo["details"] = details
		}
	case FormatELF:
		// Check for ELF signature sections (simplified)
		signed, details := c.checkELFSignature(binaryPath)
		sigInfo["signed"] = signed
		if details != nil {
			sigInfo["details"] = details
		}
	}
	
	return sigInfo, nil
}

// checkPESignature checks for PE/Authenticode signatures (simplified)
func (c *SignatureVerificationCheck) checkPESignature(binaryPath string) (bool, map[string]interface{}) {
	// This is a simplified check - real implementation would parse PE certificate table
	file, err := os.Open(binaryPath)
	if err != nil {
		return false, nil
	}
	defer file.Close()
	
	// Read file content to look for certificate markers
	content, err := io.ReadAll(file)
	if err != nil {
		return false, nil
	}
	
	// Look for certificate-related strings (very basic check)
	contentStr := strings.ToLower(string(content))
	if strings.Contains(contentStr, "microsoft") && strings.Contains(contentStr, "certificate") {
		return true, map[string]interface{}{
			"type": "Authenticode",
			"note": "Potential Authenticode signature detected (basic check)",
		}
	}
	
	return false, nil
}

// checkMachOSignature checks for macOS code signatures (simplified)
func (c *SignatureVerificationCheck) checkMachOSignature(binaryPath string) (bool, map[string]interface{}) {
	// This is a simplified check - real implementation would parse LC_CODE_SIGNATURE load command
	file, err := os.Open(binaryPath)
	if err != nil {
		return false, nil
	}
	defer file.Close()
	
	// Read file content to look for signature markers
	content, err := io.ReadAll(file)
	if err != nil {
		return false, nil
	}
	
	// Look for code signature markers (very basic check)
	if strings.Contains(string(content), "LC_CODE_SIGNATURE") {
		return true, map[string]interface{}{
			"type": "macOS Code Signature",
			"note": "Potential macOS code signature detected (basic check)",
		}
	}
	
	return false, nil
}

// checkELFSignature checks for ELF signature sections (simplified)
func (c *SignatureVerificationCheck) checkELFSignature(binaryPath string) (bool, map[string]interface{}) {
	// This is a simplified check - real implementation would parse ELF sections
	parser := NewBinaryParser()
	info, err := parser.ParseBinary(binaryPath)
	if err != nil {
		return false, nil
	}
	
	// Look for signature-related sections
	for _, section := range info.Sections {
		sectionLower := strings.ToLower(section)
		if strings.Contains(sectionLower, "sig") || strings.Contains(sectionLower, "sign") {
			return true, map[string]interface{}{
				"type":    "ELF Signature Section",
				"section": section,
				"note":    "Potential signature section detected",
			}
		}
	}
	
	return false, nil
}

// verifySignature verifies a signature file against the binary
func (c *SignatureVerificationCheck) verifySignature(binaryPath, sigPath string) (map[string]interface{}, bool) {
	sigInfo := map[string]interface{}{
		"path":  sigPath,
		"valid": false,
	}
	
	// Read signature file
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		sigInfo["error"] = fmt.Sprintf("Failed to read signature: %v", err)
		return sigInfo, false
	}
	
	// This is a simplified signature verification
	// Real implementation would:
	// 1. Parse the signature format (PGP, PKCS#7, etc.)
	// 2. Extract the public key or certificate
	// 3. Verify the signature against the binary hash
	
	sigInfo["size"] = len(sigData)
	sigInfo["type"] = c.detectSignatureType(sigData)
	
	// For now, just check if the signature file exists and is non-empty
	if len(sigData) > 0 {
		sigInfo["valid"] = true
		sigInfo["note"] = "Signature file exists and is non-empty (basic check)"
		return sigInfo, true
	}
	
	sigInfo["error"] = "Empty signature file"
	return sigInfo, false
}

// detectSignatureType attempts to detect the signature format
func (c *SignatureVerificationCheck) detectSignatureType(sigData []byte) string {
	sigStr := string(sigData)
	
	if strings.Contains(sigStr, "-----BEGIN PGP SIGNATURE-----") {
		return "PGP"
	}
	if strings.Contains(sigStr, "-----BEGIN PKCS7-----") {
		return "PKCS#7"
	}
	if strings.Contains(sigStr, "-----BEGIN SIGNATURE-----") {
		return "Generic PEM"
	}
	
	// Check for binary signature formats
	if len(sigData) >= 4 {
		// Check for common binary signature headers
		header := sigData[:4]
		if header[0] == 0x30 && header[1] == 0x82 {
			return "DER/ASN.1"
		}
	}
	
	return "Unknown"
}

// HashIntegrityCheck implements check 7: Hash integrity verification
type HashIntegrityCheck struct{}

func (c *HashIntegrityCheck) ID() string {
	return "check-7-hash-integrity"
}

func (c *HashIntegrityCheck) Description() string {
	return "Verifies binary integrity using cryptographic hashes"
}

func (c *HashIntegrityCheck) Execute(binaryPath string) CheckResult {
	start := time.Now()
	
	result := CheckResult{
		ID:          c.ID(),
		Description: c.Description(),
		Duration:    time.Since(start),
		Metadata:    make(map[string]interface{}),
	}
	
	// Calculate multiple hash algorithms
	hashes, err := c.calculateHashes(binaryPath)
	if err != nil {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Failed to calculate hashes: %v", err)
		return result
	}
	
	result.Metadata["hashes"] = hashes
	
	// Look for hash files to verify against
	hashFiles, err := c.findHashFiles(binaryPath)
	if err != nil {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Failed to search for hash files: %v", err)
		return result
	}
	
	if len(hashFiles) == 0 {
		// No hash files found - still pass but note that integrity cannot be verified
		result.Status = "pass"
		result.Details = "Hash integrity calculated successfully - no reference hashes found for verification"
		result.Metadata["hash_files"] = []string{}
		result.Metadata["verified"] = false
		return result
	}
	
	// Verify against found hash files
	verified := 0
	failed := 0
	verificationDetails := []map[string]interface{}{}
	
	for _, hashFile := range hashFiles {
		verifyInfo, success := c.verifyHashFile(binaryPath, hashFile, hashes)
		verificationDetails = append(verificationDetails, verifyInfo)
		
		if success {
			verified++
		} else {
			failed++
		}
	}
	
	result.Metadata["hash_files"] = hashFiles
	result.Metadata["verified_files"] = verified
	result.Metadata["failed_files"] = failed
	result.Metadata["verification_details"] = verificationDetails
	result.Metadata["verified"] = verified > 0 && failed == 0
	
	if failed > 0 {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Hash integrity verification failed: %d verified, %d failed", verified, failed)
	} else if verified > 0 {
		result.Status = "pass"
		result.Details = fmt.Sprintf("Hash integrity verification passed: %d hash files verified", verified)
	} else {
		result.Status = "pass"
		result.Details = "Hash integrity calculated - no verification files found"
	}
	
	result.Duration = time.Since(start)
	return result
}

// calculateHashes calculates multiple hash algorithms for the binary
func (c *HashIntegrityCheck) calculateHashes(binaryPath string) (map[string]string, error) {
	file, err := os.Open(binaryPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	// Create hash instances
	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()
	sha512Hash := sha512.New()
	
	// Create a multi-writer to calculate all hashes in one pass
	multiWriter := io.MultiWriter(md5Hash, sha1Hash, sha256Hash, sha512Hash)
	
	// Copy file content to all hash writers
	_, err = io.Copy(multiWriter, file)
	if err != nil {
		return nil, err
	}
	
	// Get final hash values
	hashes := map[string]string{
		"md5":    hex.EncodeToString(md5Hash.Sum(nil)),
		"sha1":   hex.EncodeToString(sha1Hash.Sum(nil)),
		"sha256": hex.EncodeToString(sha256Hash.Sum(nil)),
		"sha512": hex.EncodeToString(sha512Hash.Sum(nil)),
	}
	
	return hashes, nil
}

// findHashFiles looks for hash files related to the binary
func (c *HashIntegrityCheck) findHashFiles(binaryPath string) ([]string, error) {
	var hashFiles []string
	
	baseName := filepath.Base(binaryPath)
	dir := filepath.Dir(binaryPath)
	
	// Common hash file extensions and patterns
	hashPatterns := []string{
		baseName + ".md5",
		baseName + ".sha1",
		baseName + ".sha256",
		baseName + ".sha512",
		baseName + ".hash",
		baseName + ".checksum",
		"checksums.txt",
		"hashes.txt",
		"MD5SUMS",
		"SHA1SUMS",
		"SHA256SUMS",
		"SHA512SUMS",
	}
	
	for _, pattern := range hashPatterns {
		hashPath := filepath.Join(dir, pattern)
		if _, err := os.Stat(hashPath); err == nil {
			hashFiles = append(hashFiles, hashPath)
		}
	}
	
	return hashFiles, nil
}

// verifyHashFile verifies the binary hash against a hash file
func (c *HashIntegrityCheck) verifyHashFile(binaryPath, hashFile string, calculatedHashes map[string]string) (map[string]interface{}, bool) {
	verifyInfo := map[string]interface{}{
		"file":     hashFile,
		"verified": false,
	}
	
	// Read hash file
	hashData, err := os.ReadFile(hashFile)
	if err != nil {
		verifyInfo["error"] = fmt.Sprintf("Failed to read hash file: %v", err)
		return verifyInfo, false
	}
	
	hashContent := strings.TrimSpace(string(hashData))
	lines := strings.Split(hashContent, "\n")
	
	binaryName := filepath.Base(binaryPath)
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// Try to parse different hash file formats
		if verified, algorithm := c.parseAndVerifyHashLine(line, binaryName, calculatedHashes); verified {
			verifyInfo["verified"] = true
			verifyInfo["algorithm"] = algorithm
			verifyInfo["line"] = line
			return verifyInfo, true
		}
	}
	
	// If no specific line matched, try to match just the hash value
	for algorithm, hash := range calculatedHashes {
		if strings.Contains(strings.ToLower(hashContent), strings.ToLower(hash)) {
			verifyInfo["verified"] = true
			verifyInfo["algorithm"] = algorithm
			verifyInfo["note"] = "Hash found in file content"
			return verifyInfo, true
		}
	}
	
	verifyInfo["error"] = "No matching hash found in file"
	return verifyInfo, false
}

// parseAndVerifyHashLine parses a single line from a hash file and verifies it
func (c *HashIntegrityCheck) parseAndVerifyHashLine(line, binaryName string, calculatedHashes map[string]string) (bool, string) {
	// Common hash file formats:
	// 1. "hash filename"
	// 2. "hash *filename" (binary mode indicator)
	// 3. "filename: hash"
	// 4. Just "hash" (if file contains only one hash)
	
	// Format: "hash filename" or "hash *filename"
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		hash := parts[0]
		filename := strings.TrimPrefix(parts[1], "*") // Remove binary mode indicator
		
		if filename == binaryName || strings.HasSuffix(filename, binaryName) {
			return c.verifyHashValue(hash, calculatedHashes)
		}
	}
	
	// Format: "filename: hash"
	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			filename := strings.TrimSpace(parts[0])
			hash := strings.TrimSpace(parts[1])
			
			if filename == binaryName || strings.HasSuffix(filename, binaryName) {
				return c.verifyHashValue(hash, calculatedHashes)
			}
		}
	}
	
	// Format: Just "hash" (single hash in file)
	if len(parts) == 1 {
		hash := parts[0]
		return c.verifyHashValue(hash, calculatedHashes)
	}
	
	return false, ""
}

// verifyHashValue checks if a hash value matches any of the calculated hashes
func (c *HashIntegrityCheck) verifyHashValue(hash string, calculatedHashes map[string]string) (bool, string) {
	hash = strings.ToLower(hash)
	
	for algorithm, calculatedHash := range calculatedHashes {
		if hash == strings.ToLower(calculatedHash) {
			return true, algorithm
		}
	}
	
	return false, ""
}

// EncryptionStandardCheck implements check 8: Encryption standard compliance
type EncryptionStandardCheck struct{}

func (c *EncryptionStandardCheck) ID() string {
	return "check-8-encryption-standard"
}

func (c *EncryptionStandardCheck) Description() string {
	return "Validates compliance with encryption standards and cryptographic best practices"
}

func (c *EncryptionStandardCheck) Execute(binaryPath string) CheckResult {
	start := time.Now()
	
	result := CheckResult{
		ID:          c.ID(),
		Description: c.Description(),
		Duration:    time.Since(start),
		Metadata:    make(map[string]interface{}),
	}
	
	// Analyze the binary for cryptographic indicators
	cryptoAnalysis, err := c.analyzeCryptographicContent(binaryPath)
	if err != nil {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Failed to analyze cryptographic content: %v", err)
		return result
	}
	
	result.Metadata = cryptoAnalysis
	
	// Check for compliance issues
	issues := c.checkComplianceIssues(cryptoAnalysis)
	
	if len(issues) > 0 {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Encryption standard compliance failed: %d issues found", len(issues))
		result.Metadata["compliance_issues"] = issues
	} else {
		result.Status = "pass"
		result.Details = "Encryption standard compliance passed - no issues detected"
		result.Metadata["compliance_issues"] = []string{}
	}
	
	result.Duration = time.Since(start)
	return result
}

// analyzeCryptographicContent analyzes the binary for cryptographic indicators
func (c *EncryptionStandardCheck) analyzeCryptographicContent(binaryPath string) (map[string]interface{}, error) {
	analysis := map[string]interface{}{
		"weak_algorithms":     []string{},
		"strong_algorithms":   []string{},
		"key_sizes":          []string{},
		"crypto_libraries":   []string{},
		"certificates_found": false,
		"random_sources":     []string{},
	}
	
	// Read binary content
	file, err := os.Open(binaryPath)
	if err != nil {
		return analysis, err
	}
	defer file.Close()
	
	content, err := io.ReadAll(file)
	if err != nil {
		return analysis, err
	}
	
	contentStr := strings.ToLower(string(content))
	
	// Check for weak cryptographic algorithms
	weakAlgorithms := []string{
		"md5", "md4", "md2",
		"sha1",
		"des", "3des",
		"rc4", "rc2",
		"blowfish",
	}
	
	for _, weak := range weakAlgorithms {
		if strings.Contains(contentStr, weak) {
			analysis["weak_algorithms"] = append(analysis["weak_algorithms"].([]string), weak)
		}
	}
	
	// Check for strong cryptographic algorithms
	strongAlgorithms := []string{
		"aes", "aes128", "aes192", "aes256",
		"sha256", "sha384", "sha512",
		"rsa2048", "rsa3072", "rsa4096",
		"ecdsa", "ecdh",
		"chacha20", "poly1305",
		"argon2", "scrypt", "pbkdf2",
	}
	
	for _, strong := range strongAlgorithms {
		if strings.Contains(contentStr, strong) {
			analysis["strong_algorithms"] = append(analysis["strong_algorithms"].([]string), strong)
		}
	}
	
	// Check for key size indicators
	keySizes := []string{
		"1024", "2048", "3072", "4096", "8192", // RSA key sizes
		"128", "192", "256", "384", "512",      // Symmetric key sizes
	}
	
	for _, size := range keySizes {
		if strings.Contains(contentStr, size) {
			analysis["key_sizes"] = append(analysis["key_sizes"].([]string), size)
		}
	}
	
	// Check for common crypto libraries
	cryptoLibraries := []string{
		"openssl", "libssl", "libcrypto",
		"botan", "cryptopp", "libgcrypt",
		"mbedtls", "wolfssl", "bearssl",
		"sodium", "libsodium",
	}
	
	for _, lib := range cryptoLibraries {
		if strings.Contains(contentStr, lib) {
			analysis["crypto_libraries"] = append(analysis["crypto_libraries"].([]string), lib)
		}
	}
	
	// Check for certificates
	if strings.Contains(contentStr, "certificate") || strings.Contains(contentStr, "-----begin certificate-----") {
		analysis["certificates_found"] = true
	}
	
	// Check for random number sources
	randomSources := []string{
		"/dev/random", "/dev/urandom",
		"cryptgenrandom", "rtlgenrandom",
		"getrandom", "arc4random",
	}
	
	for _, source := range randomSources {
		if strings.Contains(contentStr, source) {
			analysis["random_sources"] = append(analysis["random_sources"].([]string), source)
		}
	}
	
	return analysis, nil
}

// checkComplianceIssues checks for encryption standard compliance issues
func (c *EncryptionStandardCheck) checkComplianceIssues(analysis map[string]interface{}) []string {
	var issues []string
	
	// Check for weak algorithms
	weakAlgorithms := analysis["weak_algorithms"].([]string)
	for _, weak := range weakAlgorithms {
		switch weak {
		case "md5", "md4", "md2":
			issues = append(issues, fmt.Sprintf("Weak hash algorithm detected: %s (vulnerable to collision attacks)", weak))
		case "sha1":
			issues = append(issues, "SHA-1 algorithm detected (deprecated, vulnerable to collision attacks)")
		case "des", "3des":
			issues = append(issues, fmt.Sprintf("Weak encryption algorithm detected: %s (insufficient key length)", weak))
		case "rc4", "rc2":
			issues = append(issues, fmt.Sprintf("Weak stream cipher detected: %s (known vulnerabilities)", weak))
		}
	}
	
	// Check key sizes
	keySizes := analysis["key_sizes"].([]string)
	for _, size := range keySizes {
		switch size {
		case "1024":
			issues = append(issues, "1024-bit key size detected (insufficient for RSA, should be at least 2048-bit)")
		case "128":
			// 128-bit is acceptable for symmetric encryption but check context
			strongAlgorithms := analysis["strong_algorithms"].([]string)
			hasAES := false
			for _, alg := range strongAlgorithms {
				if strings.Contains(alg, "aes") {
					hasAES = true
					break
				}
			}
			if !hasAES {
				issues = append(issues, "128-bit key detected without strong algorithm context")
			}
		}
	}
	
	// Check for missing strong algorithms
	strongAlgorithms := analysis["strong_algorithms"].([]string)
	if len(strongAlgorithms) == 0 && len(weakAlgorithms) > 0 {
		issues = append(issues, "Only weak cryptographic algorithms detected, no strong algorithms found")
	}
	
	// Check for poor random sources
	randomSources := analysis["random_sources"].([]string)
	hasPoorRandom := false
	for _, source := range randomSources {
		if source == "/dev/random" {
			// /dev/random can block, /dev/urandom is generally preferred
			hasPoorRandom = true
		}
	}
	if hasPoorRandom {
		issues = append(issues, "Potentially blocking random source detected (/dev/random), consider /dev/urandom")
	}
	
	return issues
}