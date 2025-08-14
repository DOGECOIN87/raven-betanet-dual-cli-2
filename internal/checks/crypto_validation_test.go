package checks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Test data and helper functions

// createTestCertificate creates a test X.509 certificate
func createTestCertificate(t *testing.T, expired bool) ([]byte, *rsa.PrivateKey) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Organization"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  nil,
	}

	// Make certificate expired if requested
	if expired {
		template.NotBefore = time.Now().Add(-365 * 24 * time.Hour)
		template.NotAfter = time.Now().Add(-24 * time.Hour)
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM, privateKey
}

// createTestBinary creates a test binary file with optional embedded content in an isolated directory
func createTestBinary(t *testing.T, content string) string {
	// Create isolated temp directory for this test
	tmpDir, err := os.MkdirTemp("", "test_crypto_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	
	tmpFile, err := os.CreateTemp(tmpDir, "test_binary_*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	// Write basic binary content
	binaryContent := "#!/bin/bash\necho 'test binary'\n"
	if content != "" {
		binaryContent += content
	}

	_, err = tmpFile.WriteString(binaryContent)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	return tmpFile.Name()
}

// cleanupTestDir removes the test directory and all its contents
func cleanupTestDir(t *testing.T, filePath string) {
	dir := filepath.Dir(filePath)
	if strings.Contains(dir, "test_crypto_") {
		os.RemoveAll(dir)
	}
}

// createTestHashFile creates a test hash file
func createTestHashFile(t *testing.T, binaryPath, algorithm, hash string) string {
	dir := filepath.Dir(binaryPath)
	baseName := filepath.Base(binaryPath)
	
	var hashFileName string
	switch algorithm {
	case "md5":
		hashFileName = baseName + ".md5"
	case "sha1":
		hashFileName = baseName + ".sha1"
	case "sha256":
		hashFileName = baseName + ".sha256"
	case "sha512":
		hashFileName = baseName + ".sha512"
	default:
		hashFileName = baseName + ".hash"
	}

	hashFilePath := filepath.Join(dir, hashFileName)
	
	// Write hash in common format: "hash filename"
	hashContent := hash + "  " + baseName + "\n"
	
	err := os.WriteFile(hashFilePath, []byte(hashContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create hash file: %v", err)
	}

	return hashFilePath
}

// TestCertificateValidationCheck tests the certificate validation check
func TestCertificateValidationCheck(t *testing.T) {
	check := &CertificateValidationCheck{}

	// Test basic check properties
	if check.ID() != "check-5-certificate-validation" {
		t.Errorf("Expected ID 'check-5-certificate-validation', got '%s'", check.ID())
	}

	if check.Description() == "" {
		t.Error("Description should not be empty")
	}

	t.Run("NoCertificates", func(t *testing.T) {
		// Create test binary without certificates
		binaryPath := createTestBinary(t, "")
		defer cleanupTestDir(t, binaryPath)

		result := check.Execute(binaryPath)

		if result.Status != "pass" {
			t.Errorf("Expected status 'pass', got '%s'", result.Status)
		}

		if result.Metadata["certificate_count"] != 0 {
			t.Errorf("Expected certificate_count 0, got %v", result.Metadata["certificate_count"])
		}
	})

	t.Run("ValidCertificate", func(t *testing.T) {
		// Create valid certificate
		certPEM, _ := createTestCertificate(t, false)
		
		// Create certificate file
		certFile, err := os.CreateTemp("", "test_cert_*.pem")
		if err != nil {
			t.Fatalf("Failed to create cert file: %v", err)
		}
		defer os.Remove(certFile.Name())
		
		_, err = certFile.Write(certPEM)
		if err != nil {
			t.Fatalf("Failed to write cert file: %v", err)
		}
		certFile.Close()

		// Create test binary in same directory
		dir := filepath.Dir(certFile.Name())
		binaryPath := filepath.Join(dir, "test_binary")
		err = os.WriteFile(binaryPath, []byte("test binary content"), 0755)
		if err != nil {
			t.Fatalf("Failed to create binary: %v", err)
		}
		defer os.Remove(binaryPath)

		result := check.Execute(binaryPath)

		if result.Status != "pass" {
			t.Errorf("Expected status 'pass', got '%s': %s", result.Status, result.Details)
		}

		if result.Metadata["certificate_count"].(int) == 0 {
			t.Error("Expected to find at least one certificate")
		}

		if result.Metadata["valid_certificates"].(int) == 0 {
			t.Error("Expected at least one valid certificate")
		}
	})

	t.Run("ExpiredCertificate", func(t *testing.T) {
		// Create expired certificate
		certPEM, _ := createTestCertificate(t, true)
		
		// Create certificate file
		certFile, err := os.CreateTemp("", "test_cert_*.pem")
		if err != nil {
			t.Fatalf("Failed to create cert file: %v", err)
		}
		defer os.Remove(certFile.Name())
		
		_, err = certFile.Write(certPEM)
		if err != nil {
			t.Fatalf("Failed to write cert file: %v", err)
		}
		certFile.Close()

		// Create test binary in same directory
		dir := filepath.Dir(certFile.Name())
		binaryPath := filepath.Join(dir, "test_binary")
		err = os.WriteFile(binaryPath, []byte("test binary content"), 0755)
		if err != nil {
			t.Fatalf("Failed to create binary: %v", err)
		}
		defer os.Remove(binaryPath)

		result := check.Execute(binaryPath)

		if result.Status != "fail" {
			t.Errorf("Expected status 'fail', got '%s'", result.Status)
		}

		if result.Metadata["invalid_certificates"].(int) == 0 {
			t.Error("Expected at least one invalid certificate")
		}
	})

	t.Run("EmbeddedCertificate", func(t *testing.T) {
		// Create certificate
		certPEM, _ := createTestCertificate(t, false)
		
		// Create binary with embedded certificate
		binaryContent := "binary content\n" + string(certPEM) + "\nmore binary content"
		binaryPath := createTestBinary(t, binaryContent)
		defer cleanupTestDir(t, binaryPath)

		result := check.Execute(binaryPath)

		if result.Status != "pass" {
			t.Errorf("Expected status 'pass', got '%s': %s", result.Status, result.Details)
		}

		if result.Metadata["certificate_count"].(int) == 0 {
			t.Error("Expected to find embedded certificate")
		}
	})
}

// TestSignatureVerificationCheck tests the signature verification check
func TestSignatureVerificationCheck(t *testing.T) {
	check := &SignatureVerificationCheck{}

	// Test basic check properties
	if check.ID() != "check-6-signature-verification" {
		t.Errorf("Expected ID 'check-6-signature-verification', got '%s'", check.ID())
	}

	if check.Description() == "" {
		t.Error("Description should not be empty")
	}

	t.Run("NoSignatures", func(t *testing.T) {
		// Create test binary without signatures
		binaryPath := createTestBinary(t, "")
		defer cleanupTestDir(t, binaryPath)

		result := check.Execute(binaryPath)

		if result.Status != "pass" {
			t.Errorf("Expected status 'pass', got '%s'", result.Status)
		}

		if result.Metadata["signature_count"] != 0 {
			t.Errorf("Expected signature_count 0, got %v", result.Metadata["signature_count"])
		}
	})

	t.Run("SignatureFile", func(t *testing.T) {
		// Create test binary
		binaryPath := createTestBinary(t, "")
		defer cleanupTestDir(t, binaryPath)

		// Create signature file
		sigPath := binaryPath + ".sig"
		sigContent := "test signature content"
		err := os.WriteFile(sigPath, []byte(sigContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create signature file: %v", err)
		}

		result := check.Execute(binaryPath)

		if result.Status != "pass" {
			t.Errorf("Expected status 'pass', got '%s': %s", result.Status, result.Details)
		}

		if result.Metadata["signature_count"].(int) == 0 {
			t.Error("Expected to find signature file")
		}

		if result.Metadata["valid_signatures"].(int) == 0 {
			t.Error("Expected at least one valid signature")
		}
	})

	t.Run("EmptySignatureFile", func(t *testing.T) {
		// Create test binary
		binaryPath := createTestBinary(t, "")
		defer cleanupTestDir(t, binaryPath)

		// Create empty signature file
		sigPath := binaryPath + ".sig"
		err := os.WriteFile(sigPath, []byte(""), 0644)
		if err != nil {
			t.Fatalf("Failed to create signature file: %v", err)
		}

		result := check.Execute(binaryPath)

		if result.Status != "fail" {
			t.Errorf("Expected status 'fail', got '%s'", result.Status)
		}

		if result.Metadata["invalid_signatures"].(int) == 0 {
			t.Error("Expected at least one invalid signature")
		}
	})

	t.Run("PGPSignature", func(t *testing.T) {
		// Create test binary
		binaryPath := createTestBinary(t, "")
		defer cleanupTestDir(t, binaryPath)

		// Create PGP signature file
		sigPath := binaryPath + ".asc"
		pgpSig := `-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1

iQEcBAABAgAGBQJXXXXXAAoJEABCDEFGHIJKLMNOPQRSTUVWXYZ
abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP
QRSTUVWXYZ+/=
=ABCD
-----END PGP SIGNATURE-----`
		
		err := os.WriteFile(sigPath, []byte(pgpSig), 0644)
		if err != nil {
			t.Fatalf("Failed to create signature file: %v", err)
		}

		result := check.Execute(binaryPath)

		if result.Status != "pass" {
			t.Errorf("Expected status 'pass', got '%s': %s", result.Status, result.Details)
		}

		// Check that PGP signature type was detected
		sigDetails := result.Metadata["signature_details"].([]map[string]interface{})
		if len(sigDetails) > 0 {
			if sigDetails[0]["type"] != "PGP" {
				t.Errorf("Expected PGP signature type, got %v", sigDetails[0]["type"])
			}
		}
	})
}

// TestHashIntegrityCheck tests the hash integrity check
func TestHashIntegrityCheck(t *testing.T) {
	check := &HashIntegrityCheck{}

	// Test basic check properties
	if check.ID() != "check-7-hash-integrity" {
		t.Errorf("Expected ID 'check-7-hash-integrity', got '%s'", check.ID())
	}

	if check.Description() == "" {
		t.Error("Description should not be empty")
	}

	t.Run("NoHashFiles", func(t *testing.T) {
		// Create test binary
		binaryPath := createTestBinary(t, "test content")
		defer cleanupTestDir(t, binaryPath)

		result := check.Execute(binaryPath)

		if result.Status != "pass" {
			t.Errorf("Expected status 'pass', got '%s'", result.Status)
		}

		// Should have calculated hashes
		hashes := result.Metadata["hashes"].(map[string]string)
		if len(hashes) == 0 {
			t.Error("Expected calculated hashes")
		}

		// Should have MD5, SHA1, SHA256, SHA512
		expectedAlgorithms := []string{"md5", "sha1", "sha256", "sha512"}
		for _, alg := range expectedAlgorithms {
			if _, exists := hashes[alg]; !exists {
				t.Errorf("Expected %s hash to be calculated", alg)
			}
		}

		if result.Metadata["verified"].(bool) {
			t.Error("Expected verified to be false when no hash files present")
		}
	})

	t.Run("ValidHashFile", func(t *testing.T) {
		// Create test binary
		binaryContent := "test content for hashing"
		binaryPath := createTestBinary(t, binaryContent)
		defer os.Remove(binaryPath)

		// Calculate expected hash
		hasher := sha256.New()
		hasher.Write([]byte("#!/bin/bash\necho 'test binary'\n" + binaryContent))
		expectedHash := hex.EncodeToString(hasher.Sum(nil))

		// Create hash file
		hashFilePath := createTestHashFile(t, binaryPath, "sha256", expectedHash)
		defer os.Remove(hashFilePath)

		result := check.Execute(binaryPath)

		if result.Status != "pass" {
			t.Errorf("Expected status 'pass', got '%s': %s", result.Status, result.Details)
		}

		if result.Metadata["verified_files"].(int) == 0 {
			t.Error("Expected at least one verified hash file")
		}

		if !result.Metadata["verified"].(bool) {
			t.Error("Expected verified to be true")
		}
	})

	t.Run("InvalidHashFile", func(t *testing.T) {
		// Create test binary
		binaryPath := createTestBinary(t, "test content")
		defer os.Remove(binaryPath)

		// Create hash file with wrong hash
		wrongHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		hashFilePath := createTestHashFile(t, binaryPath, "sha256", wrongHash)
		defer os.Remove(hashFilePath)

		result := check.Execute(binaryPath)

		if result.Status != "fail" {
			t.Errorf("Expected status 'fail', got '%s'", result.Status)
		}

		if result.Metadata["failed_files"].(int) == 0 {
			t.Error("Expected at least one failed hash file")
		}

		if result.Metadata["verified"].(bool) {
			t.Error("Expected verified to be false")
		}
	})

	t.Run("MultipleHashFiles", func(t *testing.T) {
		// Create test binary
		binaryContent := "test content for multiple hashes"
		binaryPath := createTestBinary(t, binaryContent)
		defer os.Remove(binaryPath)

		// Calculate expected hashes
		fullContent := []byte("#!/bin/bash\necho 'test binary'\n" + binaryContent)
		
		sha256Hasher := sha256.New()
		sha256Hasher.Write(fullContent)
		expectedSHA256 := hex.EncodeToString(sha256Hasher.Sum(nil))

		// Create multiple hash files - one correct, one incorrect
		hashFile1 := createTestHashFile(t, binaryPath, "sha256", expectedSHA256)
		defer os.Remove(hashFile1)

		wrongHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		hashFile2 := createTestHashFile(t, binaryPath, "md5", wrongHash)
		defer os.Remove(hashFile2)

		result := check.Execute(binaryPath)

		if result.Status != "fail" {
			t.Errorf("Expected status 'fail', got '%s'", result.Status)
		}

		if result.Metadata["verified_files"].(int) == 0 {
			t.Error("Expected at least one verified hash file")
		}

		if result.Metadata["failed_files"].(int) == 0 {
			t.Error("Expected at least one failed hash file")
		}
	})
}

// TestEncryptionStandardCheck tests the encryption standard compliance check
func TestEncryptionStandardCheck(t *testing.T) {
	check := &EncryptionStandardCheck{}

	// Test basic check properties
	if check.ID() != "check-8-encryption-standard" {
		t.Errorf("Expected ID 'check-8-encryption-standard', got '%s'", check.ID())
	}

	if check.Description() == "" {
		t.Error("Description should not be empty")
	}

	t.Run("NoCryptoContent", func(t *testing.T) {
		// Create test binary without crypto content
		binaryPath := createTestBinary(t, "plain content without crypto")
		defer os.Remove(binaryPath)

		result := check.Execute(binaryPath)

		if result.Status != "pass" {
			t.Errorf("Expected status 'pass', got '%s'", result.Status)
		}

		weakAlgorithms := result.Metadata["weak_algorithms"].([]string)
		if len(weakAlgorithms) != 0 {
			t.Errorf("Expected no weak algorithms, got %v", weakAlgorithms)
		}

		issues := result.Metadata["compliance_issues"].([]string)
		if len(issues) != 0 {
			t.Errorf("Expected no compliance issues, got %v", issues)
		}
	})

	t.Run("WeakAlgorithms", func(t *testing.T) {
		// Create test binary with weak crypto algorithms
		cryptoContent := "using md5 hash and des encryption with rc4 cipher"
		binaryPath := createTestBinary(t, cryptoContent)
		defer os.Remove(binaryPath)

		result := check.Execute(binaryPath)

		if result.Status != "fail" {
			t.Errorf("Expected status 'fail', got '%s'", result.Status)
		}

		weakAlgorithms := result.Metadata["weak_algorithms"].([]string)
		expectedWeak := []string{"md5", "des", "rc4"}
		
		for _, expected := range expectedWeak {
			found := false
			for _, weak := range weakAlgorithms {
				if weak == expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected to find weak algorithm %s", expected)
			}
		}

		issues := result.Metadata["compliance_issues"].([]string)
		if len(issues) == 0 {
			t.Error("Expected compliance issues for weak algorithms")
		}
	})

	t.Run("StrongAlgorithms", func(t *testing.T) {
		// Create test binary with strong crypto algorithms
		cryptoContent := "using aes256 encryption with sha256 hash and rsa2048 keys"
		binaryPath := createTestBinary(t, cryptoContent)
		defer os.Remove(binaryPath)

		result := check.Execute(binaryPath)

		if result.Status != "pass" {
			t.Errorf("Expected status 'pass', got '%s': %s", result.Status, result.Details)
		}

		strongAlgorithms := result.Metadata["strong_algorithms"].([]string)
		expectedStrong := []string{"aes256", "sha256", "rsa2048"}
		
		for _, expected := range expectedStrong {
			found := false
			for _, strong := range strongAlgorithms {
				if strong == expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected to find strong algorithm %s", expected)
			}
		}

		issues := result.Metadata["compliance_issues"].([]string)
		if len(issues) != 0 {
			t.Errorf("Expected no compliance issues, got %v", issues)
		}
	})

	t.Run("MixedAlgorithms", func(t *testing.T) {
		// Create test binary with both weak and strong algorithms
		cryptoContent := "using aes256 encryption but also md5 hash for compatibility"
		binaryPath := createTestBinary(t, cryptoContent)
		defer os.Remove(binaryPath)

		result := check.Execute(binaryPath)

		if result.Status != "fail" {
			t.Errorf("Expected status 'fail', got '%s'", result.Status)
		}

		weakAlgorithms := result.Metadata["weak_algorithms"].([]string)
		if len(weakAlgorithms) == 0 {
			t.Error("Expected to find weak algorithms")
		}

		strongAlgorithms := result.Metadata["strong_algorithms"].([]string)
		if len(strongAlgorithms) == 0 {
			t.Error("Expected to find strong algorithms")
		}

		issues := result.Metadata["compliance_issues"].([]string)
		if len(issues) == 0 {
			t.Error("Expected compliance issues for weak algorithms")
		}
	})

	t.Run("WeakKeySize", func(t *testing.T) {
		// Create test binary with weak key size
		cryptoContent := "rsa key with 1024 bit length"
		binaryPath := createTestBinary(t, cryptoContent)
		defer os.Remove(binaryPath)

		result := check.Execute(binaryPath)

		if result.Status != "fail" {
			t.Errorf("Expected status 'fail', got '%s'", result.Status)
		}

		keySizes := result.Metadata["key_sizes"].([]string)
		found1024 := false
		for _, size := range keySizes {
			if size == "1024" {
				found1024 = true
				break
			}
		}
		if !found1024 {
			t.Error("Expected to find 1024-bit key size")
		}

		issues := result.Metadata["compliance_issues"].([]string)
		found1024Issue := false
		for _, issue := range issues {
			if strings.Contains(issue, "1024-bit") {
				found1024Issue = true
				break
			}
		}
		if !found1024Issue {
			t.Error("Expected compliance issue for 1024-bit key")
		}
	})

	t.Run("CryptoLibraries", func(t *testing.T) {
		// Create test binary with crypto library references
		cryptoContent := "linked with openssl libcrypto and libsodium"
		binaryPath := createTestBinary(t, cryptoContent)
		defer os.Remove(binaryPath)

		result := check.Execute(binaryPath)

		cryptoLibraries := result.Metadata["crypto_libraries"].([]string)
		expectedLibs := []string{"openssl", "libcrypto", "libsodium"}
		
		for _, expected := range expectedLibs {
			found := false
			for _, lib := range cryptoLibraries {
				if lib == expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected to find crypto library %s", expected)
			}
		}
	})

	t.Run("RandomSources", func(t *testing.T) {
		// Create test binary with random source references
		cryptoContent := "reading from /dev/urandom and /dev/random"
		binaryPath := createTestBinary(t, cryptoContent)
		defer os.Remove(binaryPath)

		result := check.Execute(binaryPath)

		randomSources := result.Metadata["random_sources"].([]string)
		expectedSources := []string{"/dev/urandom", "/dev/random"}
		
		for _, expected := range expectedSources {
			found := false
			for _, source := range randomSources {
				if source == expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected to find random source %s", expected)
			}
		}

		// Should have issue about /dev/random being potentially blocking
		issues := result.Metadata["compliance_issues"].([]string)
		foundRandomIssue := false
		for _, issue := range issues {
			if strings.Contains(issue, "/dev/random") && strings.Contains(issue, "blocking") {
				foundRandomIssue = true
				break
			}
		}
		if !foundRandomIssue {
			t.Error("Expected compliance issue for potentially blocking random source")
		}
	})
}

// TestCryptoValidationIntegration tests integration between crypto validation checks
func TestCryptoValidationIntegration(t *testing.T) {
	// Create a registry and register all crypto checks
	registry := NewCheckRegistry()
	
	checks := []ComplianceCheck{
		&CertificateValidationCheck{},
		&SignatureVerificationCheck{},
		&HashIntegrityCheck{},
		&EncryptionStandardCheck{},
	}
	
	for _, check := range checks {
		err := registry.Register(check)
		if err != nil {
			t.Fatalf("Failed to register check %s: %v", check.ID(), err)
		}
	}

	// Create test binary with comprehensive crypto content
	cryptoContent := `
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJANIiJ1nZ8XYZMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCVRl
c3QgQ2VydDAeFw0yMzEwMTAwMDAwMDBaFw0yNDEwMTAwMDAwMDBaMBQxEjAQBgNV
BAMMCVRlc3QgQ2VydDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7VJTUt9Us8cKB
UwUiWnQGHMAccrPFjMCLXaGOjsSuAQ==
-----END CERTIFICATE-----
using aes256 encryption with sha256 hash
linked with openssl libcrypto
reading from /dev/urandom
`
	
	binaryPath := createTestBinary(t, cryptoContent)
	defer os.Remove(binaryPath)

	// Run all crypto checks
	runner := NewCheckRunner(registry)
	report, err := runner.RunSelected(binaryPath, []string{
		"check-5-certificate-validation",
		"check-6-signature-verification", 
		"check-7-hash-integrity",
		"check-8-encryption-standard",
	})
	
	if err != nil {
		t.Fatalf("Failed to run crypto checks: %v", err)
	}

	if report.TotalChecks != 4 {
		t.Errorf("Expected 4 checks, got %d", report.TotalChecks)
	}

	// All checks should pass (no signatures/hash files is acceptable)
	if report.FailedChecks > 0 {
		t.Errorf("Expected no failed checks, got %d", report.FailedChecks)
		for _, result := range report.Results {
			if result.Status == "fail" {
				t.Logf("Failed check %s: %s", result.ID, result.Details)
			}
		}
	}

	// Verify each check ran and produced expected metadata
	checkResults := make(map[string]CheckResult)
	for _, result := range report.Results {
		checkResults[result.ID] = result
	}

	// Certificate check should find embedded certificate
	certResult := checkResults["check-5-certificate-validation"]
	if certResult.Metadata["certificate_count"].(int) == 0 {
		t.Error("Expected certificate check to find embedded certificate")
	}

	// Hash check should calculate hashes
	hashResult := checkResults["check-7-hash-integrity"]
	hashes := hashResult.Metadata["hashes"].(map[string]string)
	if len(hashes) == 0 {
		t.Error("Expected hash check to calculate hashes")
	}

	// Encryption check should find strong algorithms
	encResult := checkResults["check-8-encryption-standard"]
	strongAlgs := encResult.Metadata["strong_algorithms"].([]string)
	if len(strongAlgs) == 0 {
		t.Error("Expected encryption check to find strong algorithms")
	}
}