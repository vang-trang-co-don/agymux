package e2e_test

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"agymux/internal/ca"
)

// TestTier1_F1_01_RootCAGeneration verifies Root CA generation, X.509 extensions,
// ECDSA P-256 algorithm, and strict file permissions.
func TestTier1_F1_01_RootCAGeneration(t *testing.T) {
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")

	mgr, err := ca.EnsureCA(caDir)
	if err != nil {
		t.Fatalf("EnsureCA failed: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil CAManager")
	}

	certPath := filepath.Join(caDir, "ca.crt")
	keyPath := filepath.Join(caDir, "ca.key")

	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("ca.crt missing: %v", err)
	}
	if perm := certInfo.Mode().Perm(); perm != 0644 {
		t.Errorf("expected ca.crt permissions 0644, got %o", perm)
	}

	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("ca.key missing: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("expected ca.key permissions 0600, got %o", perm)
	}

	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read ca.crt: %v", err)
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		t.Fatal("failed to decode PEM block from ca.crt")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	if !cert.IsCA {
		t.Error("expected cert.IsCA to be true")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("expected KeyUsageCertSign in ca.crt")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("expected KeyUsageCRLSign in ca.crt")
	}
	if cert.Subject.CommonName != "agymux Local Proxy Root CA" {
		t.Errorf("expected CN 'agymux Local Proxy Root CA', got %q", cert.Subject.CommonName)
	}
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("expected ECDSA key, got %v", cert.PublicKeyAlgorithm)
	}
	if cert.NotAfter.Sub(cert.NotBefore) < 9*365*24*time.Hour {
		t.Errorf("expected ca validity ~10 years, got %v", cert.NotAfter.Sub(cert.NotBefore))
	}
}

// TestTier1_F1_02_CombinedCABundleCreation verifies combined_ca.crt creation.
func TestTier1_F1_02_CombinedCABundleCreation(t *testing.T) {
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")

	mgr, err := ca.EnsureCA(caDir)
	if err != nil {
		t.Fatalf("EnsureCA failed: %v", err)
	}

	combinedPath := filepath.Join(caDir, "combined_ca.crt")
	if mgr.CombinedPath != combinedPath {
		t.Errorf("expected CombinedPath %s, got %s", combinedPath, mgr.CombinedPath)
	}

	combinedData, err := os.ReadFile(combinedPath)
	if err != nil {
		t.Fatalf("failed to read combined_ca.crt: %v", err)
	}
	if len(combinedData) == 0 {
		t.Fatal("combined_ca.crt is empty")
	}

	caCertData, err := os.ReadFile(filepath.Join(caDir, "ca.crt"))
	if err != nil {
		t.Fatalf("failed to read ca.crt: %v", err)
	}

	// Verify combined_ca.crt contains the root CA certificate bytes
	if !containsSubslice(combinedData, caCertData) {
		t.Error("combined_ca.crt does not contain root CA cert PEM bytes")
	}
}

// TestTier1_F1_03_DynamicLeafCertDomainSANs verifies on-the-fly leaf cert generation
// for domain names, including wildcard and exact SAN matching, signed by root CA.
func TestTier1_F1_03_DynamicLeafCertDomainSANs(t *testing.T) {
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")

	mgr, err := ca.EnsureCA(caDir)
	if err != nil {
		t.Fatalf("EnsureCA failed: %v", err)
	}

	// Host with port should be stripped properly
	leaf, err := mgr.GetCertificate("cloudcode-pa.googleapis.com:443")
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if leaf == nil || len(leaf.Certificate) < 2 {
		t.Fatal("expected leaf certificate chain with at least leaf and CA")
	}

	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}

	rootCert, err := x509.ParseCertificate(leaf.Certificate[1])
	if err != nil {
		t.Fatalf("failed to parse root certificate from chain: %v", err)
	}

	// Verify signature from Root CA
	if err := leafCert.CheckSignatureFrom(rootCert); err != nil {
		t.Fatalf("leaf certificate was not signed by root CA: %v", err)
	}

	// Verify SANs
	expectedDNS := map[string]bool{
		"cloudcode-pa.googleapis.com":   true,
		"*.cloudcode-pa.googleapis.com": true,
	}
	for _, name := range leafCert.DNSNames {
		delete(expectedDNS, name)
	}
	if len(expectedDNS) > 0 {
		t.Errorf("missing expected DNS SANs in leaf cert: %v", expectedDNS)
	}
}

// TestTier1_F1_04_DynamicLeafCertIPAddressSAN verifies IP address SAN in leaf certs.
func TestTier1_F1_04_DynamicLeafCertIPAddressSAN(t *testing.T) {
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")

	mgr, err := ca.EnsureCA(caDir)
	if err != nil {
		t.Fatalf("EnsureCA failed: %v", err)
	}

	leaf, err := mgr.GetCertificate("127.0.0.1:8080")
	if err != nil {
		t.Fatalf("GetCertificate for IP failed: %v", err)
	}

	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}

	hasIP := false
	for _, ip := range leafCert.IPAddresses {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			hasIP = true
			break
		}
	}
	if !hasIP {
		t.Errorf("expected IP SAN 127.0.0.1, got %v", leafCert.IPAddresses)
	}
}

// TestTier1_F1_05_LeafCertInMemCache verifies cache reuse of minted certificates.
func TestTier1_F1_05_LeafCertInMemCache(t *testing.T) {
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")

	mgr, err := ca.EnsureCA(caDir)
	if err != nil {
		t.Fatalf("EnsureCA failed: %v", err)
	}

	cert1, err := mgr.GetCertificate("daily-cloudcode-pa.googleapis.com")
	if err != nil {
		t.Fatalf("first GetCertificate failed: %v", err)
	}

	cert2, err := mgr.GetCertificate("daily-cloudcode-pa.googleapis.com")
	if err != nil {
		t.Fatalf("second GetCertificate failed: %v", err)
	}

	// Should return the exact cached pointer
	if cert1 != cert2 {
		t.Error("expected cached certificate pointer to be returned")
	}
}

// TestTier1_F1_06_ExistingCAFilesPreserved verifies EnsureCA does not regenerate
// if valid CA files already exist.
func TestTier1_F1_06_ExistingCAFilesPreserved(t *testing.T) {
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")

	mgr1, err := ca.EnsureCA(caDir)
	if err != nil {
		t.Fatalf("initial EnsureCA failed: %v", err)
	}

	originalCertPEM, err := os.ReadFile(filepath.Join(caDir, "ca.crt"))
	if err != nil {
		t.Fatalf("failed to read ca.crt: %v", err)
	}

	mgr2, err := ca.EnsureCA(caDir)
	if err != nil {
		t.Fatalf("second EnsureCA failed: %v", err)
	}

	reloadedCertPEM, err := os.ReadFile(filepath.Join(caDir, "ca.crt"))
	if err != nil {
		t.Fatalf("failed to read reloaded ca.crt: %v", err)
	}

	if string(originalCertPEM) != string(reloadedCertPEM) {
		t.Error("existing ca.crt was regenerated instead of preserved")
	}
	if mgr1.CombinedPath != mgr2.CombinedPath {
		t.Errorf("combined path mismatch: %s != %s", mgr1.CombinedPath, mgr2.CombinedPath)
	}
}

func containsSubslice(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
