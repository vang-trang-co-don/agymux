package ca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestEnsureCA_CreationAndPermissions(t *testing.T) {
	dir := t.TempDir()

	mgr, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA failed: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil CAManager")
	}

	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	combinedPath := filepath.Join(dir, "combined_ca.crt")

	// 1. Verify files exist
	for _, path := range []string{certPath, keyPath, combinedPath} {
		if fi, err := os.Stat(path); err != nil {
			t.Errorf("file %s does not exist: %v", path, err)
		} else if fi.Size() == 0 {
			t.Errorf("file %s is empty", path)
		}
	}

	// 2. Verify key permission is 0600
	keyFi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat ca.key failed: %v", err)
	}
	if perm := keyFi.Mode().Perm(); perm != 0600 {
		t.Errorf("expected ca.key permission 0600, got %o", perm)
	}

	// 3. Verify Root CA certificate properties
	caCert := mgr.CACert()
	if caCert == nil {
		t.Fatal("expected non-nil CACert")
	}
	if !caCert.IsCA {
		t.Error("expected IsCA to be true")
	}
	if !caCert.BasicConstraintsValid {
		t.Error("expected BasicConstraintsValid to be true")
	}
	if caCert.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) == 0 {
		t.Error("expected KeyUsageCertSign and KeyUsageCRLSign")
	}
	if caCert.Subject.CommonName != "agymux Local Proxy Root CA" {
		t.Errorf("unexpected CommonName: %s", caCert.Subject.CommonName)
	}
	if len(caCert.Subject.Organization) == 0 || caCert.Subject.Organization[0] != "agymux" {
		t.Errorf("unexpected Organization: %v", caCert.Subject.Organization)
	}

	// 4. Verify Root CA self-signature
	if err := caCert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("self-signature verification failed: %v", err)
	}

	// 5. Verify CombinedCertPath accessor
	if mgr.CombinedCertPath() != combinedPath {
		t.Errorf("expected %s, got %s", combinedPath, mgr.CombinedCertPath())
	}
}

func TestEnsureCA_ReloadExisting(t *testing.T) {
	dir := t.TempDir()

	mgr1, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("first EnsureCA failed: %v", err)
	}

	mgr2, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("second EnsureCA failed: %v", err)
	}

	if mgr1.CACert().SerialNumber.Cmp(mgr2.CACert().SerialNumber) != 0 {
		t.Error("expected same serial number when reloaded from disk")
	}
	if mgr1.caKey.X.Cmp(mgr2.caKey.X) != 0 || mgr1.caKey.Y.Cmp(mgr2.caKey.Y) != 0 {
		t.Error("expected identical private/public keys when reloaded")
	}
}

func TestEnsureCA_CorruptKeyRegeneration(t *testing.T) {
	dir := t.TempDir()

	_, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA failed: %v", err)
	}

	// Corrupt key file
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(keyPath, []byte("GARBAGE DATA"), 0600); err != nil {
		t.Fatalf("failed to corrupt ca.key: %v", err)
	}

	mgr2, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA should recover and regenerate CA on corrupt key: %v", err)
	}
	if mgr2.CACert() == nil || mgr2.caKey == nil {
		t.Fatal("regenerated CA must have non-nil cert and key")
	}
}

func TestEnsureCombined_SystemRootsConcatenation(t *testing.T) {
	dir := t.TempDir()

	mgr, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA failed: %v", err)
	}

	data, err := os.ReadFile(mgr.CombinedCertPath())
	if err != nil {
		t.Fatalf("read combined_ca.crt failed: %v", err)
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(data); !ok {
		t.Fatal("failed to append certs from combined_ca.crt")
	}

	// Verify the Root CA validates a certificate signed by it using the combined pool
	leaf, err := mgr.GetCertificate("example.com")
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	opts := x509.VerifyOptions{
		Roots:   pool,
		DNSName: "example.com",
	}
	if _, err := leaf.Leaf.Verify(opts); err != nil {
		t.Errorf("leaf verification against combined pool failed: %v", err)
	}
}

func TestEnsureCombined_BoundaryNewlineHandling(t *testing.T) {
	dir := t.TempDir()

	// Mock system roots with one that has NO trailing newline
	mockSysRoot := filepath.Join(dir, "mock_sys.crt")
	block := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("mock certificate bytes for boundary test"),
	})
	// Strip trailing newline
	if len(block) > 0 && block[len(block)-1] == '\n' {
		block = block[:len(block)-1]
	}
	if err := os.WriteFile(mockSysRoot, block, 0644); err != nil {
		t.Fatalf("failed to write mock sys root: %v", err)
	}

	// Temporarily override systemRoots
	origRoots := systemRoots
	systemRoots = []string{mockSysRoot}
	defer func() { systemRoots = origRoots }()

	combinedPath := filepath.Join(dir, "combined_test.crt")
	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("mock ca certificate bytes"),
	})

	if err := ensureCombined(combinedPath, caPEM); err != nil {
		t.Fatalf("ensureCombined failed: %v", err)
	}

	combinedData, err := os.ReadFile(combinedPath)
	if err != nil {
		t.Fatalf("read combined file failed: %v", err)
	}

	// Decode all blocks: should cleanly decode 2 blocks
	b1, rest := pem.Decode(combinedData)
	if b1 == nil {
		t.Fatal("failed to decode first PEM block")
	}
	b2, _ := pem.Decode(rest)
	if b2 == nil {
		t.Fatal("failed to decode second PEM block due to missing newline delimiter")
	}
}

func TestGetCertificate_DomainSAN(t *testing.T) {
	dir := t.TempDir()
	mgr, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA failed: %v", err)
	}

	domain := "cloudcode-pa.googleapis.com"
	tlsCert, err := mgr.GetCertificate(domain)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if tlsCert == nil || tlsCert.Leaf == nil {
		t.Fatal("expected non-nil leaf certificate")
	}

	cert := tlsCert.Leaf
	if cert.Subject.CommonName != domain {
		t.Errorf("expected CommonName %s, got %s", domain, cert.Subject.CommonName)
	}

	// Verify SANs
	expectedDNS := []string{domain, "*." + domain}
	if len(cert.DNSNames) != 2 || cert.DNSNames[0] != expectedDNS[0] || cert.DNSNames[1] != expectedDNS[1] {
		t.Errorf("expected DNSNames %v, got %v", expectedDNS, cert.DNSNames)
	}
	if len(cert.IPAddresses) != 0 {
		t.Errorf("expected empty IPAddresses for domain, got %v", cert.IPAddresses)
	}

	// Verify signature against Root CA
	if err := cert.CheckSignatureFrom(mgr.CACert()); err != nil {
		t.Errorf("CheckSignatureFrom failed: %v", err)
	}

	// Verify verification options
	pool := x509.NewCertPool()
	pool.AddCert(mgr.CACert())

	// Exact domain match
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: domain}); err != nil {
		t.Errorf("verify exact domain failed: %v", err)
	}

	// Subdomain wildcard match
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "sub." + domain}); err != nil {
		t.Errorf("verify wildcard subdomain failed: %v", err)
	}
}

func TestGetCertificate_PortStripping(t *testing.T) {
	dir := t.TempDir()
	mgr, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA failed: %v", err)
	}

	c1, err := mgr.GetCertificate("cloudcode-pa.googleapis.com:443")
	if err != nil {
		t.Fatalf("GetCertificate with port failed: %v", err)
	}

	c2, err := mgr.GetCertificate("cloudcode-pa.googleapis.com")
	if err != nil {
		t.Fatalf("GetCertificate without port failed: %v", err)
	}

	if c1 != c2 {
		t.Error("expected port-stripped host to hit cache and return identical pointer")
	}
}

func TestGetCertificate_IPv4SAN(t *testing.T) {
	dir := t.TempDir()
	mgr, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA failed: %v", err)
	}

	tlsCert, err := mgr.GetCertificate("127.0.0.1:8080")
	if err != nil {
		t.Fatalf("GetCertificate for IPv4 failed: %v", err)
	}

	cert := tlsCert.Leaf
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("expected IPAddresses [127.0.0.1], got %v", cert.IPAddresses)
	}
	if len(cert.DNSNames) != 0 {
		t.Errorf("expected empty DNSNames for IP, got %v", cert.DNSNames)
	}

	pool := x509.NewCertPool()
	pool.AddCert(mgr.CACert())
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "127.0.0.1"}); err != nil {
		t.Errorf("verify IPv4 failed: %v", err)
	}
}

func TestGetCertificate_IPv6SAN(t *testing.T) {
	dir := t.TempDir()
	mgr, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA failed: %v", err)
	}

	testCases := []string{"::1", "[::1]", "[::1]:8443"}
	for _, tc := range testCases {
		tlsCert, err := mgr.GetCertificate(tc)
		if err != nil {
			t.Fatalf("GetCertificate for %s failed: %v", tc, err)
		}

		cert := tlsCert.Leaf
		if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("::1")) {
			t.Errorf("for host %s expected IPAddresses [::1], got %v", tc, cert.IPAddresses)
		}

		pool := x509.NewCertPool()
		pool.AddCert(mgr.CACert())
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "::1"}); err != nil {
			t.Errorf("verify IPv6 for host %s failed: %v", tc, err)
		}
	}
}

func TestGetCertificate_EmptyHost(t *testing.T) {
	dir := t.TempDir()
	mgr, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA failed: %v", err)
	}

	_, err = mgr.GetCertificate("")
	if err == nil {
		t.Error("expected error for empty host")
	}
}

func TestGetCertificate_Concurrency(t *testing.T) {
	dir := t.TempDir()
	mgr, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA failed: %v", err)
	}

	hosts := []string{
		"cloudcode-pa.googleapis.com",
		"daily-cloudcode-pa.googleapis.com",
		"127.0.0.1",
		"::1",
		"example.com",
		"test.local",
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			h := hosts[idx%len(hosts)]
			cert, err := mgr.GetCertificate(h)
			if err != nil || cert == nil {
				t.Errorf("concurrent GetCertificate failed for %s: %v", h, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestTLSHandshake_FullClientServer(t *testing.T) {
	dir := t.TempDir()
	mgr, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA failed: %v", err)
	}

	targetDomain := "cloudcode-pa.googleapis.com"

	// 1. Start TLS server with dynamically dispatched certificate
	serverTLSConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return mgr.GetCertificate(hello.ServerName)
		},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	if err != nil {
		t.Fatalf("tls.Listen failed: %v", err)
	}
	defer ln.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverDone <- err
			return
		}
		if _, err := conn.Write([]byte("PONG")); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	// 2. Client connects with combined_ca.crt as RootCAs
	combinedData, err := os.ReadFile(mgr.CombinedCertPath())
	if err != nil {
		t.Fatalf("read combined_ca.crt failed: %v", err)
	}

	clientRoots := x509.NewCertPool()
	if ok := clientRoots.AppendCertsFromPEM(combinedData); !ok {
		t.Fatal("failed to append certs from combined_ca.crt")
	}

	clientTLSConfig := &tls.Config{
		RootCAs:    clientRoots,
		ServerName: targetDomain,
	}

	clientConn, err := tls.Dial("tcp", ln.Addr().String(), clientTLSConfig)
	if err != nil {
		t.Fatalf("client tls.Dial failed: %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("PING")); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	resp := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, resp); err != nil {
		t.Fatalf("client read failed: %v", err)
	}
	if string(resp) != "PONG" {
		t.Errorf("expected PONG, got %s", string(resp))
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Errorf("server error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server timed out")
	}
}
