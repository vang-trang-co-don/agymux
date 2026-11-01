package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Default system root certificate paths across Linux distributions.
var systemRoots = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
	"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
	"/etc/pki/tls/cacert.pem",                           // OpenELEC
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7+
	"/etc/ssl/cert.pem",                                 // Alpine Linux / macOS / BSD
}

type CAManager struct {
	mu           sync.RWMutex
	caCert       *x509.Certificate
	caKey        *ecdsa.PrivateKey
	caCertPEM    []byte
	CombinedPath string
	leafCache    map[string]*tls.Certificate
}

// EnsureCA initializes or loads the Root CA in the given directory.
func EnsureCA(dir string) (*CAManager, error) {
	if dir == "" {
		if env := os.Getenv("AGYMUX_CONFIG_DIR"); env != "" {
			dir = env
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				home = "."
			}
			dir = filepath.Join(home, ".agymux")
		}
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("không thể tạo thư mục CA %s: %w", dir, err)
	}

	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	combinedPath := filepath.Join(dir, "combined_ca.crt")

	mgr := &CAManager{
		CombinedPath: combinedPath,
		leafCache:    make(map[string]*tls.Certificate),
	}

	certPEM, errCert := os.ReadFile(certPath)
	keyPEM, errKey := os.ReadFile(keyPath)

	if errCert == nil && errKey == nil {
		block, _ := pem.Decode(certPEM)
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				keyBlock, _ := pem.Decode(keyPEM)
				if keyBlock != nil {
					key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
					if err == nil {
						mgr.caCert = cert
						mgr.caKey = key
						mgr.caCertPEM = certPEM
						if err := ensureCombined(combinedPath, certPEM); err != nil {
							return nil, fmt.Errorf("lỗi cập nhật combined_ca.crt: %w", err)
						}
						return mgr, nil
					}
				}
			}
		}
	}

	// Generate new Root CA
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("lỗi sinh CA key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("lỗi sinh CA serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "agymux Local Proxy Root CA",
			Organization: []string{"agymux"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("lỗi tạo chứng chỉ CA: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("lỗi parse chứng chỉ CA mới sinh: %w", err)
	}

	mgr.caCert = cert
	mgr.caKey = privKey
	mgr.caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("lỗi marshal EC key: %w", err)
	}
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	if err := os.WriteFile(certPath, mgr.caCertPEM, 0644); err != nil {
		return nil, fmt.Errorf("lỗi ghi ca.crt: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEMBytes, 0600); err != nil {
		return nil, fmt.Errorf("lỗi ghi ca.key: %w", err)
	}
	if err := ensureCombined(combinedPath, mgr.caCertPEM); err != nil {
		return nil, fmt.Errorf("lỗi tạo combined_ca.crt: %w", err)
	}

	return mgr, nil
}

// CombinedCertPath satisfies the ca interface contract.
func (m *CAManager) CombinedCertPath() string {
	return m.CombinedPath
}

// CACert returns the parsed Root CA certificate.
func (m *CAManager) CACert() *x509.Certificate {
	return m.caCert
}

// CACertPEM returns the PEM-encoded Root CA certificate bytes.
func (m *CAManager) CACertPEM() []byte {
	return m.caCertPEM
}

func ensureCombined(combinedPath string, caPEM []byte) error {
	var combined []byte

	// Check environment variable first if set
	if envCert := os.Getenv("SSL_CERT_FILE"); envCert != "" && envCert != combinedPath {
		if data, err := os.ReadFile(envCert); err == nil && len(data) > 0 {
			combined = append(combined, data...)
			if combined[len(combined)-1] != '\n' {
				combined = append(combined, '\n')
			}
		}
	}

	// Search known system root locations if not loaded from env
	if len(combined) == 0 {
		for _, sysRoot := range systemRoots {
			if data, err := os.ReadFile(sysRoot); err == nil && len(data) > 0 {
				combined = append(combined, data...)
				if combined[len(combined)-1] != '\n' {
					combined = append(combined, '\n')
				}
				break
			}
		}
	}

	combined = append(combined, caPEM...)
	return os.WriteFile(combinedPath, combined, 0644)
}

// GetCertificate returns a dynamic leaf certificate signed by the Root CA for the requested host.
func (m *CAManager) GetCertificate(host string) (*tls.Certificate, error) {
	// Strip port
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")

	if host == "" {
		return nil, fmt.Errorf("host không được để trống")
	}

	m.mu.RLock()
	if cert, ok := m.leafCache[host]; ok {
		m.mu.RUnlock()
		return cert, nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double check
	if cert, ok := m.leafCache[host]; ok {
		return cert, nil
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("lỗi sinh leaf serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"agymux MitM"},
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		if strings.HasPrefix(host, "*.") {
			base := strings.TrimPrefix(host, "*.")
			template.DNSNames = []string{host, base}
		} else {
			template.DNSNames = []string{host, "*." + host}
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, m.caCert, &privKey.PublicKey, m.caKey)
	if err != nil {
		return nil, err
	}

	leafCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("lỗi parse leaf certificate: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{derBytes, m.caCert.Raw},
		PrivateKey:  privKey,
		Leaf:        leafCert,
	}

	m.leafCache[host] = tlsCert
	return tlsCert, nil
}
