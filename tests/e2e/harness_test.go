package e2e_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain handles the mock agy child process execution pattern.
func TestMain(m *testing.M) {
	if os.Getenv("AGYMUX_MOCK_AGY_MODE") == "1" {
		runMockAgyProcess()
		return
	}

	tempDir, err := os.MkdirTemp("", "agymux-test-bin-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir for test binary: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tempDir)

	binPath := filepath.Join(tempDir, "agymux")
	cmd := exec.Command("go", "build", "-o", binPath, "agymux/cmd/agymux")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to pre-build agymux binary: %v\nOutput: %s\n", err, string(out))
		os.Exit(1)
	}
	os.Setenv("AGYMUX_BIN", binPath)

	os.Exit(m.Run())
}

// RecordedRequest stores details of an HTTP request received by MockGoogleBackend.
type RecordedRequest struct {
	Method  string
	Host    string
	URL     string
	Headers http.Header
	Body    []byte
	Token   string
}

// MockResponseRule dictates what response MockGoogleBackend returns.
type MockResponseRule struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
	IsSSE      bool
	SSEChunks  [][]byte
}

// MockGoogleBackend simulates Google Cloud Code PA backends with TLS.
type MockGoogleBackend struct {
	mu            sync.Mutex
	Server        *httptest.Server
	Requests      []*RecordedRequest
	ResponseRules []MockResponseRule
	DefaultStatus int
	DefaultBody   []byte
}

func NewMockGoogleBackend(t *testing.T) *MockGoogleBackend {
	t.Helper()

	mock := &MockGoogleBackend{
		Requests:      make([]*RecordedRequest, 0),
		ResponseRules: make([]MockResponseRule, 0),
		DefaultStatus: http.StatusOK,
		DefaultBody:   []byte(`{"candidates":[{"content":{"parts":[{"text":"Hello from Mock Antigravity"}]}}]}`),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mock.mu.Lock()
		defer mock.mu.Unlock()

		bodyBytes, _ := io.ReadAll(r.Body)
		authHeader := r.Header.Get("Authorization")
		token := ""
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}

		mock.Requests = append(mock.Requests, &RecordedRequest{
			Method:  r.Method,
			Host:    r.Host,
			URL:     r.URL.String(),
			Headers: r.Header.Clone(),
			Body:    bodyBytes,
			Token:   token,
		})

		reqIndex := len(mock.Requests) - 1
		rule := MockResponseRule{
			StatusCode: mock.DefaultStatus,
			Body:       mock.DefaultBody,
		}
		if reqIndex < len(mock.ResponseRules) {
			rule = mock.ResponseRules[reqIndex]
		}

		for k, v := range rule.Headers {
			w.Header().Set(k, v)
		}

		if rule.IsSSE {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			w.WriteHeader(rule.StatusCode)
			flusher, ok := w.(http.Flusher)
			for _, chunk := range rule.SSEChunks {
				_, _ = w.Write(chunk)
				if ok {
					flusher.Flush()
				}
				time.Sleep(5 * time.Millisecond)
			}
			return
		}

		w.WriteHeader(rule.StatusCode)
		_, _ = w.Write(rule.Body)
	})

	// Generate certificate for cloudcode-pa.googleapis.com and localhost
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate backend TLS key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "cloudcode-pa.googleapis.com",
			Organization: []string{"Google LLC Mock"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames: []string{
			"cloudcode-pa.googleapis.com",
			"*.cloudcode-pa.googleapis.com",
			"daily-cloudcode-pa.googleapis.com",
			"*.daily-cloudcode-pa.googleapis.com",
			"localhost",
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create backend TLS cert: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privKey,
	}

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	server.StartTLS()

	mock.Server = server
	return mock
}

func (m *MockGoogleBackend) Close() {
	if m.Server != nil {
		m.Server.Close()
	}
}

func (m *MockGoogleBackend) GetRequests() []*RecordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([]*RecordedRequest, len(m.Requests))
	copy(res, m.Requests)
	return res
}

func (m *MockGoogleBackend) ClearRequests() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Requests = make([]*RecordedRequest, 0)
}

func (m *MockGoogleBackend) SetResponseRules(rules []MockResponseRule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ResponseRules = rules
}

// MockOAuthServer simulates Google OAuth token endpoint.
type MockOAuthServer struct {
	mu           sync.Mutex
	Server       *httptest.Server
	ExchangeCode string
	TokensIssued map[string]string
	FailRefresh  bool
	FailExchange bool
}

func NewMockOAuthServer(t *testing.T) *MockOAuthServer {
	t.Helper()

	mock := &MockOAuthServer{
		TokensIssued: make(map[string]string),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mock.mu.Lock()
		defer mock.mu.Unlock()

		_ = r.ParseForm()
		grantType := r.Form.Get("grant_type")

		if grantType == "authorization_code" {
			if mock.FailExchange {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Code expired"}`))
				return
			}
			code := r.Form.Get("code")
			email := "user@example.com"
			if strings.Contains(code, "testuser2") {
				email = "user2@example.com"
			}

			// Generate mock JWT ID token
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
			payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"email":"%s","name":"Mock User"}`, email)))
			sig := base64.RawURLEncoding.EncodeToString([]byte("signature"))
			idToken := fmt.Sprintf("%s.%s.%s", header, payload, sig)

			accToken := "ya29.mock_access_token_" + code
			refToken := "1//mock_refresh_token_" + code
			mock.TokensIssued[code] = accToken

			resp := map[string]interface{}{
				"access_token":  accToken,
				"refresh_token": refToken,
				"expires_in":    3600,
				"id_token":      idToken,
				"token_type":    "Bearer",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		if grantType == "refresh_token" {
			if mock.FailRefresh {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Token revoked"}`))
				return
			}
			refToken := r.Form.Get("refresh_token")
			accToken := "ya29.refreshed_" + refToken

			resp := map[string]interface{}{
				"access_token": accToken,
				"expires_in":   3600,
				"token_type":   "Bearer",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"unsupported_grant_type"}`))
	})

	mock.Server = httptest.NewServer(handler)
	return mock
}

func (m *MockOAuthServer) Close() {
	if m.Server != nil {
		m.Server.Close()
	}
}

// TestAccount represents account schema stored in ~/.agymux/accounts.json.
type TestAccount struct {
	Email         string    `json:"email"`
	RefreshToken  string    `json:"refresh_token"`
	AccessToken   string    `json:"access_token"`
	ExpiresAt     time.Time `json:"expires_at"`
	CooldownUntil time.Time `json:"cooldown_until"`
	AddedAt       time.Time `json:"added_at"`
	Tier          string    `json:"tier,omitempty"`
}

// TestPool represents pool schema stored in ~/.agymux/accounts.json.
type TestPool struct {
	Accounts   []*TestAccount `json:"accounts"`
	CurrentIdx int            `json:"current_idx"`
}

// TestEnv provides a fully hermetic test environment with temporary homes and mocks.
type TestEnv struct {
	T               *testing.T
	TempDir         string
	HomeDir         string
	ConfigDir       string
	BinDir          string
	AgyWrapperPath  string
	AgyArgsFile     string
	AgyEnvFile      string
	AgyRespFile     string
	MockGoogle      *MockGoogleBackend
	MockOAuth       *MockOAuthServer
	BinaryPath      string
	UpstreamAddress string
}

func NewTestEnv(t *testing.T) *TestEnv {
	t.Helper()

	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "home")
	configDir := filepath.Join(homeDir, ".agymux")
	binDir := filepath.Join(tempDir, "bin")

	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("failed to create bin dir: %v", err)
	}

	mockGoogle := NewMockGoogleBackend(t)
	mockOAuth := NewMockOAuthServer(t)

	// Create wrapper script for agy
	agyArgsFile := filepath.Join(tempDir, "agy_args.json")
	agyEnvFile := filepath.Join(tempDir, "agy_env.json")
	agyRespFile := filepath.Join(tempDir, "agy_resp.json")

	currentExe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get test executable: %v", err)
	}

	agyWrapperPath := filepath.Join(binDir, "agy")
	wrapperScript := fmt.Sprintf(`#!/bin/sh
export AGYMUX_MOCK_AGY_MODE=1
export AGY_ARGS_FILE="%s"
export AGY_ENV_FILE="%s"
export AGY_RESP_FILE="%s"
exec "%s" "$@"
`, agyArgsFile, agyEnvFile, agyRespFile, currentExe)

	if err := os.WriteFile(agyWrapperPath, []byte(wrapperScript), 0755); err != nil {
		t.Fatalf("failed to write agy wrapper script: %v", err)
	}

	u, _ := url.Parse(mockGoogle.Server.URL)
	upstreamAddr := u.Host

	return &TestEnv{
		T:               t,
		TempDir:         tempDir,
		HomeDir:         homeDir,
		ConfigDir:       configDir,
		BinDir:          binDir,
		AgyWrapperPath:  agyWrapperPath,
		AgyArgsFile:     agyArgsFile,
		AgyEnvFile:      agyEnvFile,
		AgyRespFile:     agyRespFile,
		MockGoogle:      mockGoogle,
		MockOAuth:       mockOAuth,
		UpstreamAddress: upstreamAddr,
	}
}

func (e *TestEnv) Cleanup() {
	if e.MockGoogle != nil {
		e.MockGoogle.Close()
	}
	if e.MockOAuth != nil {
		e.MockOAuth.Close()
	}
}

// GetBinary builds or resolves the agymux CLI executable.
func (e *TestEnv) GetBinary() string {
	e.T.Helper()
	if e.BinaryPath != "" {
		return e.BinaryPath
	}

	if bin := os.Getenv("AGYMUX_BIN"); bin != "" {
		if _, err := os.Stat(bin); err == nil {
			e.BinaryPath = bin
			return bin
		}
	}

	binPath := filepath.Join(e.TempDir, "agymux")
	cmd := exec.Command("go", "build", "-o", binPath, "agymux/cmd/agymux")
	cmd.Dir = filepath.Join(findRepoRoot(e.T))
	out, err := cmd.CombinedOutput()
	if err != nil {
		e.T.Fatalf("failed to build agymux binary: %v\nOutput: %s", err, string(out))
	}

	e.BinaryPath = binPath
	return binPath
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working dir: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "/home/dungcq/projects/agymux"
}

// Command constructs an *exec.Cmd for agymux with the isolated test environment.
func (e *TestEnv) Command(args ...string) *exec.Cmd {
	e.T.Helper()
	bin := e.GetBinary()

	cmd := exec.Command(bin, args...)
	cmd.Dir = e.TempDir

	overrides := fmt.Sprintf("cloudcode-pa.googleapis.com=%s,daily-cloudcode-pa.googleapis.com=%s",
		e.UpstreamAddress, e.UpstreamAddress)

	cmd.Env = append(os.Environ(),
		"HOME="+e.HomeDir,
		"PATH="+e.BinDir+":"+os.Getenv("PATH"),
		"AGYMUX_UPSTREAM_OVERRIDE="+overrides,
		"AGYMUX_TOKEN_ENDPOINT="+e.MockOAuth.Server.URL,
		"AGYMUX_CONFIG_DIR="+e.ConfigDir,
	)
	return cmd
}

// RunAgymux runs agymux binary with the isolated test environment.
func (e *TestEnv) RunAgymux(args []string, stdin string) (stdout, stderr string, exitCode int, err error) {
	e.T.Helper()
	bin := e.GetBinary()

	cmd := exec.Command(bin, args...)
	cmd.Dir = e.TempDir

	overrides := fmt.Sprintf("cloudcode-pa.googleapis.com=%s,daily-cloudcode-pa.googleapis.com=%s",
		e.UpstreamAddress, e.UpstreamAddress)

	cmd.Env = append(os.Environ(),
		"HOME="+e.HomeDir,
		"PATH="+e.BinDir+":"+os.Getenv("PATH"),
		"AGYMUX_UPSTREAM_OVERRIDE="+overrides,
		"AGYMUX_TOKEN_ENDPOINT="+e.MockOAuth.Server.URL,
		"AGYMUX_CONFIG_DIR="+e.ConfigDir,
	)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	runErr := cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
		err = runErr
	} else {
		exitCode = 0
	}

	return stdout, stderr, exitCode, err
}

// SeedAccounts saves a populated accounts.json in the test config directory.
func (e *TestEnv) SeedAccounts(accounts []*TestAccount, currentIdx int) {
	e.T.Helper()
	pool := TestPool{
		Accounts:   accounts,
		CurrentIdx: currentIdx,
	}
	data, err := json.MarshalIndent(pool, "", "  ")
	if err != nil {
		e.T.Fatalf("failed to serialize test accounts: %v", err)
	}
	configPath := filepath.Join(e.ConfigDir, "accounts.json")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		e.T.Fatalf("failed to write test accounts.json: %v", err)
	}
}

// ReadAccounts loads accounts.json from the test config directory.
func (e *TestEnv) ReadAccounts() *TestPool {
	e.T.Helper()
	configPath := filepath.Join(e.ConfigDir, "accounts.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		e.T.Fatalf("failed to read test accounts.json: %v", err)
	}
	var pool TestPool
	if err := json.Unmarshal(data, &pool); err != nil {
		e.T.Fatalf("failed to unmarshal test accounts.json: %v", err)
	}
	return &pool
}

// runMockAgyProcess is executed when mock agy is invoked.
func runMockAgyProcess() {
	argsFile := os.Getenv("AGY_ARGS_FILE")
	envFile := os.Getenv("AGY_ENV_FILE")
	respFile := os.Getenv("AGY_RESP_FILE")

	// Save args
	if argsFile != "" {
		argsJSON, _ := json.Marshal(os.Args[1:])
		_ = os.WriteFile(argsFile, argsJSON, 0644)
	}

	// Save env
	if envFile != "" {
		envMap := map[string]string{
			"HTTP_PROXY":    os.Getenv("HTTP_PROXY"),
			"HTTPS_PROXY":   os.Getenv("HTTPS_PROXY"),
			"SSL_CERT_FILE": os.Getenv("SSL_CERT_FILE"),
			"http_proxy":    os.Getenv("http_proxy"),
			"https_proxy":   os.Getenv("https_proxy"),
		}
		envJSON, _ := json.Marshal(envMap)
		_ = os.WriteFile(envFile, envJSON, 0644)
	}

	// If AGY_DO_HTTP_REQUEST is requested, make an HTTPS request via proxy
	reqURL := os.Getenv("AGY_REQUEST_URL")
	if reqURL != "" {
		doClientRequest(reqURL, respFile)
	}

	// Exit code
	if exitCodeStr := os.Getenv("AGY_EXIT_CODE"); exitCodeStr != "" {
		if code, err := strconv.Atoi(exitCodeStr); err == nil {
			os.Exit(code)
		}
	}

	os.Exit(0)
}

func doClientRequest(reqURL, respFile string) {
	proxyURLStr := os.Getenv("HTTPS_PROXY")
	if proxyURLStr == "" {
		proxyURLStr = os.Getenv("HTTP_PROXY")
	}

	caCertPath := os.Getenv("SSL_CERT_FILE")
	var rootCAs *x509.CertPool
	if caCertPath != "" {
		rootCAs = x509.NewCertPool()
		caData, err := os.ReadFile(caCertPath)
		if err == nil {
			rootCAs.AppendCertsFromPEM(caData)
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: rootCAs,
		},
	}
	if proxyURLStr != "" {
		u, err := url.Parse(proxyURLStr)
		if err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	method := os.Getenv("AGY_REQUEST_METHOD")
	if method == "" {
		method = "POST"
	}
	bodyStr := os.Getenv("AGY_REQUEST_BODY")
	if bodyStr == "" {
		bodyStr = `{"prompt":"Hello Model"}`
	}

	req, err := http.NewRequest(method, reqURL, strings.NewReader(bodyStr))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if clientAuth := os.Getenv("AGY_REQUEST_AUTH"); clientAuth != "" {
		req.Header.Set("Authorization", clientAuth)
	}

	resp, err := client.Do(req)
	if err != nil {
		if respFile != "" {
			errMap := map[string]interface{}{"error": err.Error()}
			d, _ := json.Marshal(errMap)
			_ = os.WriteFile(respFile, d, 0644)
		}
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if respFile != "" {
		out := map[string]interface{}{
			"status_code": resp.StatusCode,
			"headers":     resp.Header,
			"body":        string(respBody),
		}
		d, _ := json.Marshal(out)
		_ = os.WriteFile(respFile, d, 0644)
	}
}
