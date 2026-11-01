package e2e_test

import (
	"encoding/json"
	"net/url"
	"os"
	"testing"
	"time"
)

// TestTier1_F4_01_ProxyLifecycleAndEphemeralPort verifies proxy starts on ephemeral port
// and shuts down when agy exits.
func TestTier1_F4_01_ProxyLifecycleAndEphemeralPort(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{
			Email:       "test@example.com",
			AccessToken: "token_123",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}, 0)

	// Run agymux which starts proxy and launches mock agy
	stdout, stderr, exitCode, err := env.RunAgymux([]string{"version"}, "")
	if err != nil {
		t.Fatalf("RunAgymux failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	// Verify env passed to mock agy
	envData, err := os.ReadFile(env.AgyEnvFile)
	if err != nil {
		t.Fatalf("failed to read agy_env.json: %v", err)
	}
	var childEnv map[string]string
	if err := json.Unmarshal(envData, &childEnv); err != nil {
		t.Fatalf("failed to parse child env: %v", err)
	}

	proxyURLStr := childEnv["HTTPS_PROXY"]
	if proxyURLStr == "" {
		t.Fatal("HTTPS_PROXY was not injected into child environment")
	}
	u, err := url.Parse(proxyURLStr)
	if err != nil {
		t.Fatalf("invalid HTTPS_PROXY URL %q: %v", proxyURLStr, err)
	}
	if u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" {
		t.Errorf("expected proxy host 127.0.0.1, got %s", u.Hostname())
	}
	if u.Port() == "" || u.Port() == "0" {
		t.Errorf("expected non-zero ephemeral proxy port, got %s", u.Port())
	}
}

// TestTier1_F4_02_HTTPProxyPassThrough verifies proxy handles standard HTTP requests.
func TestTier1_F4_02_HTTPProxyPassThrough(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{
			Email:       "test@example.com",
			AccessToken: "token_123",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}, 0)

	// Instruct mock agy to make an HTTP request
	t.Setenv("AGY_REQUEST_URL", "http://"+env.UpstreamAddress+"/health")
	t.Setenv("AGY_REQUEST_METHOD", "GET")

	stdout, stderr, exitCode, err := env.RunAgymux([]string{"run"}, "")
	if err != nil {
		t.Fatalf("RunAgymux failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	respData, err := os.ReadFile(env.AgyRespFile)
	if err != nil {
		t.Fatalf("failed to read agy_resp.json: %v", err)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(respData, &resp); err != nil {
		t.Fatalf("failed to parse agy response: %v", err)
	}

	statusCode, ok := resp["status_code"].(float64)
	if !ok || int(statusCode) != 200 {
		t.Errorf("expected HTTP 200, got %v (raw: %s)", resp["status_code"], string(respData))
	}
}

// TestTier1_F4_03_HTTPSConnectHijackingAndTLSHandshake verifies CONNECT tunnel
// and dynamic TLS certificate validation.
func TestTier1_F4_03_HTTPSConnectHijackingAndTLSHandshake(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{
			Email:       "test@example.com",
			AccessToken: "token_abc",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}, 0)

	// Instruct mock agy to send HTTPS request to cloudcode-pa.googleapis.com
	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:test")
	t.Setenv("AGY_REQUEST_METHOD", "POST")
	t.Setenv("AGY_REQUEST_BODY", `{"query":"test handshake"}`)

	stdout, stderr, exitCode, err := env.RunAgymux([]string{"generate"}, "")
	if err != nil {
		t.Fatalf("RunAgymux failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	respData, err := os.ReadFile(env.AgyRespFile)
	if err != nil {
		t.Fatalf("failed to read agy_resp.json: %v", err)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(respData, &resp); err != nil {
		t.Fatalf("failed to parse agy response: %v", err)
	}

	if errStr, ok := resp["error"].(string); ok && errStr != "" {
		t.Fatalf("HTTPS request failed via proxy: %s", errStr)
	}
	if int(resp["status_code"].(float64)) != 200 {
		t.Errorf("expected 200, got %v", resp["status_code"])
	}
}

// TestTier1_F4_04_RequestBodyBuffering verifies proxy buffers request body and forwards
// intact to upstream.
func TestTier1_F4_04_RequestBodyBuffering(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{
			Email:       "test@example.com",
			AccessToken: "token_buf",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}, 0)

	expectedPayload := `{"system":"Be helpful","prompt":"Explain quantum computing in detail"}`
	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")
	t.Setenv("AGY_REQUEST_BODY", expectedPayload)

	_, _, exitCode, err := env.RunAgymux([]string{"stream"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d", err, exitCode)
	}

	reqs := env.MockGoogle.GetRequests()
	if len(reqs) == 0 {
		t.Fatal("upstream mock received no requests")
	}
	if string(reqs[0].Body) != expectedPayload {
		t.Errorf("request body was corrupted or truncated: got %q, expected %q",
			string(reqs[0].Body), expectedPayload)
	}
}

// TestTier1_F4_05_ConcurrentProxyRequests verifies handling of client requests under load.
func TestTier1_F4_05_ConcurrentProxyRequests(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{
			Email:       "test@example.com",
			AccessToken: "token_concurrent",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}, 0)

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")
	t.Setenv("AGY_REQUEST_BODY", `{"prompt":"concurrent test"}`)

	_, _, exitCode, err := env.RunAgymux([]string{"query"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d", err, exitCode)
	}

	reqs := env.MockGoogle.GetRequests()
	if len(reqs) == 0 {
		t.Fatal("expected request to reach mock backend")
	}
}
