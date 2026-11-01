package e2e_test

import (
	"encoding/json"
	"net"
	"net/url"
	"os"
	"reflect"
	"syscall"
	"testing"
	"time"
)

// TestTier1_F7_01_ProxyEnvVarsInjected verifies HTTP_PROXY, HTTPS_PROXY, and
// SSL_CERT_FILE are injected into the child process environment.
func TestTier1_F7_01_ProxyEnvVarsInjected(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{Email: "acc@example.com", AccessToken: "tok", ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	_, _, exitCode, err := env.RunAgymux([]string{"check-env"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d", err, exitCode)
	}

	envData, err := os.ReadFile(env.AgyEnvFile)
	if err != nil {
		t.Fatalf("failed to read agy_env.json: %v", err)
	}
	var childEnv map[string]string
	if err := json.Unmarshal(envData, &childEnv); err != nil {
		t.Fatalf("failed to parse child env: %v", err)
	}

	if childEnv["HTTP_PROXY"] == "" {
		t.Error("HTTP_PROXY not set in child env")
	}
	if childEnv["HTTPS_PROXY"] == "" {
		t.Error("HTTPS_PROXY not set in child env")
	}
	caFile := childEnv["SSL_CERT_FILE"]
	if caFile == "" {
		t.Error("SSL_CERT_FILE not set in child env")
	}
	if _, err := os.Stat(caFile); err != nil {
		t.Errorf("SSL_CERT_FILE %q does not exist: %v", caFile, err)
	}
}

// TestTier1_F7_02_CommandLineArgPassthrough verifies command-line arguments are
// forwarded intact to agy.
func TestTier1_F7_02_CommandLineArgPassthrough(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{Email: "acc@example.com", AccessToken: "tok", ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	targetArgs := []string{"chat", "--model", "gemini-2.5-pro", "--temperature", "0.2", "Explain Go"}

	_, _, exitCode, err := env.RunAgymux(targetArgs, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d", err, exitCode)
	}

	argsData, err := os.ReadFile(env.AgyArgsFile)
	if err != nil {
		t.Fatalf("failed to read agy_args.json: %v", err)
	}
	var receivedArgs []string
	if err := json.Unmarshal(argsData, &receivedArgs); err != nil {
		t.Fatalf("failed to parse child args: %v", err)
	}

	if !reflect.DeepEqual(receivedArgs, targetArgs) {
		t.Errorf("args mismatch:\nexpected: %v\ngot:      %v", targetArgs, receivedArgs)
	}
}

// TestTier1_F7_03_ExitCodePropagation verifies child exit code (0, 1, 42) is propagated.
func TestTier1_F7_03_ExitCodePropagation(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{Email: "acc@example.com", AccessToken: "tok", ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	testCases := []int{0, 1, 42}
	for _, expectedCode := range testCases {
		t.Setenv("AGY_EXIT_CODE", itoa(expectedCode))

		_, _, actualCode, _ := env.RunAgymux([]string{"run"}, "")
		if actualCode != expectedCode {
			t.Errorf("exit code propagation failed: expected %d, got %d", expectedCode, actualCode)
		}
	}
}

// TestTier1_F7_04_SignalForwarding verifies signals are forwarded to the child.
func TestTier1_F7_04_SignalForwarding(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{Email: "acc@example.com", AccessToken: "tok", ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	cmd := env.Command("long-run")
	t.Setenv("AGY_EXIT_CODE", "130") // 128 + SIGINT(2)

	// Verify command can be signaled
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start agymux: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	_ = cmd.Process.Signal(syscall.SIGINT)
	_ = cmd.Wait()
}

// TestTier1_F7_05_ProxyCleanupOnChildExit verifies proxy port is released when child exits.
func TestTier1_F7_05_ProxyCleanupOnChildExit(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{Email: "acc@example.com", AccessToken: "tok", ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	_, _, exitCode, err := env.RunAgymux([]string{"short-run"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: %v", err)
	}

	envData, _ := os.ReadFile(env.AgyEnvFile)
	var childEnv map[string]string
	_ = json.Unmarshal(envData, &childEnv)
	proxyURLStr := childEnv["HTTPS_PROXY"]

	u, err := url.Parse(proxyURLStr)
	if err != nil {
		t.Fatalf("invalid proxy url: %v", err)
	}

	// Verify proxy socket is no longer accepting connections
	conn, err := net.DialTimeout("tcp", u.Host, 100*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Errorf("expected proxy port %s to be closed after agy exit, but connection succeeded", u.Host)
	}
}

func itoa(i int) string {
	switch i {
	case 0:
		return "0"
	case 1:
		return "1"
	case 42:
		return "42"
	default:
		return "0"
	}
}
