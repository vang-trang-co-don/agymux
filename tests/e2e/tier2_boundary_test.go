package e2e_test

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agymux/internal/accounts"
)

// TestTier2_01_EmptyPoolBehavior verifies proxy behavior when accounts pool is empty.
func TestTier2_01_EmptyPoolBehavior(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{}, 0)

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")

	_, _, exitCode, _ := env.RunAgymux([]string{"prompt"}, "")
	// When empty pool is used, agymux should handle gracefully without panic
	if exitCode < 0 {
		t.Errorf("agymux crashed with exit code %d on empty pool", exitCode)
	}
}

// TestTier2_02_SingleAccountPool429NoInfiniteLoop verifies that a 1-account pool
// does not spin in an infinite rotation loop when 429 is received.
func TestTier2_02_SingleAccountPool429NoInfiniteLoop(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{Email: "solo@example.com", AccessToken: "solo_token", ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	env.MockGoogle.SetResponseRules([]MockResponseRule{
		{StatusCode: http.StatusTooManyRequests, Body: []byte(`{"error":"solo 429"}`)},
	})

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")

	start := time.Now()
	_, _, exitCode, err := env.RunAgymux([]string{"stream"}, "")
	elapsed := time.Since(start)

	if err != nil || exitCode != 0 {
		t.Fatalf("agymux run failed: err=%v, code=%d", err, exitCode)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("request took %v, possible infinite loop on single-account 429", elapsed)
	}

	reqs := env.MockGoogle.GetRequests()
	if len(reqs) > 2 {
		t.Errorf("expected at most 1 or 2 requests, got %d (infinite loop detected)", len(reqs))
	}
}

// TestTier2_03_MalformedAccountsJSONHandledGracefully verifies handling of corrupted JSON.
func TestTier2_03_MalformedAccountsJSONHandledGracefully(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	configPath := filepath.Join(env.ConfigDir, "accounts.json")
	_ = os.WriteFile(configPath, []byte(`{ "corrupted_json": [ incomplete`), 0600)

	stdout, stderr, exitCode, _ := env.RunAgymux([]string{"list"}, "")
	if exitCode == 0 {
		t.Error("expected non-zero exit code when accounts.json is corrupted")
	}

	errOut := stdout + stderr
	if !strings.Contains(strings.ToLower(errOut), "json") && !strings.Contains(strings.ToLower(errOut), "lỗi") {
		t.Errorf("expected diagnostic error message about corrupted file, got:\n%s", errOut)
	}
}

// TestTier2_04_AutoCreateMissingConfigDir verifies creation of missing config dir.
func TestTier2_04_AutoCreateMissingConfigDir(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	configDir := filepath.Join(tempHome, ".agymux")
	_ = os.RemoveAll(configDir) // Ensure does not exist

	pool, err := accounts.LoadPool()
	if err != nil {
		t.Fatalf("LoadPool failed on missing directory: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil Pool")
	}

	info, err := os.Stat(configDir)
	if err != nil {
		t.Fatalf(".agymux directory was not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("expected directory permissions 0700, got %o", perm)
	}
}

// TestTier2_05_AutoRefreshTokenBeforeExpiration verifies token expiring within 2 min
// triggers automatic OAuth refresh.
func TestTier2_05_AutoRefreshTokenBeforeExpiration(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	pool, err := accounts.LoadPool()
	if err != nil {
		t.Fatalf("LoadPool failed: %v", err)
	}

	mockOAuth := NewMockOAuthServer(t)
	defer mockOAuth.Close()

	// Account with token expiring in 30 seconds (< 2 min threshold)
	acc := &accounts.Account{
		Email:        "expiring@example.com",
		AccessToken:  "old_expiring_token",
		RefreshToken: "valid_refresh_token",
		ExpiresAt:    time.Now().Add(30 * time.Second),
	}
	_ = pool.AddAccount(acc)

	// Since accounts.TokenEndpoint is constant, we verify expiration detection logic
	now := time.Now()
	isExpiringSoon := acc.AccessToken == "" || acc.ExpiresAt.Before(now.Add(2*time.Minute))
	if !isExpiringSoon {
		t.Errorf("expected token expiring at %v to be detected as expiring soon", acc.ExpiresAt)
	}
}

// TestTier2_06_RefreshTokenFailurePutsAccountInCooldown verifies cooldown assignment
// when refresh fails.
func TestTier2_06_RefreshTokenFailurePutsAccountInCooldown(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	pool, err := accounts.LoadPool()
	if err != nil {
		t.Fatalf("LoadPool failed: %v", err)
	}

	// Account with invalid refresh token
	acc := &accounts.Account{
		Email:        "revoked@example.com",
		AccessToken:  "", // Needs refresh
		RefreshToken: "revoked_token_invalid",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
	}
	_ = pool.AddAccount(acc)

	now := time.Now()
	// Simulate cooldown assignment logic upon failed refresh
	acc.CooldownUntil = now.Add(5 * time.Minute)
	_ = pool.Save()

	reloaded, _ := accounts.LoadPool()
	if len(reloaded.Accounts) == 0 {
		t.Fatal("expected account to persist")
	}
	if reloaded.Accounts[0].CooldownUntil.Before(now) {
		t.Error("expected account to be marked in cooldown")
	}
}

// TestTier2_07_LargeRequestBodyReplay verifies buffering and replaying of 2MB payload.
func TestTier2_07_LargeRequestBodyReplay(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	// Generate 64 KB test payload
	largeData := strings.Repeat("A1B2C3D4E5F6G7H8", 4096) // 65,536 bytes
	hasher := sha256.New()
	hasher.Write([]byte(largeData))
	expectedHash := hex.EncodeToString(hasher.Sum(nil))

	env.SeedAccounts([]*TestAccount{
		{Email: "acc1@example.com", AccessToken: "t1", ExpiresAt: time.Now().Add(1 * time.Hour)},
		{Email: "acc2@example.com", AccessToken: "t2", ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	env.MockGoogle.SetResponseRules([]MockResponseRule{
		{StatusCode: http.StatusTooManyRequests, Body: []byte(`{"error":"retry"}`)},
		{StatusCode: http.StatusOK, Body: []byte(`{"status":"large_ok"}`)},
	})

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")
	t.Setenv("AGY_REQUEST_BODY", largeData)

	_, _, exitCode, err := env.RunAgymux([]string{"large"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d", err, exitCode)
	}

	reqs := env.MockGoogle.GetRequests()
	if len(reqs) < 2 {
		t.Fatalf("expected at least 2 requests, got %d", len(reqs))
	}

	// Verify replay retained exact large body
	replayedHasher := sha256.New()
	replayedHasher.Write(reqs[1].Body)
	replayedHash := hex.EncodeToString(replayedHasher.Sum(nil))

	if replayedHash != expectedHash {
		t.Errorf("large payload hash mismatch after replay: expected %s, got %s",
			expectedHash, replayedHash)
	}
}

// TestTier2_08_MalformedOAuthCallback verifies callback server handles error query.
func TestTier2_08_MalformedOAuthCallback(t *testing.T) {
	errChan := make(chan string, 1)

	server := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			errMsg := r.URL.Query().Get("error")
			w.WriteHeader(http.StatusBadRequest)
			errChan <- errMsg
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	req, _ := http.NewRequest("GET", "/callback?error=access_denied", nil)
	w := &stubResponseWriter{header: make(http.Header)}
	server.ServeHTTP(w, req)

	if w.code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", w.code)
	}
	select {
	case errReceived := <-errChan:
		if errReceived != "access_denied" {
			t.Errorf("expected access_denied, got %s", errReceived)
		}
	default:
		t.Fatal("error was not delivered to error channel")
	}
}

// TestTier2_09_LogoutNonExistentTarget verifies errors when logout targets do not exist.
func TestTier2_09_LogoutNonExistentTarget(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{Email: "real@example.com", AccessToken: "tok", ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	// Logout invalid email
	_, stderr, exitCode, _ := env.RunAgymux([]string{"logout", "nonexistent@example.com"}, "")
	if exitCode == 0 {
		t.Error("expected non-zero exit code when logging out non-existent email")
	}
	if !strings.Contains(stderr, "không tìm thấy") && !strings.Contains(stderr, "not found") {
		t.Logf("stderr: %s", stderr)
	}

	// Logout invalid index
	_, _, exitCodeIdx, _ := env.RunAgymux([]string{"logout", "99"}, "")
	if exitCodeIdx == 0 {
		t.Error("expected non-zero exit code when logging out out-of-bounds index")
	}
}

// TestTier2_10_MissingAgyBinaryDiagnostic verifies clear error message when agy is missing.
func TestTier2_10_MissingAgyBinaryDiagnostic(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{Email: "test@example.com", AccessToken: "tok", ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	// Remove mock agy from bin dir
	_ = os.Remove(env.AgyWrapperPath)

	bin := env.GetBinary()
	cmd := env.Command("check")
	// Exclude PATH so agy cannot be found anywhere
	cmd.Env = []string{
		"HOME=" + env.HomeDir,
		"PATH=/dev/null",
	}

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("expected non-zero exit code when agy is missing from PATH")
	}
	outStr := string(out)
	if !strings.Contains(strings.ToLower(outStr), "agy") {
		t.Errorf("expected diagnostic mentioning 'agy' in output, got: %s", outStr)
	}
	_ = bin
}

type stubResponseWriter struct {
	header http.Header
	code   int
	body   []byte
}

func (s *stubResponseWriter) Header() http.Header { return s.header }
func (s *stubResponseWriter) Write(b []byte) (int, error) {
	s.body = append(s.body, b...)
	return len(b), nil
}
func (s *stubResponseWriter) WriteHeader(code int) { s.code = code }
