package accounts_test

import (
	"agymux/internal/accounts"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConfigDir_EnvOverride(t *testing.T) {
	customDir := filepath.Join(t.TempDir(), "custom-agymux")
	t.Setenv(accounts.ConfigDirEnv, customDir)

	got := accounts.GetConfigDir()
	if got != customDir {
		t.Fatalf("expected GetConfigDir() = %q, got %q", customDir, got)
	}
}

func TestLoadPoolFrom_Lifecycle(t *testing.T) {
	tempDir := t.TempDir()
	targetDir := filepath.Join(tempDir, "sub", "config")

	// 1. Missing directory and file -> creates dir 0700 and returns empty pool
	pool, err := accounts.LoadPoolFrom(targetDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}
	if len(pool.Accounts) != 0 {
		t.Fatalf("expected 0 accounts, got %d", len(pool.Accounts))
	}
	info, err := os.Stat(targetDir)
	if err != nil {
		t.Fatalf("expected config dir to be created: %v", err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("expected dir perm 0700, got %o", info.Mode().Perm())
	}

	// 2. Populate accounts.json manually
	acc := &accounts.Account{
		Email:        "persisted@example.com",
		RefreshToken: "ref-1",
		AccessToken:  "acc-1",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		AddedAt:      time.Now(),
	}
	pool.Accounts = append(pool.Accounts, acc)
	if err := pool.Save(); err != nil {
		t.Fatalf("pool.Save failed: %v", err)
	}

	// 3. Reload from same directory -> verifies persistence
	reloaded, err := accounts.LoadPoolFrom(targetDir)
	if err != nil {
		t.Fatalf("failed reloading pool: %v", err)
	}
	if len(reloaded.Accounts) != 1 || reloaded.Accounts[0].Email != "persisted@example.com" {
		t.Fatalf("reloaded pool content mismatch: %+v", reloaded.Accounts)
	}

	// 4. Corrupted file -> returns error
	configPath := filepath.Join(targetDir, "accounts.json")
	if err := os.WriteFile(configPath, []byte("{invalid-json"), 0600); err != nil {
		t.Fatalf("failed writing corrupted file: %v", err)
	}
	_, err = accounts.LoadPoolFrom(targetDir)
	if err == nil {
		t.Fatalf("expected error loading corrupted JSON, got nil")
	}
}

func TestPool_AddAccount_UpsertAndAtomic(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	acc1 := &accounts.Account{
		Email:        "user1@example.com",
		RefreshToken: "rt1",
		AccessToken:  "at1",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		AddedAt:      time.Now(),
	}

	if err := pool.AddAccount(acc1); err != nil {
		t.Fatalf("AddAccount failed: %v", err)
	}

	if len(pool.Accounts) != 1 {
		t.Fatalf("expected 1 account, got %d", len(pool.Accounts))
	}

	// Verify file permissions (0600)
	configPath := filepath.Join(tempDir, "accounts.json")
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("accounts.json not found: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected file permissions 0600, got %o", info.Mode().Perm())
	}

	// Verify no tmp file remaining
	tmpPath := configPath + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("temporary file %s was not cleaned up", tmpPath)
	}

	// Upsert with same email but updated access token
	acc1Updated := &accounts.Account{
		Email:        "user1@example.com",
		RefreshToken: "rt1_new",
		AccessToken:  "at1_new",
		ExpiresAt:    time.Now().Add(2 * time.Hour),
		AddedAt:      acc1.AddedAt,
	}
	if err := pool.AddAccount(acc1Updated); err != nil {
		t.Fatalf("AddAccount upsert failed: %v", err)
	}

	if len(pool.Accounts) != 1 {
		t.Fatalf("expected 1 account after upsert, got %d", len(pool.Accounts))
	}
	if pool.Accounts[0].AccessToken != "at1_new" {
		t.Fatalf("expected updated token 'at1_new', got %q", pool.Accounts[0].AccessToken)
	}

	// Add second account
	acc2 := &accounts.Account{
		Email:        "user2@example.com",
		RefreshToken: "rt2",
		AccessToken:  "at2",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		AddedAt:      time.Now(),
	}
	if err := pool.AddAccount(acc2); err != nil {
		t.Fatalf("AddAccount acc2 failed: %v", err)
	}
	if len(pool.Accounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(pool.Accounts))
	}
}

func TestPool_RemoveAccount_IndexBoundary(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	// Out of bounds on empty pool
	if _, err := pool.RemoveAccount(0); err == nil {
		t.Fatalf("expected error on out-of-bounds index")
	}
	if _, err := pool.RemoveAccount(-1); err == nil {
		t.Fatalf("expected error on negative index")
	}

	// Populate 3 accounts: [A, B, C]
	for _, email := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		_ = pool.AddAccount(&accounts.Account{
			Email:       email,
			AccessToken: "token-" + email,
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		})
	}

	// Set CurrentIdx = 2 (pointing to C)
	pool.CurrentIdx = 2

	// Remove index 0 (A). Active account C was at index 2, should shift to index 1!
	removed, err := pool.RemoveAccount(0)
	if err != nil {
		t.Fatalf("RemoveAccount(0) failed: %v", err)
	}
	if removed.Email != "a@example.com" {
		t.Fatalf("expected removed email 'a@example.com', got %q", removed.Email)
	}
	if len(pool.Accounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(pool.Accounts))
	}
	if pool.CurrentIdx != 1 {
		t.Fatalf("expected CurrentIdx to decrement to 1 (pointing to C), got %d", pool.CurrentIdx)
	}
	if pool.Accounts[pool.CurrentIdx].Email != "c@example.com" {
		t.Fatalf("expected active account to remain C ('c@example.com'), got %q", pool.Accounts[pool.CurrentIdx].Email)
	}

	// Remove index 1 (C, which is CurrentIdx). CurrentIdx was 1, length becomes 1 -> CurrentIdx should reset to 0!
	removed, err = pool.RemoveAccount(1)
	if err != nil {
		t.Fatalf("RemoveAccount(1) failed: %v", err)
	}
	if removed.Email != "c@example.com" {
		t.Fatalf("expected removed email 'c@example.com', got %q", removed.Email)
	}
	if len(pool.Accounts) != 1 || pool.CurrentIdx != 0 {
		t.Fatalf("expected 1 account and CurrentIdx=0, got len=%d, idx=%d", len(pool.Accounts), pool.CurrentIdx)
	}

	// Remove last account (B)
	removed, err = pool.RemoveAccount(0)
	if err != nil {
		t.Fatalf("RemoveAccount(0) failed: %v", err)
	}
	if removed.Email != "b@example.com" {
		t.Fatalf("expected removed email 'b@example.com', got %q", removed.Email)
	}
	if len(pool.Accounts) != 0 || pool.CurrentIdx != 0 {
		t.Fatalf("expected empty pool with CurrentIdx=0, got len=%d, idx=%d", len(pool.Accounts), pool.CurrentIdx)
	}
}

func TestPool_RemoveByEmail_SuccessAndNotFound(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	_ = pool.AddAccount(&accounts.Account{Email: "alpha@example.com"})
	_ = pool.AddAccount(&accounts.Account{Email: "beta@example.com"})

	// Remove non-existent
	if _, err := pool.RemoveByEmail("gamma@example.com"); err == nil {
		t.Fatalf("expected error removing non-existent email, got nil")
	}

	// Remove existing
	removed, err := pool.RemoveByEmail("alpha@example.com")
	if err != nil {
		t.Fatalf("RemoveByEmail failed: %v", err)
	}
	if removed.Email != "alpha@example.com" {
		t.Fatalf("expected removed account 'alpha@example.com', got %q", removed.Email)
	}
	if len(pool.Accounts) != 1 || pool.Accounts[0].Email != "beta@example.com" {
		t.Fatalf("pool state unexpected after RemoveByEmail: %+v", pool.Accounts)
	}
}

func TestPool_RemoveByEmail_ConcurrencyRace(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	// Preload 20 accounts
	for i := 0; i < 20; i++ {
		_ = pool.AddAccount(&accounts.Account{
			Email:       fmt.Sprintf("user%d@example.com", i),
			AccessToken: fmt.Sprintf("token-%d", i),
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		})
	}

	var wg sync.WaitGroup
	// Run 10 parallel goroutines doing RemoveByEmail, AddAccount, and ListTo
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for iter := 0; iter < 15; iter++ {
				email := fmt.Sprintf("user%d@example.com", (workerID+iter)%25)
				// Concurrently remove
				_, _ = pool.RemoveByEmail(email)

				// Concurrently add
				_ = pool.AddAccount(&accounts.Account{
					Email:       email,
					AccessToken: "token-stress",
					ExpiresAt:   time.Now().Add(1 * time.Hour),
				})

				// Concurrently list to discard
				pool.ListTo(io.Discard)
			}
		}(i)
	}

	wg.Wait()
}

func TestPool_ListTo_Statuses(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	// 1. Empty pool output
	var buf bytes.Buffer
	pool.ListTo(&buf)
	if !strings.Contains(buf.String(), "Chưa có tài khoản nào") {
		t.Fatalf("expected empty pool prompt in output, got:\n%s", buf.String())
	}

	// 2. Add 3 accounts:
	// Acc 0: Active
	// Acc 1: Standby
	// Acc 2: Cooldown
	_ = pool.AddAccount(&accounts.Account{
		Email:       "active@example.com",
		AccessToken: "token-active",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})
	_ = pool.AddAccount(&accounts.Account{
		Email:       "standby@example.com",
		AccessToken: "token-standby",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})
	_ = pool.AddAccount(&accounts.Account{
		Email:         "cooldown@example.com",
		AccessToken:   "token-cooldown",
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		CooldownUntil: time.Now().Add(25 * time.Minute),
	})

	pool.CurrentIdx = 0

	buf.Reset()
	pool.ListTo(&buf)
	out := buf.String()

	if !strings.Contains(out, "[Active]") {
		t.Fatalf("expected output to contain '[Active]', got:\n%s", out)
	}
	if !strings.Contains(out, "[Standby]") {
		t.Fatalf("expected output to contain '[Standby]', got:\n%s", out)
	}
	if !strings.Contains(out, "[Cooldown") {
		t.Fatalf("expected output to contain '[Cooldown', got:\n%s", out)
	}
	if !strings.Contains(out, "[★ ACTIVE]") {
		t.Fatalf("expected output to contain active indicator '[★ ACTIVE]', got:\n%s", out)
	}
}

func TestPool_GetActiveToken_SelectionAndRefresh(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	// Empty pool returns error
	if _, _, err := pool.GetActiveToken(); err == nil {
		t.Fatalf("expected error on empty pool, got nil")
	}

	// Mock OAuth token endpoint
	refreshCalled := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshCalled = true
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)
		if !strings.Contains(bodyStr, "grant_type=refresh_token") || !strings.Contains(bodyStr, "refresh_token=rt-expired") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		resp := map[string]interface{}{
			"access_token": "new-refreshed-token-12345",
			"expires_in":   3600,
			"token_type":   "Bearer",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	pool.SetTokenEndpoint(ts.URL)

	// Add account with token expiring in 1 minute (< 2 minute threshold -> triggers refresh)
	acc := &accounts.Account{
		Email:        "refreshable@example.com",
		RefreshToken: "rt-expired",
		AccessToken:  "old-token",
		ExpiresAt:    time.Now().Add(1 * time.Minute),
	}
	_ = pool.AddAccount(acc)

	token, email, err := pool.GetActiveToken()
	if err != nil {
		t.Fatalf("GetActiveToken failed: %v", err)
	}
	if !refreshCalled {
		t.Fatalf("expected refresh endpoint to be called for expiring token")
	}
	if token != "new-refreshed-token-12345" {
		t.Fatalf("expected refreshed token 'new-refreshed-token-12345', got %q", token)
	}
	if email != "refreshable@example.com" {
		t.Fatalf("expected email 'refreshable@example.com', got %q", email)
	}

	// Verify updated token was saved on disk
	reloaded, _ := accounts.LoadPoolFrom(tempDir)
	if reloaded.Accounts[0].AccessToken != "new-refreshed-token-12345" {
		t.Fatalf("expected refreshed token to be saved to disk, got %q", reloaded.Accounts[0].AccessToken)
	}
}

func TestPool_GetActiveToken_CooldownSkipAndFallback(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	// Account 0 in cooldown, Account 1 ready
	_ = pool.AddAccount(&accounts.Account{
		Email:         "acc0@example.com",
		AccessToken:   "token0",
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		CooldownUntil: time.Now().Add(10 * time.Minute),
	})
	_ = pool.AddAccount(&accounts.Account{
		Email:       "acc1@example.com",
		AccessToken: "token1",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})

	pool.CurrentIdx = 0

	// Should skip acc0 and return acc1
	token, email, err := pool.GetActiveToken()
	if err != nil {
		t.Fatalf("GetActiveToken failed: %v", err)
	}
	if email != "acc1@example.com" || token != "token1" {
		t.Fatalf("expected acc1 token, got %s (%s)", token, email)
	}
	if pool.CurrentIdx != 1 {
		t.Fatalf("expected CurrentIdx to advance to 1, got %d", pool.CurrentIdx)
	}

	// Now put acc1 in cooldown too (all accounts cooled down)
	pool.Accounts[1].CooldownUntil = time.Now().Add(10 * time.Minute)

	// Fallback should return current account without panic
	fallbackToken, fallbackEmail, err := pool.GetActiveToken()
	if err != nil {
		t.Fatalf("GetActiveToken fallback failed: %v", err)
	}
	if fallbackEmail != "acc1@example.com" || fallbackToken != "token1" {
		t.Fatalf("expected fallback to acc1, got %s (%s)", fallbackToken, fallbackEmail)
	}
}

func TestPool_RotateOnQuota(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	// Pool with <= 1 account returns error
	if _, _, err := pool.RotateOnQuota("test"); err == nil {
		t.Fatalf("expected error on <= 1 account, got nil")
	}

	_ = pool.AddAccount(&accounts.Account{
		Email:       "first@example.com",
		AccessToken: "token-first",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})
	if _, _, err := pool.RotateOnQuota("test"); err == nil {
		t.Fatalf("expected error on single account pool, got nil")
	}

	// Add second account
	_ = pool.AddAccount(&accounts.Account{
		Email:       "second@example.com",
		AccessToken: "token-second",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})

	pool.CurrentIdx = 0

	// Rotate on quota
	beforeRotate := time.Now()
	newToken, newEmail, err := pool.RotateOnQuota("429 rate limit")
	if err != nil {
		t.Fatalf("RotateOnQuota failed: %v", err)
	}

	if newEmail != "second@example.com" || newToken != "token-second" {
		t.Fatalf("expected rotation to second account, got %s (%s)", newToken, newEmail)
	}
	if pool.CurrentIdx != 1 {
		t.Fatalf("expected CurrentIdx=1, got %d", pool.CurrentIdx)
	}

	// Verify first account cooldown
	firstAcc := pool.Accounts[0]
	if firstAcc.CooldownUntil.Before(beforeRotate.Add(29 * time.Minute)) {
		t.Fatalf("expected ~30m cooldown on rotated account, got %v", firstAcc.CooldownUntil)
	}

	// Verify persistence
	reloaded, _ := accounts.LoadPoolFrom(tempDir)
	if reloaded.CurrentIdx != 1 {
		t.Fatalf("expected reloaded CurrentIdx=1, got %d", reloaded.CurrentIdx)
	}
}

func TestTokenEndpoint_Mocking(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"access_token":"global-mock-token","expires_in":3600,"token_type":"Bearer"}`)
	}))
	defer ts.Close()

	// Test package variable override
	orig := accounts.TokenEndpoint
	accounts.TokenEndpoint = ts.URL
	defer func() { accounts.TokenEndpoint = orig }()

	pool, _ := accounts.LoadPoolFrom(t.TempDir())
	_ = pool.AddAccount(&accounts.Account{
		Email:        "global@example.com",
		RefreshToken: "rt-global",
		AccessToken:  "", // empty -> triggers refresh
	})

	tok, _, err := pool.GetActiveToken()
	if err != nil {
		t.Fatalf("GetActiveToken failed: %v", err)
	}
	if tok != "global-mock-token" {
		t.Fatalf("expected 'global-mock-token', got %q", tok)
	}
}

func TestPool_RotateOnQuota_AllInCooldown_SelectsEarliest(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	now := time.Now()
	// Account 0: CooldownUntil = now + 5 min (earliest among candidates)
	_ = pool.AddAccount(&accounts.Account{
		Email:         "acc0@example.com",
		AccessToken:   "token-0",
		ExpiresAt:     now.Add(1 * time.Hour),
		CooldownUntil: now.Add(5 * time.Minute),
	})
	// Account 1: CooldownUntil = now + 15 min
	_ = pool.AddAccount(&accounts.Account{
		Email:         "acc1@example.com",
		AccessToken:   "token-1",
		ExpiresAt:     now.Add(1 * time.Hour),
		CooldownUntil: now.Add(15 * time.Minute),
	})
	// Account 2: Active account (CurrentIdx = 2)
	_ = pool.AddAccount(&accounts.Account{
		Email:       "acc2@example.com",
		AccessToken: "token-2",
		ExpiresAt:   now.Add(1 * time.Hour),
	})

	pool.CurrentIdx = 2

	// When Account 2 hits 429, RotateOnQuota must NOT fail even if all accounts end up in cooldown
	token, email, err := pool.RotateOnQuota("Account 2 429")
	if err != nil {
		t.Fatalf("expected RotateOnQuota to succeed with earliest candidate, got err: %v", err)
	}

	// Must select acc0 because it has earliest cooldown expiration (5m vs 15m)
	if email != "acc0@example.com" {
		t.Errorf("expected earliest cooldown account 'acc0@example.com', got %q", email)
	}
	if token != "token-0" {
		t.Errorf("expected token 'token-0', got %q", token)
	}
	if pool.CurrentIdx != 0 {
		t.Errorf("expected CurrentIdx updated to 0, got %d", pool.CurrentIdx)
	}

	// Account 2 must be placed in cooldown
	if pool.Accounts[2].CooldownUntil.Before(now.Add(25 * time.Minute)) {
		t.Errorf("expected acc2 in cooldown, got %v", pool.Accounts[2].CooldownUntil)
	}
}

func TestPool_GetActiveToken_AllInCooldown_DeadlockResolution(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	now := time.Now()
	// All 3 accounts are in cooldown.
	// Acc0 has earliest expiration (5m)
	_ = pool.AddAccount(&accounts.Account{
		Email:         "acc0@example.com",
		AccessToken:   "token-0",
		ExpiresAt:     now.Add(1 * time.Hour),
		CooldownUntil: now.Add(5 * time.Minute),
	})
	// Acc1 has 20m cooldown
	_ = pool.AddAccount(&accounts.Account{
		Email:         "acc1@example.com",
		AccessToken:   "token-1",
		ExpiresAt:     now.Add(1 * time.Hour),
		CooldownUntil: now.Add(20 * time.Minute),
	})
	// Acc2 has 35m cooldown (just exhausted)
	_ = pool.AddAccount(&accounts.Account{
		Email:         "acc2@example.com",
		AccessToken:   "token-2",
		ExpiresAt:     now.Add(1 * time.Hour),
		CooldownUntil: now.Add(35 * time.Minute),
	})

	// CurrentIdx was left at 2
	pool.CurrentIdx = 2

	// GetActiveToken must NOT remain locked on acc2; it should select acc0 (earliest expiration)
	token, email, err := pool.GetActiveToken()
	if err != nil {
		t.Fatalf("GetActiveToken failed: %v", err)
	}

	if email != "acc0@example.com" {
		t.Errorf("expected deadlock breaker to select acc0@example.com, got %q", email)
	}
	if token != "token-0" {
		t.Errorf("expected token-0, got %q", token)
	}
	if pool.CurrentIdx != 0 {
		t.Errorf("expected CurrentIdx updated to 0, got %d", pool.CurrentIdx)
	}
}

func TestPool_AccountTierPrioritization_GetActiveToken(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	now := time.Now()
	// Acc0: Free tier
	_ = pool.AddAccount(&accounts.Account{
		Email:       "free@example.com",
		AccessToken: "token-free",
		ExpiresAt:   now.Add(1 * time.Hour),
		Tier:        accounts.TierFree,
	})
	// Acc1: AI Pro tier
	_ = pool.AddAccount(&accounts.Account{
		Email:       "pro@example.com",
		AccessToken: "token-pro",
		ExpiresAt:   now.Add(1 * time.Hour),
		Tier:        "AI Pro",
	})

	pool.CurrentIdx = 0

	// GetActiveToken must prioritize AI Pro account over Free tier
	token, email, err := pool.GetActiveToken()
	if err != nil {
		t.Fatalf("GetActiveToken failed: %v", err)
	}
	if email != "pro@example.com" {
		t.Errorf("expected Pro tier account 'pro@example.com' to be prioritized, got %q", email)
	}
	if token != "token-pro" {
		t.Errorf("expected token-pro, got %q", token)
	}
	if pool.CurrentIdx != 1 {
		t.Errorf("expected CurrentIdx=1, got %d", pool.CurrentIdx)
	}

	// Now place Pro account in cooldown
	pool.Accounts[1].CooldownUntil = now.Add(30 * time.Minute)

	// GetActiveToken should fall back to available Free tier account
	token, email, err = pool.GetActiveToken()
	if err != nil {
		t.Fatalf("GetActiveToken fallback failed: %v", err)
	}
	if email != "free@example.com" {
		t.Errorf("expected fallback to 'free@example.com', got %q", email)
	}
	if token != "token-free" {
		t.Errorf("expected token-free, got %q", token)
	}
	if pool.CurrentIdx != 0 {
		t.Errorf("expected CurrentIdx=0, got %d", pool.CurrentIdx)
	}
}

func TestPool_AccountTierPrioritization_RotateOnQuota(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	now := time.Now()
	// Acc0: Free (Current, hits 429)
	_ = pool.AddAccount(&accounts.Account{
		Email:       "acc0-free@example.com",
		AccessToken: "tok-0",
		ExpiresAt:   now.Add(1 * time.Hour),
		Tier:        accounts.TierFree,
	})
	// Acc1: Free (Ready)
	_ = pool.AddAccount(&accounts.Account{
		Email:       "acc1-free@example.com",
		AccessToken: "tok-1",
		ExpiresAt:   now.Add(1 * time.Hour),
		Tier:        accounts.TierFree,
	})
	// Acc2: AI Pro (Ready)
	_ = pool.AddAccount(&accounts.Account{
		Email:       "acc2-pro@example.com",
		AccessToken: "tok-2",
		ExpiresAt:   now.Add(1 * time.Hour),
		Tier:        "AI Pro",
	})

	pool.CurrentIdx = 0

	// Rotation should select acc2-pro over acc1-free due to higher tier priority
	token, email, err := pool.RotateOnQuota("429 rate limit")
	if err != nil {
		t.Fatalf("RotateOnQuota failed: %v", err)
	}
	if email != "acc2-pro@example.com" {
		t.Errorf("expected rotation to prefer AI Pro account, got %q", email)
	}
	if token != "tok-2" {
		t.Errorf("expected tok-2, got %q", token)
	}
	if pool.CurrentIdx != 2 {
		t.Errorf("expected CurrentIdx=2, got %d", pool.CurrentIdx)
	}
}

func TestPool_ParseQuotaCooldown(t *testing.T) {
	tests := []struct {
		name         string
		header       http.Header
		body         []byte
		wantMin      time.Duration
		wantMax      time.Duration
		wantTranisnt bool
	}{
		{
			name: "Retry-After integer seconds",
			header: http.Header{
				"Retry-After": []string{"45"},
			},
			body:         nil,
			wantMin:      45 * time.Second,
			wantMax:      45 * time.Second,
			wantTranisnt: true,
		},
		{
			name: "X-Goog-Retry-After duration string",
			header: http.Header{
				"X-Goog-Retry-After": []string{"15s"},
			},
			body:         nil,
			wantMin:      15 * time.Second,
			wantMax:      15 * time.Second,
			wantTranisnt: true,
		},
		{
			name: "Google RPC RetryInfo in JSON body",
			header: nil,
			body: []byte(`{
				"error": {
					"code": 429,
					"message": "Resource exhausted",
					"details": [
						{
							"@type": "type.googleapis.com/google.rpc.RetryInfo",
							"retryDelay": "20s"
						}
					]
				}
			}`),
			wantMin:      20 * time.Second,
			wantMax:      20 * time.Second,
			wantTranisnt: true,
		},
		{
			name: "Google RPC ErrorInfo RATE_LIMIT_EXCEEDED",
			header: nil,
			body: []byte(`{
				"error": {
					"code": 429,
					"details": [
						{
							"@type": "type.googleapis.com/google.rpc.ErrorInfo",
							"reason": "RATE_LIMIT_EXCEEDED"
						}
					]
				}
			}`),
			wantMin:      1 * time.Minute,
			wantMax:      1 * time.Minute,
			wantTranisnt: true,
		},
		{
			name: "Message with embedded retry delay",
			header: nil,
			body: []byte(`{
				"error": {
					"code": 429,
					"message": "Rate limit reached. Please retry after 10s."
				}
			}`),
			wantMin:      10 * time.Second,
			wantMax:      10 * time.Second,
			wantTranisnt: true,
		},
		{
			name: "Generic RESOURCE_EXHAUSTED default 30m block",
			header: nil,
			body:         []byte(`{"error":{"code":429,"message":"RESOURCE_EXHAUSTED"}}`),
			wantMin:      30 * time.Minute,
			wantMax:      30 * time.Minute,
			wantTranisnt: false,
		},
		{
			name:         "Retry-After header with 0 seconds",
			header:       http.Header{"Retry-After": []string{"0"}},
			body:         nil,
			wantMin:      5 * time.Second,
			wantMax:      5 * time.Second,
			wantTranisnt: true,
		},
		{
			name:   "Google RPC proto3 Status format B without error wrapper",
			header: nil,
			body: []byte(`{
				"code": 429,
				"message": "Resource exhausted",
				"details": [
					{
						"@type": "type.googleapis.com/google.rpc.RetryInfo",
						"retryDelay": "20s"
					}
				]
			}`),
			wantMin:      20 * time.Second,
			wantMax:      20 * time.Second,
			wantTranisnt: true,
		},
		{
			name:   "Google RPC RetryInfo with map seconds and nanos",
			header: nil,
			body: []byte(`{
				"error": {
					"code": 429,
					"details": [
						{
							"@type": "type.googleapis.com/google.rpc.RetryInfo",
							"retryDelay": {
								"seconds": 25,
								"nanos": 0
							}
						}
					]
				}
			}`),
			wantMin:      25 * time.Second,
			wantMax:      25 * time.Second,
			wantTranisnt: true,
		},
		{
			name:   "Message with try again in 15 seconds",
			header: nil,
			body: []byte(`{
				"error": {
					"code": 429,
					"message": "Rate limit reached. Try again in 15s."
				}
			}`),
			wantMin:      15 * time.Second,
			wantMax:      15 * time.Second,
			wantTranisnt: true,
		},
		{
			name:         "Empty body and nil header default 30m block",
			header:       nil,
			body:         nil,
			wantMin:      30 * time.Minute,
			wantMax:      30 * time.Minute,
			wantTranisnt: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dur, isTransient := accounts.ParseQuotaCooldown(tc.header, tc.body)
			if dur < tc.wantMin || dur > tc.wantMax {
				t.Errorf("got duration %v, expected between [%v, %v]", dur, tc.wantMin, tc.wantMax)
			}
			if isTransient != tc.wantTranisnt {
				t.Errorf("got isTransient=%v, want %v", isTransient, tc.wantTranisnt)
			}
		})
	}
}

func TestPool_RotateOnQuota_DynamicCooldownApplied(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	_ = pool.AddAccount(&accounts.Account{
		Email:       "acc0@example.com",
		AccessToken: "t0",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})
	_ = pool.AddAccount(&accounts.Account{
		Email:       "acc1@example.com",
		AccessToken: "t1",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})

	pool.CurrentIdx = 0

	// Transient 15s cooldown
	before := time.Now()
	transientDur := 15 * time.Second
	_, _, err = pool.RotateOnQuota("transient rate limit", transientDur)
	if err != nil {
		t.Fatalf("RotateOnQuota failed: %v", err)
	}

	acc0 := pool.Accounts[0]
	cooldownDur := acc0.CooldownUntil.Sub(before)
	if cooldownDur < 14*time.Second || cooldownDur > 18*time.Second {
		t.Errorf("expected acc0 cooldown ~15s, got %v", cooldownDur)
	}
}

func TestPool_HasAvailableCandidate(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	_ = pool.AddAccount(&accounts.Account{
		Email:       "ready@example.com",
		AccessToken: "t0",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})
	_ = pool.AddAccount(&accounts.Account{
		Email:         "cooldown@example.com",
		AccessToken:   "t1",
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		CooldownUntil: time.Now().Add(10 * time.Minute),
	})

	// With no excluded emails, ready@example.com is available
	if !pool.HasAvailableCandidate(nil) {
		t.Error("expected candidate to be available")
	}

	// If ready@example.com is excluded (already tried), no candidates available
	tried := map[string]bool{"ready@example.com": true}
	if pool.HasAvailableCandidate(tried) {
		t.Error("expected no candidates available when ready account is excluded")
	}
}

func TestPool_GetActiveToken_AllInCooldown_RefreshesExpiredToken(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	refreshCalled := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshCalled = true
		resp := map[string]interface{}{
			"access_token": "fresh-token-after-all-cooldown",
			"expires_in":   3600,
			"token_type":   "Bearer",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()
	pool.SetTokenEndpoint(ts.URL)

	now := time.Now()
	// Acc0 has earliest cooldown (1s), but expired access token!
	_ = pool.AddAccount(&accounts.Account{
		Email:         "acc0@example.com",
		RefreshToken:  "rt0",
		AccessToken:   "expired-token-0",
		ExpiresAt:     now.Add(-10 * time.Minute),
		CooldownUntil: now.Add(1 * time.Second),
	})
	// Acc1 has longer cooldown (30m)
	_ = pool.AddAccount(&accounts.Account{
		Email:         "acc1@example.com",
		RefreshToken:  "rt1",
		AccessToken:   "valid-token-1",
		ExpiresAt:     now.Add(1 * time.Hour),
		CooldownUntil: now.Add(30 * time.Minute),
	})

	pool.CurrentIdx = 1

	token, email, err := pool.GetActiveToken()
	if err != nil {
		t.Fatalf("GetActiveToken failed: %v", err)
	}
	if email != "acc0@example.com" {
		t.Errorf("expected acc0@example.com, got %s", email)
	}
	if !refreshCalled {
		t.Errorf("expected refresh endpoint to be called when earliest cooldown account token is expired")
	}
	if token != "fresh-token-after-all-cooldown" {
		t.Errorf("expected refreshed token, got %q", token)
	}
}

func TestPool_OutOfBounds_CurrentIdx(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	_ = pool.AddAccount(&accounts.Account{
		Email:       "a@example.com",
		AccessToken: "token-a",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})
	_ = pool.AddAccount(&accounts.Account{
		Email:       "b@example.com",
		AccessToken: "token-b",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})

	// Simulate corrupted/out-of-bounds current_idx (e.g. 99)
	pool.CurrentIdx = 99

	// Must not panic!
	tok, em, err := pool.GetActiveToken()
	if err != nil {
		t.Fatalf("GetActiveToken failed on out of bounds CurrentIdx: %v", err)
	}
	if tok == "" || em == "" {
		t.Errorf("expected valid token and email, got tok=%q, em=%q", tok, em)
	}

	// RotateOnQuota must also not panic
	pool.CurrentIdx = 99
	tok, em, err = pool.RotateOnQuota("test")
	if err != nil {
		t.Fatalf("RotateOnQuota failed on out of bounds CurrentIdx: %v", err)
	}
	if tok == "" || em == "" {
		t.Errorf("expected valid token and email after rotation, got tok=%q, em=%q", tok, em)
	}
}

func TestPool_RotateAccountOnQuota_ConcurrentRequests(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	_ = pool.AddAccount(&accounts.Account{
		Email:       "acc0@example.com",
		AccessToken: "token-0",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})
	_ = pool.AddAccount(&accounts.Account{
		Email:       "acc1@example.com",
		AccessToken: "token-1",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})

	pool.CurrentIdx = 0

	// 1st request using acc0 hits 429
	tok, em, err := pool.RotateAccountOnQuota("acc0@example.com", "req1 429")
	if err != nil {
		t.Fatalf("RotateAccountOnQuota failed: %v", err)
	}
	if em != "acc1@example.com" || tok != "token-1" {
		t.Fatalf("expected rotation to acc1, got %s (%s)", em, tok)
	}
	if pool.CurrentIdx != 1 {
		t.Fatalf("expected CurrentIdx=1, got %d", pool.CurrentIdx)
	}

	// 2nd concurrent request also using acc0 hits 429 after pool already rotated to acc1!
	// It MUST NOT put acc1 in cooldown or rotate away from healthy acc1!
	tok2, em2, err := pool.RotateAccountOnQuota("acc0@example.com", "req2 429 on acc0")
	if err != nil {
		t.Fatalf("RotateAccountOnQuota 2 failed: %v", err)
	}
	if em2 != "acc1@example.com" || tok2 != "token-1" {
		t.Errorf("expected acc1 to remain active and returned, got %s (%s)", em2, tok2)
	}
	if pool.CurrentIdx != 1 {
		t.Errorf("expected CurrentIdx to remain 1, got %d", pool.CurrentIdx)
	}
	if !pool.Accounts[1].CooldownUntil.IsZero() && pool.Accounts[1].CooldownUntil.After(time.Now()) {
		t.Errorf("acc1 should NOT have been put in cooldown: %v", pool.Accounts[1].CooldownUntil)
	}
}

func TestPool_RotateAccountOnQuota_UnknownEmailDoesNotPenalizeActiveAccount(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	_ = pool.AddAccount(&accounts.Account{
		Email:       "alice@example.com",
		AccessToken: "token-alice",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})
	_ = pool.AddAccount(&accounts.Account{
		Email:       "bob@example.com",
		AccessToken: "token-bob",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})

	pool.CurrentIdx = 0 // Alice is active

	// An unknown / already logged-out account encounters 429
	_, em, err := pool.RotateAccountOnQuota("ghost@example.com", "429 ghost account")
	if err != nil {
		t.Fatalf("RotateAccountOnQuota failed: %v", err)
	}

	// Active account Alice MUST NOT be placed into cooldown!
	if !pool.Accounts[0].CooldownUntil.IsZero() && pool.Accounts[0].CooldownUntil.After(time.Now()) {
		t.Fatalf("innocent account alice@example.com was falsely placed in cooldown: %v", pool.Accounts[0].CooldownUntil)
	}
	// Alice should still be returned and active
	if em != "alice@example.com" {
		t.Errorf("expected alice@example.com to remain active, got %s", em)
	}
	if pool.CurrentIdx != 0 {
		t.Errorf("expected CurrentIdx=0, got %d", pool.CurrentIdx)
	}
}

func TestPool_GetActiveToken_AllInCooldown_NeverPermanentlyLockedOnCurrentIdx(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	now := time.Now()
	// Both accounts are in cooldown with the exact same expiration (tied earliest cooldown)
	_ = pool.AddAccount(&accounts.Account{
		Email:         "acc0@example.com",
		AccessToken:   "token-0",
		ExpiresAt:     now.Add(1 * time.Hour),
		CooldownUntil: now.Add(30 * time.Minute),
	})
	_ = pool.AddAccount(&accounts.Account{
		Email:         "acc1@example.com",
		AccessToken:   "token-1",
		ExpiresAt:     now.Add(1 * time.Hour),
		CooldownUntil: now.Add(30 * time.Minute),
	})

	pool.CurrentIdx = 1 // Acc1 was active and hits 429

	// 1st rotation on Acc1 must rotate to Acc0 even if both are in 30m cooldown!
	_, em1, err := pool.RotateAccountOnQuota("acc1@example.com", "429 limit on acc1")
	if err != nil {
		t.Fatalf("RotateAccountOnQuota call 1 failed: %v", err)
	}
	if em1 != "acc0@example.com" {
		t.Fatalf("expected rotation away from acc1 to acc0, got %s", em1)
	}
	if pool.CurrentIdx != 0 {
		t.Fatalf("expected CurrentIdx=0, got %d", pool.CurrentIdx)
	}

	// GetActiveToken now returns Acc0 without getting stuck on Acc1
	tok, emToken, err := pool.GetActiveToken()
	if err != nil || emToken != "acc0@example.com" || tok != "token-0" {
		t.Fatalf("GetActiveToken returned %s (%s), err=%v", emToken, tok, err)
	}

	// 2nd rotation on Acc0 must rotate back to Acc1!
	_, em2, err := pool.RotateAccountOnQuota("acc0@example.com", "429 limit on acc0")
	if err != nil {
		t.Fatalf("RotateAccountOnQuota call 2 failed: %v", err)
	}
	if em2 != "acc1@example.com" {
		t.Fatalf("expected alternating rotation back to acc1, got %s", em2)
	}
	if pool.CurrentIdx != 1 {
		t.Fatalf("expected CurrentIdx=1, got %d", pool.CurrentIdx)
	}
}

func TestPool_GetActiveToken_AllInCooldown_RefreshTokenFailureFallback(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)
		if strings.Contains(bodyStr, "refresh_token=rt-broken") {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, `{"error":"invalid_grant"}`)
			return
		}
		resp := map[string]interface{}{
			"access_token": "valid-refreshed-token-acc1",
			"expires_in":   3600,
			"token_type":   "Bearer",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()
	pool.SetTokenEndpoint(ts.URL)

	now := time.Now()
	// Acc0 has earliest cooldown (1s), but broken refresh token and no access token!
	_ = pool.AddAccount(&accounts.Account{
		Email:         "acc0@example.com",
		RefreshToken:  "rt-broken",
		AccessToken:   "",
		ExpiresAt:     now.Add(-10 * time.Minute),
		CooldownUntil: now.Add(1 * time.Second),
	})
	// Acc1 has cooldown (5s), with valid refresh token!
	_ = pool.AddAccount(&accounts.Account{
		Email:         "acc1@example.com",
		RefreshToken:  "rt-valid",
		AccessToken:   "",
		ExpiresAt:     now.Add(-10 * time.Minute),
		CooldownUntil: now.Add(5 * time.Second),
	})

	pool.CurrentIdx = 0

	// GetActiveToken must detect Acc0 refresh failure, penalize Acc0, and fall back to Acc1!
	tok, em, err := pool.GetActiveToken()
	if err != nil {
		t.Fatalf("expected fallback to acc1 on acc0 refresh failure, got err: %v", err)
	}
	if tok == "" {
		t.Fatalf("expected non-empty token from acc1, got empty token")
	}
	if em != "acc1@example.com" {
		t.Fatalf("expected fallback to acc1@example.com, got %s", em)
	}
	if tok != "valid-refreshed-token-acc1" {
		t.Fatalf("expected token 'valid-refreshed-token-acc1', got %q", tok)
	}
}

func TestPool_RotateAccountOnQuota_RefreshTokenFailureSkipsToNextAccount(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "refresh_token=rt-dead") {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, `{"error":"invalid_grant"}`)
			return
		}
		resp := map[string]interface{}{
			"access_token": "valid-refreshed-token-acc2",
			"expires_in":   3600,
			"token_type":   "Bearer",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()
	pool.SetTokenEndpoint(ts.URL)

	now := time.Now()
	// Acc0 hits 429
	_ = pool.AddAccount(&accounts.Account{
		Email:       "acc0@example.com",
		AccessToken: "tok0",
		ExpiresAt:   now.Add(1 * time.Hour),
	})
	// Acc1 is next in line, but has broken refresh token and expired token!
	_ = pool.AddAccount(&accounts.Account{
		Email:        "acc1@example.com",
		RefreshToken: "rt-dead",
		AccessToken:  "",
		ExpiresAt:    now.Add(-10 * time.Minute),
	})
	// Acc2 is healthy with valid refresh token!
	_ = pool.AddAccount(&accounts.Account{
		Email:        "acc2@example.com",
		RefreshToken: "rt-alive",
		AccessToken:  "",
		ExpiresAt:    now.Add(-10 * time.Minute),
	})

	pool.CurrentIdx = 0

	// Rotating away from acc0 should skip broken acc1 and return valid acc2!
	tok, em, err := pool.RotateAccountOnQuota("acc0@example.com", "429 rate limit")
	if err != nil {
		t.Fatalf("RotateAccountOnQuota failed: %v", err)
	}
	if tok == "" {
		t.Fatalf("RotateAccountOnQuota returned empty token instead of skipping broken acc1")
	}
	if em != "acc2@example.com" {
		t.Errorf("expected rotation to skip acc1 and select acc2, got %s", em)
	}
}

func TestPool_ParseQuotaCooldown_AdvancedGoogleFormats(t *testing.T) {
	tests := []struct {
		name          string
		header        http.Header
		body          []byte
		wantMin       time.Duration
		wantMax       time.Duration
		wantTransient bool
	}{
		{
			name: "Standard Retry-After with duration unit e.g. 15s",
			header: http.Header{
				"Retry-After": []string{"15s"},
			},
			body:          nil,
			wantMin:       15 * time.Second,
			wantMax:       15 * time.Second,
			wantTransient: true,
		},
		{
			name:   "Google RPC proto3 Status with snake_case retry_delay in RetryInfo",
			header: nil,
			body: []byte(`{
				"code": 429,
				"message": "Resource exhausted",
				"status": "RESOURCE_EXHAUSTED",
				"details": [
					{
						"@type": "type.googleapis.com/google.rpc.RetryInfo",
						"retry_delay": "18s"
					}
				]
			}`),
			wantMin:       18 * time.Second,
			wantMax:       18 * time.Second,
			wantTransient: true,
		},
		{
			name:   "Google RPC QuotaFailure with violations mentioning requests per minute",
			header: nil,
			body: []byte(`{
				"code": 429,
				"message": "Resource has been exhausted (e.g. check quota).",
				"status": "RESOURCE_EXHAUSTED",
				"details": [
					{
						"@type": "type.googleapis.com/google.rpc.QuotaFailure",
						"violations": [
							{
								"subject": "project:12345",
								"description": "Quota exceeded for metric GenerateContent requests per minute"
							}
						]
					}
				]
			}`),
			wantMin:       1 * time.Minute,
			wantMax:       1 * time.Minute,
			wantTransient: true,
		},
		{
			name:   "Google RPC ErrorInfo with Unix timestamp in milliseconds in reset_time",
			header: nil,
			body: func() []byte {
				milli := time.Now().Add(45 * time.Second).UnixMilli()
				return []byte(fmt.Sprintf(`{
					"error": {
						"code": 429,
						"details": [
							{
								"@type": "type.googleapis.com/google.rpc.ErrorInfo",
								"metadata": {
									"reset_time": "%d"
								}
							}
						]
					}
				}`, milli))
			}(),
			wantMin:       35 * time.Second,
			wantMax:       55 * time.Second,
			wantTransient: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dur, isTransient := accounts.ParseQuotaCooldown(tc.header, tc.body)
			if dur < tc.wantMin || dur > tc.wantMax {
				t.Errorf("got duration %v, want [%v, %v]", dur, tc.wantMin, tc.wantMax)
			}
			if isTransient != tc.wantTransient {
				t.Errorf("got isTransient=%v, want %v", isTransient, tc.wantTransient)
			}
		})
	}
}

func TestPool_RotateAccountOnAuthFailure_RefreshesInPlaceWhenRefreshTokenValid(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "ya29.revived_token",
			"expires_in":   3600,
		})
	}))
	defer ts.Close()
	pool.SetTokenEndpoint(ts.URL)

	_ = pool.AddAccount(&accounts.Account{
		Email:        "user@example.com",
		AccessToken:  "stale-token",
		RefreshToken: "valid-refresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})

	sameRefreshed, newToken, email, err := pool.RotateAccountOnAuthFailure("user@example.com", "401 Unauthorized")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sameRefreshed {
		t.Errorf("expected sameRefreshed=true, got false")
	}
	if newToken != "ya29.revived_token" {
		t.Errorf("expected newToken=ya29.revived_token, got %s", newToken)
	}
	if email != "user@example.com" {
		t.Errorf("expected email=user@example.com, got %s", email)
	}
	if pool.Accounts[0].CooldownUntil.After(time.Now()) {
		t.Errorf("account should not be in cooldown after successful in-place refresh")
	}
}

func TestPool_RotateAccountOnAuthFailure_RotatesToNextAccountWhenRefreshTokenFails(t *testing.T) {
	tempDir := t.TempDir()
	pool, err := accounts.LoadPoolFrom(tempDir)
	if err != nil {
		t.Fatalf("LoadPoolFrom failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized_client"}`))
	}))
	defer ts.Close()
	pool.SetTokenEndpoint(ts.URL)

	_ = pool.AddAccount(&accounts.Account{
		Email:        "dead@example.com",
		AccessToken:  "dead-access",
		RefreshToken: "revoked-refresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})
	_ = pool.AddAccount(&accounts.Account{
		Email:        "healthy@example.com",
		AccessToken:  "healthy-access",
		RefreshToken: "healthy-refresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})

	pool.CurrentIdx = 0

	sameRefreshed, newToken, email, err := pool.RotateAccountOnAuthFailure("dead@example.com", "401 Unauthorized")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sameRefreshed {
		t.Errorf("expected sameRefreshed=false, got true")
	}
	if email != "healthy@example.com" || newToken != "healthy-access" {
		t.Errorf("expected rotation to healthy@example.com with healthy-access, got %s (%s)", email, newToken)
	}
	if pool.CurrentIdx != 1 {
		t.Errorf("expected CurrentIdx=1, got %d", pool.CurrentIdx)
	}
	if !pool.Accounts[0].CooldownUntil.After(time.Now()) {
		t.Errorf("dead account must be placed in cooldown")
	}
}



