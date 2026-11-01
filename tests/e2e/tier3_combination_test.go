package e2e_test

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"agymux/internal/accounts"
)

// TestTier3_01_FullLifecycle_LoginListRotateLogout exercises the entire workflow:
// login -> pool update -> list -> proxy 429 rotation -> cooldown status check -> logout.
func TestTier3_01_FullLifecycle_LoginListRotateLogout(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	acc1Email := "primary@company.com"
	acc1Token := "ya29.primary_token"
	acc2Email := "secondary@company.com"
	acc2Token := "ya29.secondary_token"

	// 1. Seed two accounts (simulating successful logins)
	env.SeedAccounts([]*TestAccount{
		{Email: acc1Email, AccessToken: acc1Token, ExpiresAt: time.Now().Add(1 * time.Hour)},
		{Email: acc2Email, AccessToken: acc2Token, ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	// 2. Verify agymux list displays both accounts with primary active
	stdout, _, exitCode, err := env.RunAgymux([]string{"list"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("agymux list failed: %v", err)
	}
	if !strings.Contains(stdout, acc1Email) || !strings.Contains(stdout, acc2Email) {
		t.Errorf("list missing accounts:\n%s", stdout)
	}
	if !strings.Contains(stdout, "[★ ACTIVE]") {
		t.Errorf("list missing active tag:\n%s", stdout)
	}

	// 3. Configure mock backend: primary hits 429, secondary hits 200
	env.MockGoogle.SetResponseRules([]MockResponseRule{
		{StatusCode: http.StatusTooManyRequests, Body: []byte(`{"error":"quota exceeded"}`)},
		{StatusCode: http.StatusOK, Body: []byte(`{"response":"model completion success"}`)},
	})

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")

	// 4. Run proxy session
	_, _, exitCode, err = env.RunAgymux([]string{"chat", "generate"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("agymux proxy session failed: %v", err)
	}

	reqs := env.MockGoogle.GetRequests()
	if len(reqs) != 2 {
		t.Fatalf("expected 2 requests during rotation replay, got %d", len(reqs))
	}
	if reqs[0].Token != acc1Token {
		t.Errorf("1st attempt did not use primary token: %s", reqs[0].Token)
	}
	if reqs[1].Token != acc2Token {
		t.Errorf("2nd attempt did not use secondary token: %s", reqs[1].Token)
	}

	// 5. Run agymux list again: verify primary is now in Cooldown and secondary is ACTIVE
	stdoutAfter, _, exitCode, err := env.RunAgymux([]string{"list"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("agymux list after rotation failed: %v", err)
	}
	if !strings.Contains(stdoutAfter, "Cooldown") && !strings.Contains(stdoutAfter, "Hết Quota") {
		t.Errorf("expected primary to show Cooldown status in list:\n%s", stdoutAfter)
	}

	// 6. Logout primary account
	_, _, exitCode, err = env.RunAgymux([]string{"logout", acc1Email}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("agymux logout failed: %v", err)
	}

	// 7. Verify only secondary account remains in pool
	pool := env.ReadAccounts()
	if len(pool.Accounts) != 1 {
		t.Fatalf("expected exactly 1 account remaining, got %d", len(pool.Accounts))
	}
	if pool.Accounts[0].Email != acc2Email {
		t.Errorf("expected remaining account to be %s, got %s", acc2Email, pool.Accounts[0].Email)
	}
}

// TestTier3_02_ConcurrentRequestsUnder429Rotation verifies thread safety
// when multiple concurrent requests trigger 429 quota exhaustion.
func TestTier3_02_ConcurrentRequestsUnder429Rotation(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	pool, err := accounts.LoadPool()
	if err != nil {
		t.Fatalf("LoadPool failed: %v", err)
	}

	for i := 1; i <= 5; i++ {
		_ = pool.AddAccount(&accounts.Account{
			Email:       string(rune('a'+i)) + "@example.com",
			AccessToken: "token_" + string(rune('a'+i)),
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		})
	}

	var wg sync.WaitGroup
	errCount := 0
	var mu sync.Mutex

	// 10 concurrent rotation attempts
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			_, _, err := pool.RotateOnQuota("concurrent 429")
			if err != nil {
				mu.Lock()
				errCount++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	// Verify pool integrity after concurrent rotations
	reloaded, err := accounts.LoadPool()
	if err != nil {
		t.Fatalf("failed to reload pool after concurrent operations: %v", err)
	}
	if len(reloaded.Accounts) != 5 {
		t.Errorf("expected 5 accounts preserved, got %d", len(reloaded.Accounts))
	}
	if reloaded.CurrentIdx < 0 || reloaded.CurrentIdx >= len(reloaded.Accounts) {
		t.Errorf("current_idx out of bounds: %d", reloaded.CurrentIdx)
	}
}

// TestTier3_03_TerminalManualLoginThenProxySession verifies manual login
// followed by child proxy execution.
func TestTier3_03_TerminalManualLoginThenProxySession(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	// Initial pool empty
	env.SeedAccounts([]*TestAccount{}, 0)

	// Simulate adding account from terminal manual entry
	newToken := "ya29.terminal_manual_token_777"
	newEmail := "terminal_user@example.com"
	env.SeedAccounts([]*TestAccount{
		{
			Email:        newEmail,
			AccessToken:  newToken,
			RefreshToken: "refresh_terminal",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
			AddedAt:      time.Now(),
		},
	}, 0)

	// Launch agymux session
	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")

	_, _, exitCode, err := env.RunAgymux([]string{"stream"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: %v", err)
	}

	reqs := env.MockGoogle.GetRequests()
	if len(reqs) == 0 {
		t.Fatal("expected request to reach mock backend")
	}
	if reqs[0].Token != newToken {
		t.Errorf("expected newly logged-in token %q, got %q", newToken, reqs[0].Token)
	}
}

// TestTier3_04_CooldownExpirationTransitionsBackToActive verifies that when cooldown
// time elapses, the account becomes eligible for active use again.
func TestTier3_04_CooldownExpirationTransitionsBackToActive(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	pool, err := accounts.LoadPool()
	if err != nil {
		t.Fatalf("LoadPool failed: %v", err)
	}

	pastTime := time.Now().Add(-35 * time.Minute) // Cooldown expired 5 minutes ago
	acc1 := &accounts.Account{
		Email:         "recovered@example.com",
		AccessToken:   "token_recovered",
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		CooldownUntil: pastTime,
	}
	_ = pool.AddAccount(acc1)
	pool.CurrentIdx = 0

	token, email, err := pool.GetActiveToken()
	if err != nil {
		t.Fatalf("GetActiveToken failed for recovered account: %v", err)
	}

	if email != "recovered@example.com" {
		t.Errorf("expected recovered account to be selected, got %s", email)
	}
	if token != "token_recovered" {
		t.Errorf("expected token_recovered, got %s", token)
	}
}
