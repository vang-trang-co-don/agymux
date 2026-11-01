package e2e_test

import (
	"net/http"
	"testing"
	"time"

	"agymux/internal/accounts"
)

// TestTier4_01_SimulatedMultiTurnSessionQuotaExhaustion simulates a realistic
// 6-turn interactive Antigravity coding session where multiple quota limits occur.
func TestTier4_01_SimulatedMultiTurnSessionQuotaExhaustion(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	t1 := "ya29.engineer_acc1"
	t2 := "ya29.engineer_acc2"
	t3 := "ya29.engineer_acc3"

	env.SeedAccounts([]*TestAccount{
		{Email: "dev1@org.com", AccessToken: t1, ExpiresAt: time.Now().Add(2 * time.Hour)},
		{Email: "dev2@org.com", AccessToken: t2, ExpiresAt: time.Now().Add(2 * time.Hour)},
		{Email: "dev3@org.com", AccessToken: t3, ExpiresAt: time.Now().Add(2 * time.Hour)},
	}, 0)

	// Upstream simulation sequence across 6 user turns:
	// Turn 1: 200 (Acc1)
	// Turn 2: 200 (Acc1)
	// Turn 3: 429 (Acc1 exhausted) -> Rotates to Acc2 -> 200 (Acc2)
	// Turn 4: 200 (Acc2)
	// Turn 5: 429 (Acc2 exhausted) -> Rotates to Acc3 -> 200 (Acc3)
	// Turn 6: 200 (Acc3)
	env.MockGoogle.SetResponseRules([]MockResponseRule{
		{StatusCode: http.StatusOK, Body: []byte(`{"turn": 1, "text": "HTTP server generated"}`)},
		{StatusCode: http.StatusOK, Body: []byte(`{"turn": 2, "text": "Middleware added"}`)},
		{StatusCode: http.StatusTooManyRequests, Body: []byte(`{"error":"quota limit reached"}`)},
		{StatusCode: http.StatusOK, Body: []byte(`{"turn": 3, "text": "Rate limiting added"}`)},
		{StatusCode: http.StatusOK, Body: []byte(`{"turn": 4, "text": "TLS configured"}`)},
		{StatusCode: http.StatusTooManyRequests, Body: []byte(`{"error":"quota limit reached"}`)},
		{StatusCode: http.StatusOK, Body: []byte(`{"turn": 5, "text": "Load test configured"}`)},
		{StatusCode: http.StatusOK, Body: []byte(`{"turn": 6, "text": "Refactoring complete"}`)},
	})

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")

	// Execute 6 user turns sequentially through the proxy
	for turn := 1; turn <= 6; turn++ {
		t.Setenv("AGY_REQUEST_BODY", `{"turn":`+itoa(turn)+`,"prompt":"Continue development"}`)
		_, _, exitCode, err := env.RunAgymux([]string{"turn", itoa(turn)}, "")
		if err != nil || exitCode != 0 {
			t.Fatalf("Turn %d failed: err=%v, code=%d", turn, err, exitCode)
		}
	}

	// Verify upstream received total of 8 requests (6 successful + 2 retried 429s)
	reqs := env.MockGoogle.GetRequests()
	if len(reqs) != 8 {
		t.Fatalf("expected 8 total requests to upstream, got %d", len(reqs))
	}

	// Turn 1 & 2 used Acc1
	if reqs[0].Token != t1 || reqs[1].Token != t1 {
		t.Errorf("Turn 1-2 should use acc1: got [%s, %s]", reqs[0].Token, reqs[1].Token)
	}
	// Turn 3 1st attempt used Acc1 (got 429), 2nd attempt used Acc2 (got 200)
	if reqs[2].Token != t1 || reqs[3].Token != t2 {
		t.Errorf("Turn 3 rotation mismatch: got [%s, %s]", reqs[2].Token, reqs[3].Token)
	}
	// Turn 4 used Acc2
	if reqs[4].Token != t2 {
		t.Errorf("Turn 4 should use acc2: got %s", reqs[4].Token)
	}
	// Turn 5 1st attempt used Acc2 (got 429), 2nd attempt used Acc3 (got 200)
	if reqs[5].Token != t2 || reqs[6].Token != t3 {
		t.Errorf("Turn 5 rotation mismatch: got [%s, %s]", reqs[5].Token, reqs[6].Token)
	}
	// Turn 6 used Acc3
	if reqs[7].Token != t3 {
		t.Errorf("Turn 6 should use acc3: got %s", reqs[7].Token)
	}

	// Final pool state check: Acc1 & Acc2 in Cooldown, Acc3 is Active
	pool := env.ReadAccounts()
	if pool.CurrentIdx != 2 {
		t.Errorf("expected final CurrentIdx 2, got %d", pool.CurrentIdx)
	}
	if pool.Accounts[0].CooldownUntil.IsZero() || pool.Accounts[1].CooldownUntil.IsZero() {
		t.Error("expected Acc1 and Acc2 to be in cooldown")
	}
}

// TestTier4_02_AllAccountsExhaustedAndCooldownRecovery simulates quota exhaustion
// across all accounts, followed by recovery after 30-minute cooldown window expires.
func TestTier4_02_AllAccountsExhaustedAndCooldownRecovery(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	pool, err := accounts.LoadPool()
	if err != nil {
		t.Fatalf("LoadPool failed: %v", err)
	}

	acc1 := &accounts.Account{
		Email:       "acc1@cloud.com",
		AccessToken: "token_acc1",
		ExpiresAt:   time.Now().Add(2 * time.Hour),
	}
	acc2 := &accounts.Account{
		Email:       "acc2@cloud.com",
		AccessToken: "token_acc2",
		ExpiresAt:   time.Now().Add(2 * time.Hour),
	}
	_ = pool.AddAccount(acc1)
	_ = pool.AddAccount(acc2)

	// Step 1: Both accounts hit 429
	_, _, _ = pool.RotateOnQuota("Acc1 429")
	_, _, _ = pool.RotateOnQuota("Acc2 429")

	// Both accounts are now in cooldown
	now := time.Now()
	if !acc1.CooldownUntil.After(now) || !acc2.CooldownUntil.After(now) {
		t.Fatal("expected both accounts to be in cooldown")
	}

	// Step 2: Simulate passage of 31 minutes
	acc1.CooldownUntil = now.Add(-1 * time.Minute) // Acc1 recovered!
	_ = pool.Save()

	// Step 3: Get active token after cooldown recovery
	token, email, err := pool.GetActiveToken()
	if err != nil {
		t.Fatalf("GetActiveToken failed after recovery: %v", err)
	}

	if email != "acc1@cloud.com" {
		t.Errorf("expected recovered account acc1@cloud.com, got %s", email)
	}
	if token != "token_acc1" {
		t.Errorf("expected token_acc1, got %s", token)
	}
}

// TestTier4_03_MixedTrafficEnterpriseSession verifies that Google endpoints undergo
// token injection and rotation while third-party endpoints pass cleanly untouched.
func TestTier4_03_MixedTrafficEnterpriseSession(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	googleToken := "ya29.enterprise_google"
	env.SeedAccounts([]*TestAccount{
		{Email: "corp@example.com", AccessToken: googleToken, ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	// 1. Google endpoint request -> Bearer token injected
	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")
	t.Setenv("AGY_REQUEST_AUTH", "Bearer dummy")

	_, _, exitCode, err := env.RunAgymux([]string{"google-call"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("Google endpoint call failed: %v", err)
	}

	reqs := env.MockGoogle.GetRequests()
	if len(reqs) == 0 {
		t.Fatal("expected request to reach Google mock")
	}
	if reqs[0].Token != googleToken {
		t.Errorf("expected injected token %q, got %q", googleToken, reqs[0].Token)
	}

	// 2. Non-Google endpoint request -> Original header preserved
	env.MockGoogle.ClearRequests()
	externalAuth := "Bearer npm_token_secret_1234"
	t.Setenv("AGY_REQUEST_URL", "http://"+env.UpstreamAddress+"/npm/registry")
	t.Setenv("AGY_REQUEST_METHOD", "GET")
	t.Setenv("AGY_REQUEST_AUTH", externalAuth)

	_, _, exitCode, err = env.RunAgymux([]string{"npm-call"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("External endpoint call failed: %v", err)
	}

	reqs = env.MockGoogle.GetRequests()
	if len(reqs) == 0 {
		t.Fatal("expected request to reach mock")
	}
	if reqs[0].Token != "npm_token_secret_1234" {
		t.Errorf("expected original token preserved for external endpoint, got %q", reqs[0].Token)
	}
}
