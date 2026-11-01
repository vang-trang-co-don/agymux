package e2e_test

import (
	"testing"
	"time"
)

// TestTier1_F5_01_InterceptCloudcodePA verifies Authorization header replacement on
// cloudcode-pa.googleapis.com.
func TestTier1_F5_01_InterceptCloudcodePA(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	activeToken := "ya29.active_google_token_999"
	env.SeedAccounts([]*TestAccount{
		{
			Email:       "active@example.com",
			AccessToken: activeToken,
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}, 0)

	// Instruct mock agy to send request with a dummy or expired auth header
	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")
	t.Setenv("AGY_REQUEST_AUTH", "Bearer dummy_client_token")
	t.Setenv("AGY_REQUEST_BODY", `{"prompt":"test intercept"}`)

	_, _, exitCode, err := env.RunAgymux([]string{"stream"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d", err, exitCode)
	}

	reqs := env.MockGoogle.GetRequests()
	if len(reqs) == 0 {
		t.Fatal("expected request to reach mock backend")
	}

	// Verify proxy replaced the Authorization header with the active account's token
	if reqs[0].Token != activeToken {
		t.Errorf("expected token %q injected into request, got %q", activeToken, reqs[0].Token)
	}
}

// TestTier1_F5_02_InterceptDailyCloudcodePA verifies interception on staging domain.
func TestTier1_F5_02_InterceptDailyCloudcodePA(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	activeToken := "ya29.daily_staging_token_888"
	env.SeedAccounts([]*TestAccount{
		{
			Email:       "daily@example.com",
			AccessToken: activeToken,
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}, 0)

	t.Setenv("AGY_REQUEST_URL", "https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist")
	t.Setenv("AGY_REQUEST_METHOD", "POST")
	t.Setenv("AGY_REQUEST_AUTH", "Bearer client_token")

	_, _, exitCode, err := env.RunAgymux([]string{"load"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d", err, exitCode)
	}

	reqs := env.MockGoogle.GetRequests()
	if len(reqs) == 0 {
		t.Fatal("expected request to reach mock backend")
	}

	if reqs[0].Token != activeToken {
		t.Errorf("expected daily token %q, got %q", activeToken, reqs[0].Token)
	}
}

// TestTier1_F5_03_NonTargetDomainPassthrough verifies non-Google domains do NOT have
// their Authorization header modified.
func TestTier1_F5_03_NonTargetDomainPassthrough(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{
			Email:       "active@example.com",
			AccessToken: "ya29.agymux_token",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}, 0)

	clientAuth := "Bearer github_pat_11223344"
	t.Setenv("AGY_REQUEST_URL", "http://"+env.UpstreamAddress+"/api/v3/user")
	t.Setenv("AGY_REQUEST_METHOD", "GET")
	t.Setenv("AGY_REQUEST_AUTH", clientAuth)

	_, _, exitCode, err := env.RunAgymux([]string{"get"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d", err, exitCode)
	}

	reqs := env.MockGoogle.GetRequests()
	if len(reqs) == 0 {
		t.Fatal("expected request to reach mock backend")
	}

	// For non-target domains, Authorization header must NOT be replaced!
	if reqs[0].Token != "github_pat_11223344" {
		t.Errorf("expected original client token %q preserved, got %q", "github_pat_11223344", reqs[0].Token)
	}
}

// TestTier1_F5_04_HeaderPreservation verifies client headers are preserved intact.
func TestTier1_F5_04_HeaderPreservation(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{
			Email:       "active@example.com",
			AccessToken: "ya29.token_preserve",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}, 0)

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")
	t.Setenv("AGY_REQUEST_BODY", `{"content":"hello"}`)

	_, _, exitCode, err := env.RunAgymux([]string{"chat"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d", err, exitCode)
	}

	reqs := env.MockGoogle.GetRequests()
	if len(reqs) == 0 {
		t.Fatal("expected request to reach mock backend")
	}

	// Verify Content-Type was preserved
	contentType := reqs[0].Headers.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", contentType)
	}
}

// TestTier1_F5_05_HostWithPortInterception verifies matching when port is explicit.
func TestTier1_F5_05_HostWithPortInterception(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	token := "ya29.token_port_match"
	env.SeedAccounts([]*TestAccount{
		{
			Email:       "port@example.com",
			AccessToken: token,
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}, 0)

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com:443/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")

	_, _, exitCode, err := env.RunAgymux([]string{"port-test"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d", err, exitCode)
	}

	reqs := env.MockGoogle.GetRequests()
	if len(reqs) == 0 {
		t.Fatal("expected request to reach mock backend")
	}

	if reqs[0].Token != token {
		t.Errorf("expected token %q for host with explicit port, got %q", token, reqs[0].Token)
	}
}
