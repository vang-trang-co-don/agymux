package e2e_test

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestTier1_F6_01_Single429SeamlessReplay verifies that when upstream returns 429,
// proxy rotates token to next standby account and replays without client error.
func TestTier1_F6_01_Single429SeamlessReplay(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	acc1Token := "ya29.acc1_exhausted"
	acc2Token := "ya29.acc2_fresh"

	env.SeedAccounts([]*TestAccount{
		{
			Email:       "acc1@example.com",
			AccessToken: acc1Token,
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
		{
			Email:       "acc2@example.com",
			AccessToken: acc2Token,
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}, 0)

	// Configure mock backend rules:
	// 1st request -> HTTP 429
	// 2nd request -> HTTP 200
	env.MockGoogle.SetResponseRules([]MockResponseRule{
		{
			StatusCode: http.StatusTooManyRequests,
			Body:       []byte(`{"error":{"code":429,"message":"RESOURCE_EXHAUSTED"}}`),
		},
		{
			StatusCode: http.StatusOK,
			Body:       []byte(`{"candidates":[{"content":{"parts":[{"text":"Successfully recovered!"}]}}]}`),
		},
	})

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")
	t.Setenv("AGY_REQUEST_BODY", `{"prompt":"test seamless rotation"}`)

	stdout, stderr, exitCode, err := env.RunAgymux([]string{"stream"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d\nStdout: %s\nStderr: %s", err, exitCode, stdout, stderr)
	}

	// Client (mock agy) must have received HTTP 200 without ever seeing the 429
	respData, err := os.ReadFile(env.AgyRespFile)
	if err != nil {
		t.Fatalf("failed to read agy_resp.json: %v", err)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(respData, &resp); err != nil {
		t.Fatalf("failed to parse agy response: %v", err)
	}

	if int(resp["status_code"].(float64)) != 200 {
		t.Fatalf("expected client to receive 200, got %v", resp["status_code"])
	}
	if !strings.Contains(resp["body"].(string), "Successfully recovered!") {
		t.Errorf("expected recovered response body, got %s", resp["body"])
	}

	// Verify upstream recorded 2 requests: 1st with acc1, 2nd with acc2
	reqs := env.MockGoogle.GetRequests()
	if len(reqs) != 2 {
		t.Fatalf("expected upstream to receive exactly 2 requests (initial + replay), got %d", len(reqs))
	}
	if reqs[0].Token != acc1Token {
		t.Errorf("expected 1st request token %q, got %q", acc1Token, reqs[0].Token)
	}
	if reqs[1].Token != acc2Token {
		t.Errorf("expected 2nd request token %q, got %q", acc2Token, reqs[1].Token)
	}

	// Verify accounts.json updated on disk: acc1 in cooldown, acc2 active
	pool := env.ReadAccounts()
	if pool.CurrentIdx != 1 {
		t.Errorf("expected CurrentIdx 1, got %d", pool.CurrentIdx)
	}
	if time.Until(pool.Accounts[0].CooldownUntil) < 25*time.Minute {
		t.Errorf("expected acc1 to be placed in ~30m cooldown, got %v", pool.Accounts[0].CooldownUntil)
	}
}

// TestTier1_F6_02_Multi429CascadingRotation verifies multiple 429 responses rotate
// sequentially through available accounts until an account succeeds.
func TestTier1_F6_02_Multi429CascadingRotation(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	t1 := "ya29.acc1"
	t2 := "ya29.acc2"
	t3 := "ya29.acc3"

	env.SeedAccounts([]*TestAccount{
		{Email: "acc1@example.com", AccessToken: t1, ExpiresAt: time.Now().Add(1 * time.Hour)},
		{Email: "acc2@example.com", AccessToken: t2, ExpiresAt: time.Now().Add(1 * time.Hour)},
		{Email: "acc3@example.com", AccessToken: t3, ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	// Acc1 -> 429, Acc2 -> 429, Acc3 -> 200
	env.MockGoogle.SetResponseRules([]MockResponseRule{
		{StatusCode: http.StatusTooManyRequests, Body: []byte(`{"error":"quota1"}`)},
		{StatusCode: http.StatusTooManyRequests, Body: []byte(`{"error":"quota2"}`)},
		{StatusCode: http.StatusOK, Body: []byte(`{"result":"success from acc3"}`)},
	})

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")

	_, _, exitCode, err := env.RunAgymux([]string{"prompt"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d", err, exitCode)
	}

	reqs := env.MockGoogle.GetRequests()
	if len(reqs) != 3 {
		t.Fatalf("expected 3 requests to upstream, got %d", len(reqs))
	}
	if reqs[0].Token != t1 || reqs[1].Token != t2 || reqs[2].Token != t3 {
		t.Errorf("tokens mismatch in rotation sequence: [%s, %s, %s]",
			reqs[0].Token, reqs[1].Token, reqs[2].Token)
	}

	pool := env.ReadAccounts()
	if pool.CurrentIdx != 2 {
		t.Errorf("expected CurrentIdx 2 (acc3 active), got %d", pool.CurrentIdx)
	}
	if pool.Accounts[0].CooldownUntil.IsZero() || pool.Accounts[1].CooldownUntil.IsZero() {
		t.Error("expected acc1 and acc2 to be in cooldown")
	}
}

// TestTier1_F6_03_AllAccountsExhaustedReturns429 verifies proxy returns 429 to client
// when all accounts in pool are exhausted.
func TestTier1_F6_03_AllAccountsExhaustedReturns429(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{Email: "acc1@example.com", AccessToken: "t1", ExpiresAt: time.Now().Add(1 * time.Hour)},
		{Email: "acc2@example.com", AccessToken: "t2", ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	// All accounts return 429
	env.MockGoogle.SetResponseRules([]MockResponseRule{
		{StatusCode: http.StatusTooManyRequests, Body: []byte(`{"error":"all exhausted 1"}`)},
		{StatusCode: http.StatusTooManyRequests, Body: []byte(`{"error":"all exhausted 2"}`)},
	})

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")

	_, _, exitCode, err := env.RunAgymux([]string{"stream"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d", err, exitCode)
	}

	respData, err := os.ReadFile(env.AgyRespFile)
	if err != nil {
		t.Fatalf("failed to read agy_resp.json: %v", err)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(respData, &resp)

	// Client should receive HTTP 429 because pool is fully exhausted
	if int(resp["status_code"].(float64)) != http.StatusTooManyRequests {
		t.Errorf("expected 429 returned to client when pool exhausted, got %v", resp["status_code"])
	}
}

// TestTier1_F6_04_RequestBodyIntegrityOnReplay verifies request body is intact across replays.
func TestTier1_F6_04_RequestBodyIntegrityOnReplay(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	complexBody := `{"contents":[{"role":"user","parts":[{"text":"Multi-line\nComplex\tJSON\nPayload"}]}],"generationConfig":{"temperature":0.7}}`

	env.SeedAccounts([]*TestAccount{
		{Email: "acc1@example.com", AccessToken: "t1", ExpiresAt: time.Now().Add(1 * time.Hour)},
		{Email: "acc2@example.com", AccessToken: "t2", ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	env.MockGoogle.SetResponseRules([]MockResponseRule{
		{StatusCode: http.StatusTooManyRequests, Body: []byte(`{"error":"retry"}`)},
		{StatusCode: http.StatusOK, Body: []byte(`{"status":"ok"}`)},
	})

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")
	t.Setenv("AGY_REQUEST_BODY", complexBody)

	_, _, exitCode, err := env.RunAgymux([]string{"prompt"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d", err, exitCode)
	}

	reqs := env.MockGoogle.GetRequests()
	if len(reqs) < 2 {
		t.Fatalf("expected at least 2 requests, got %d", len(reqs))
	}
	if string(reqs[0].Body) != complexBody {
		t.Errorf("1st attempt body mismatch: %q", string(reqs[0].Body))
	}
	if string(reqs[1].Body) != complexBody {
		t.Errorf("replayed attempt body mismatch: %q", string(reqs[1].Body))
	}
}

// TestTier1_F6_05_SSEStreamingStreamPipedAfter200 verifies SSE streaming after rotation.
func TestTier1_F6_05_SSEStreamingStreamPipedAfter200(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{Email: "acc1@example.com", AccessToken: "t1", ExpiresAt: time.Now().Add(1 * time.Hour)},
		{Email: "acc2@example.com", AccessToken: "t2", ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	sseChunks := [][]byte{
		[]byte("data: {\"chunk\": 1}\n\n"),
		[]byte("data: {\"chunk\": 2}\n\n"),
		[]byte("data: [DONE]\n\n"),
	}

	env.MockGoogle.SetResponseRules([]MockResponseRule{
		{StatusCode: http.StatusTooManyRequests, Body: []byte(`{"error":"retry"}`)},
		{StatusCode: http.StatusOK, IsSSE: true, SSEChunks: sseChunks},
	})

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse")
	t.Setenv("AGY_REQUEST_METHOD", "POST")

	_, _, exitCode, err := env.RunAgymux([]string{"stream"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d", err, exitCode)
	}

	respData, err := os.ReadFile(env.AgyRespFile)
	if err != nil {
		t.Fatalf("failed to read agy_resp.json: %v", err)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(respData, &resp)

	body := resp["body"].(string)
	if !strings.Contains(body, "{\"chunk\": 1}") || !strings.Contains(body, "[DONE]") {
		t.Errorf("expected full SSE stream delivered after rotation, got: %s", body)
	}
}

// TestTier1_F6_06_DynamicCooldownTransientRateLimit verifies that a transient 429
// with Retry-After header applies a short dynamic cooldown instead of static 30m.
func TestTier1_F6_06_DynamicCooldownTransientRateLimit(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	acc1Token := "ya29.acc1_transient"
	acc2Token := "ya29.acc2_fresh"

	env.SeedAccounts([]*TestAccount{
		{
			Email:       "acc1@example.com",
			AccessToken: acc1Token,
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
		{
			Email:       "acc2@example.com",
			AccessToken: acc2Token,
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}, 0)

	// Mock Google PA backend:
	// 1st request -> 429 with Retry-After: 15s
	// 2nd request -> 200 OK
	env.MockGoogle.SetResponseRules([]MockResponseRule{
		{
			StatusCode: http.StatusTooManyRequests,
			Headers: map[string]string{
				"Retry-After": "15",
			},
			Body: []byte(`{"error":{"code":429,"message":"Rate limit exceeded"}}`),
		},
		{
			StatusCode: http.StatusOK,
			Body:       []byte(`{"candidates":[{"content":{"parts":[{"text":"Success after transient 429!"}]}}]}`),
		},
	})

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")
	t.Setenv("AGY_REQUEST_BODY", `{"prompt":"test transient rate limit"}`)

	before := time.Now()
	stdout, stderr, exitCode, err := env.RunAgymux([]string{"prompt"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d\nStdout: %s\nStderr: %s", err, exitCode, stdout, stderr)
	}

	// Verify transparent in-flight retry succeeded
	reqs := env.MockGoogle.GetRequests()
	if len(reqs) != 2 {
		t.Fatalf("expected 2 requests to upstream, got %d", len(reqs))
	}
	if reqs[0].Token != acc1Token || reqs[1].Token != acc2Token {
		t.Errorf("expected sequence [acc1, acc2], got [%s, %s]", reqs[0].Token, reqs[1].Token)
	}

	// Verify acc1 was given ~15s cooldown on disk, NOT 30 minutes!
	pool := env.ReadAccounts()
	dur := pool.Accounts[0].CooldownUntil.Sub(before)
	if dur < 10*time.Second || dur > 20*time.Second {
		t.Errorf("expected acc1 cooldown ~15s (transient), got %v", dur)
	}
}

// TestTier1_F6_07_AllInCooldownSelectsEarliestRecoveryWithoutDeadlock reproduces the
// confirmed incident where all accounts are in cooldown, verifying agymux selects the
// earliest cooldown account and seamlessly recovers once that cooldown expires.
func TestTier1_F6_07_AllInCooldownSelectsEarliestRecoveryWithoutDeadlock(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	now := time.Now()
	acc0Token := "ya29.acc0_quick_recover"
	acc1Token := "ya29.acc1_long_cooldown"
	acc2Token := "ya29.acc2_exhausted"

	// Acc0 has 500ms cooldown (expires almost immediately)
	// Acc1 has 15m cooldown
	// Acc2 is active initially (CurrentIdx = 2)
	env.SeedAccounts([]*TestAccount{
		{
			Email:         "acc0@example.com",
			AccessToken:   acc0Token,
			ExpiresAt:     now.Add(1 * time.Hour),
			CooldownUntil: now.Add(500 * time.Millisecond),
		},
		{
			Email:         "acc1@example.com",
			AccessToken:   acc1Token,
			ExpiresAt:     now.Add(1 * time.Hour),
			CooldownUntil: now.Add(15 * time.Minute),
		},
		{
			Email:       "acc2@example.com",
			AccessToken: acc2Token,
			ExpiresAt:   now.Add(1 * time.Hour),
		},
	}, 2)

	// Step 1: Acc2 hits 429.
	// Since all accounts are in cooldown, proxy returns 429, BUT pool must select Acc0
	// (earliest cooldown) rather than locking onto exhausted Acc2!
	env.MockGoogle.SetResponseRules([]MockResponseRule{
		{
			StatusCode: http.StatusTooManyRequests,
			Body:       []byte(`{"error":{"code":429,"message":"Acc2 RESOURCE_EXHAUSTED"}}`),
		},
	})

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")

	_, _, exitCode, err := env.RunAgymux([]string{"prompt"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux 1 failed: err=%v, code=%d", err, exitCode)
	}

	// Verify accounts.json on disk: CurrentIdx MUST be 0 (Acc0, earliest cooldown)
	pool := env.ReadAccounts()
	if pool.CurrentIdx != 0 {
		t.Fatalf("expected pool CurrentIdx to rotate to Acc0 (earliest cooldown), got %d (email: %s)",
			pool.CurrentIdx, pool.Accounts[pool.CurrentIdx].Email)
	}

	// Step 2: Wait 600ms for Acc0 cooldown to expire
	time.Sleep(600 * time.Millisecond)

	// Step 3: Run next request. Acc0 is now recovered and ready.
	// Proxy must use Acc0 token and succeed with 200 OK!
	env.MockGoogle.ClearRequests()
	env.MockGoogle.SetResponseRules([]MockResponseRule{
		{
			StatusCode: http.StatusOK,
			Body:       []byte(`{"candidates":[{"content":{"parts":[{"text":"Acc0 recovered successfully!"}]}}]}`),
		},
	})

	_, _, exitCode, err = env.RunAgymux([]string{"prompt"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux 2 failed: err=%v, code=%d", err, exitCode)
	}

	reqs := env.MockGoogle.GetRequests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request on recovery, got %d", len(reqs))
	}
	if reqs[0].Token != acc0Token {
		t.Errorf("expected recovered request to use acc0Token %q, got %q", acc0Token, reqs[0].Token)
	}

	respData, err := os.ReadFile(env.AgyRespFile)
	if err != nil {
		t.Fatalf("failed to read agy_resp.json: %v", err)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(respData, &resp)
	if int(resp["status_code"].(float64)) != 200 {
		t.Errorf("expected HTTP 200 on recovery, got %v", resp["status_code"])
	}
}

// TestTier1_F6_08_ProTierPrioritySelectionAndRotation verifies that active accounts
// with AI Pro / higher tier are prioritized over free tier accounts.
func TestTier1_F6_08_ProTierPrioritySelectionAndRotation(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	freeToken := "ya29.free_account"
	proToken := "ya29.pro_account"

	// Acc0 is Free, Acc1 is AI Pro.
	// Seed pool with CurrentIdx = 0 (Free)
	env.SeedAccounts([]*TestAccount{
		{
			Email:       "free@example.com",
			AccessToken: freeToken,
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			Tier:        "free",
		},
		{
			Email:       "pro@example.com",
			AccessToken: proToken,
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			Tier:        "AI Pro",
		},
	}, 0)

	// 1st request (with Pro): 429
	// 2nd request (fallback to Free): 200 OK
	env.MockGoogle.SetResponseRules([]MockResponseRule{
		{
			StatusCode: http.StatusTooManyRequests,
			Body:       []byte(`{"error":{"code":429,"message":"Pro quota limit"}}`),
		},
		{
			StatusCode: http.StatusOK,
			Body:       []byte(`{"result":"Success from Free account"}`),
		},
	})

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")

	_, _, exitCode, err := env.RunAgymux([]string{"prompt"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d", err, exitCode)
	}

	reqs := env.MockGoogle.GetRequests()
	if len(reqs) != 2 {
		t.Fatalf("expected 2 requests (Pro attempt + Free replay), got %d", len(reqs))
	}

	// 1st request must have used Pro token despite CurrentIdx initially pointing to Free!
	if reqs[0].Token != proToken {
		t.Errorf("expected 1st attempt to prioritize Pro account token %q, got %q", proToken, reqs[0].Token)
	}
	// 2nd request used Free token after Pro hit 429
	if reqs[1].Token != freeToken {
		t.Errorf("expected 2nd attempt to fall back to Free token %q, got %q", freeToken, reqs[1].Token)
	}
}

// TestTier1_F6_09_InFlightRetryNeverReRetriesSameAccount verifies that even if an account's
// transient cooldown expires while retry loop is active, the proxy never re-attempts that account
// in the same in-flight request.
func TestTier1_F6_09_InFlightRetryNeverReRetriesSameAccount(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	proToken := "ya29.pro_exhausted"
	freeToken := "ya29.free_fresh"

	env.SeedAccounts([]*TestAccount{
		{
			Email:       "pro@example.com",
			AccessToken: proToken,
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			Tier:        "AI Pro",
		},
		{
			Email:       "free@example.com",
			AccessToken: freeToken,
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			Tier:        "free",
		},
	}, 0)

	// Pro account gets 429 with 5s transient cooldown
	// Free account gets 200 OK
	env.MockGoogle.SetResponseRules([]MockResponseRule{
		{
			StatusCode: http.StatusTooManyRequests,
			Headers: map[string]string{
				"Retry-After": "5",
			},
			Body: []byte(`{"error":{"code":429,"message":"Rate limit exceeded"}}`),
		},
		{
			StatusCode: http.StatusOK,
			Body:       []byte(`{"result":"Success from Free account"}`),
		},
	})

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")

	_, _, exitCode, err := env.RunAgymux([]string{"prompt"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d", err, exitCode)
	}

	reqs := env.MockGoogle.GetRequests()
	if len(reqs) != 2 {
		t.Fatalf("expected exactly 2 requests, got %d", len(reqs))
	}
	if reqs[0].Token != proToken {
		t.Errorf("expected attempt 1 to use proToken %q, got %q", proToken, reqs[0].Token)
	}
	if reqs[1].Token != freeToken {
		t.Errorf("expected attempt 2 to use freeToken %q, got %q", freeToken, reqs[1].Token)
	}
}

// TestTier1_F6_10_Proto3StatusFormatBSupport verifies that upstream responses in standard
// proto3 JSON format (without top-level "error" key) are parsed dynamically.
func TestTier1_F6_10_Proto3StatusFormatBSupport(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	acc1Token := "ya29.acc1"
	acc2Token := "ya29.acc2"

	env.SeedAccounts([]*TestAccount{
		{Email: "acc1@example.com", AccessToken: acc1Token, ExpiresAt: time.Now().Add(1 * time.Hour)},
		{Email: "acc2@example.com", AccessToken: acc2Token, ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	// Acc1 gets 429 with proto3 format B body
	proto3Body := `{
		"code": 429,
		"message": "Resource exhausted",
		"status": "RESOURCE_EXHAUSTED",
		"details": [
			{
				"@type": "type.googleapis.com/google.rpc.RetryInfo",
				"retryDelay": "12s"
			}
		]
	}`

	env.MockGoogle.SetResponseRules([]MockResponseRule{
		{
			StatusCode: http.StatusTooManyRequests,
			Body:       []byte(proto3Body),
		},
		{
			StatusCode: http.StatusOK,
			Body:       []byte(`{"result":"Success"}`),
		},
	})

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")

	before := time.Now()
	_, _, exitCode, err := env.RunAgymux([]string{"prompt"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d", err, exitCode)
	}

	pool := env.ReadAccounts()
	dur := pool.Accounts[0].CooldownUntil.Sub(before)
	// Acc1 must have received ~12s cooldown, NOT default 30m!
	if dur < 8*time.Second || dur > 16*time.Second {
		t.Errorf("expected acc1 cooldown ~12s from proto3 format B, got %v", dur)
	}
}

// TestTier1_F6_11_Single401SeamlessReplay verifies that when upstream returns HTTP 401 (Unauthorized),
// agymux automatically rotates to the next healthy standby account and replays without client failure.
func TestTier1_F6_11_Single401SeamlessReplay(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	acc1Token := "ya29.acc1_invalid_auth"
	acc2Token := "ya29.acc2_fresh"

	env.SeedAccounts([]*TestAccount{
		{
			Email:       "acc1@example.com",
			AccessToken: acc1Token,
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
		{
			Email:       "acc2@example.com",
			AccessToken: acc2Token,
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}, 0)

	// Configure mock backend rules:
	// 1st request -> HTTP 401 Unauthorized
	// 2nd request -> HTTP 200 OK
	env.MockGoogle.SetResponseRules([]MockResponseRule{
		{
			StatusCode: http.StatusUnauthorized,
			Body:       []byte(`{"error":{"code":401,"message":"Request had invalid authentication credentials.","status":"UNAUTHENTICATED"}}`),
		},
		{
			StatusCode: http.StatusOK,
			Body:       []byte(`{"candidates":[{"content":{"parts":[{"text":"Successfully recovered from 401!"}]}}]}`),
		},
	})

	t.Setenv("AGY_REQUEST_URL", "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
	t.Setenv("AGY_REQUEST_METHOD", "POST")
	t.Setenv("AGY_REQUEST_BODY", `{"prompt":"test 401 rotation"}`)

	stdout, stderr, exitCode, err := env.RunAgymux([]string{"stream"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("RunAgymux failed: err=%v, code=%d\nStdout: %s\nStderr: %s", err, exitCode, stdout, stderr)
	}

	// Client (mock agy) must have received HTTP 200 without ever seeing the 401
	respData, err := os.ReadFile(env.AgyRespFile)
	if err != nil {
		t.Fatalf("failed to read agy_resp.json: %v", err)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(respData, &resp); err != nil {
		t.Fatalf("failed to parse agy_resp: %v", err)
	}
	if int(resp["status_code"].(float64)) != 200 {
		t.Errorf("expected HTTP 200, got %v", resp["status_code"])
	}

	// Verify requests sent to upstream
	reqs := env.MockGoogle.GetRequests()
	if len(reqs) != 2 {
		t.Fatalf("expected 2 requests to upstream, got %d", len(reqs))
	}
	if reqs[0].Token != acc1Token {
		t.Errorf("expected 1st request with acc1Token %q, got %q", acc1Token, reqs[0].Token)
	}
	if reqs[1].Token != acc2Token {
		t.Errorf("expected 2nd request with acc2Token %q, got %q", acc2Token, reqs[1].Token)
	}

	// Verify acc1 was put in cooldown and current index moved to acc2 (idx 1)
	pool := env.ReadAccounts()
	if !pool.Accounts[0].CooldownUntil.After(time.Now()) {
		t.Errorf("expected acc1 to be in cooldown after 401, got %v", pool.Accounts[0].CooldownUntil)
	}
	if pool.CurrentIdx != 1 {
		t.Errorf("expected pool.CurrentIdx=1, got %d", pool.CurrentIdx)
	}
}


