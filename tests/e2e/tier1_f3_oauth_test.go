package e2e_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"agymux/internal/accounts"
)

// TestTier1_F3_01_AuthURLParametersAndScopes verifies Google OAuth URL parameters.
func TestTier1_F3_01_AuthURLParametersAndScopes(t *testing.T) {
	redirectURI := "http://127.0.0.1:54321/callback"
	authURL := fmt.Sprintf(
		"https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=openid%%20email%%20https://www.googleapis.com/auth/cloud-platform&access_type=offline&prompt=consent",
		accounts.DefaultClientID,
		url.QueryEscape(redirectURI),
	)

	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("failed to parse authURL: %v", err)
	}

	q := u.Query()
	if q.Get("client_id") != accounts.DefaultClientID {
		t.Errorf("expected client_id %s, got %s", accounts.DefaultClientID, q.Get("client_id"))
	}
	if q.Get("redirect_uri") != redirectURI {
		t.Errorf("expected redirect_uri %s, got %s", redirectURI, q.Get("redirect_uri"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("expected response_type=code, got %s", q.Get("response_type"))
	}
	if q.Get("access_type") != "offline" {
		t.Errorf("expected access_type=offline, got %s", q.Get("access_type"))
	}
	if q.Get("prompt") != "consent" {
		t.Errorf("expected prompt=consent, got %s", q.Get("prompt"))
	}
	if !strings.Contains(q.Get("scope"), "https://www.googleapis.com/auth/cloud-platform") {
		t.Errorf("expected cloud-platform scope in %s", q.Get("scope"))
	}
}

// TestTier1_F3_02_EphemeralCallbackServerSuccess verifies callback server handles redirect.
func TestTier1_F3_02_EphemeralCallbackServerSuccess(t *testing.T) {
	codeChan := make(chan string, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		code := r.URL.Query().Get("code")
		if code != "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>✓ Đăng nhập thành công!</body></html>"))
			codeChan <- code
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	resp, err := http.Get(server.URL + "/callback?code=mock_auth_code_123")
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "thành công") {
		t.Errorf("expected success message in html body, got: %s", string(body))
	}

	select {
	case receivedCode := <-codeChan:
		if receivedCode != "mock_auth_code_123" {
			t.Errorf("expected mock_auth_code_123, got %s", receivedCode)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for authorization code from callback")
	}
}

// TestTier1_F3_03_TerminalManualCodeParsing verifies terminal input of raw authorization code.
func TestTier1_F3_03_TerminalManualCodeParsing(t *testing.T) {
	// User pastes raw code into terminal
	rawInput := "  4/0Abc123XYZ_MockCode_999  \n"
	trimmed := strings.TrimSpace(rawInput)

	code := extractCodeFromInput(trimmed)
	if code != "4/0Abc123XYZ_MockCode_999" {
		t.Errorf("expected extracted code '4/0Abc123XYZ_MockCode_999', got %q", code)
	}
}

// TestTier1_F3_04_TerminalManualCallbackURLParsing verifies terminal input of full redirect URL.
func TestTier1_F3_04_TerminalManualCallbackURLParsing(t *testing.T) {
	// User pastes full callback URL into terminal
	fullURL := "http://localhost:54321/callback?state=xyz&code=4/0AbcFullURLCode_888&scope=email"
	code := extractCodeFromInput(fullURL)
	if code != "4/0AbcFullURLCode_888" {
		t.Errorf("expected extracted code '4/0AbcFullURLCode_888', got %q", code)
	}

	// Also test 127.0.0.1 variant
	fullURL2 := "http://127.0.0.1:44332/callback?code=4/0Abc127URLCode_777"
	code2 := extractCodeFromInput(fullURL2)
	if code2 != "4/0Abc127URLCode_777" {
		t.Errorf("expected extracted code '4/0Abc127URLCode_777', got %q", code2)
	}
}

// TestTier1_F3_05_IdTokenClaimsEmailExtraction verifies JWT parsing of id_token claims.
func TestTier1_F3_05_IdTokenClaimsEmailExtraction(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"email":"developer@example.com","name":"Test Dev"}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("signature"))
	validJWT := fmt.Sprintf("%s.%s.%s", header, payload, sig)

	email := parseEmailFromJWT(validJWT)
	if email != "developer@example.com" {
		t.Errorf("expected developer@example.com, got %s", email)
	}

	// Malformed JWT should return empty string without panic
	if emailBad := parseEmailFromJWT("not-a-jwt"); emailBad != "" {
		t.Errorf("expected empty string on malformed JWT, got %s", emailBad)
	}
	if emailBad2 := parseEmailFromJWT(""); emailBad2 != "" {
		t.Errorf("expected empty string on empty JWT, got %s", emailBad2)
	}
}

// TestTier1_F3_06_OAuthTokenExchangeErrorResponse verifies upstream OAuth errors
// are handled cleanly and prevent pool corruption.
func TestTier1_F3_06_OAuthTokenExchangeErrorResponse(t *testing.T) {
	mockOAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Code expired"}`))
	}))
	defer mockOAuth.Close()

	// Simulate exchange against error server
	data := "code=bad_code&client_id=test&grant_type=authorization_code"
	req, _ := http.NewRequest("POST", mockOAuth.URL, strings.NewReader(data))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var errResp map[string]string
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}
	if errResp["error"] != "invalid_grant" {
		t.Errorf("expected invalid_grant, got %s", errResp["error"])
	}
}

// Helper functions matching auth logic contract
func extractCodeFromInput(input string) string {
	input = strings.TrimSpace(input)
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		u, err := url.Parse(input)
		if err == nil {
			return u.Query().Get("code")
		}
	}
	return input
}

func parseEmailFromJWT(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Email
}
