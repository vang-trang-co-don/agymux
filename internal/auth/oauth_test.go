package auth_test

import (
	"agymux/internal/accounts"
	"agymux/internal/auth"
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
)

func TestExtractCode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "raw_code_standard",
			input:    "4/0AeanS-xyz123_StandardCode",
			expected: "4/0AeanS-xyz123_StandardCode",
		},
		{
			name:     "raw_code_with_quotes_and_spaces",
			input:    "  \"4/0AeanS-xyz123_QuotedCode\" \n ",
			expected: "4/0AeanS-xyz123_QuotedCode",
		},
		{
			name:     "raw_code_single_quotes",
			input:    "'4/0AeanS-xyz123_SingleQuoted'",
			expected: "4/0AeanS-xyz123_SingleQuoted",
		},
		{
			name:     "full_url_127.0.0.1_url-encoded_code",
			input:    "http://127.0.0.1:54321/callback?code=4%2F0AeanS-xyz123&scope=email",
			expected: "4/0AeanS-xyz123",
		},
		{
			name:     "full_url_localhost_with_state_and_code",
			input:    "http://localhost:54321/callback?state=xyz&code=4/0AeanS-xyz123&scope=email",
			expected: "4/0AeanS-xyz123",
		},
		{
			name:     "full_https_url",
			input:    "https://agymux.local/callback?code=code123",
			expected: "code123",
		},
		{
			name:     "url_without_scheme",
			input:    "127.0.0.1:54321/callback?code=code123",
			expected: "code123",
		},
		{
			name:     "path_only_with_code",
			input:    "/callback?code=code123",
			expected: "code123",
		},
		{
			name:     "query_string_only",
			input:    "?code=code123",
			expected: "code123",
		},
		{
			name:     "param_only",
			input:    "code=code123",
			expected: "code123",
		},
		{
			name:     "param_in_middle_of_query_string",
			input:    "foo=bar&code=code123&baz=qux",
			expected: "code123",
		},
		{
			name:     "oauth_error_url_without_code",
			input:    "http://127.0.0.1:54321/callback?error=access_denied&error_description=User+denied",
			expected: "",
		},
		{
			name:     "empty_input",
			input:    "",
			expected: "",
		},
		{
			name:     "whitespace_only",
			input:    "   \n\t  ",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := auth.ExtractCode(tc.input)
			if got != tc.expected {
				t.Errorf("ExtractCode(%q) = %q, expected %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestParseEmailFromIdToken(t *testing.T) {
	tests := []struct {
		name     string
		idToken  string
		expected string
	}{
		{
			name: "valid_jwt_unpadded",
			idToken: func() string {
				header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
				payload := base64.RawURLEncoding.EncodeToString([]byte(`{"email":"unpadded@example.com","name":"Unpadded"}`))
				sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
				return fmt.Sprintf("%s.%s.%s", header, payload, sig)
			}(),
			expected: "unpadded@example.com",
		},
		{
			name: "valid_jwt_padded",
			idToken: func() string {
				header := base64.URLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
				payload := base64.URLEncoding.EncodeToString([]byte(`{"email":"padded@example.com","name":"Padded"}`))
				sig := base64.URLEncoding.EncodeToString([]byte("sig"))
				return fmt.Sprintf("%s.%s.%s", header, payload, sig)
			}(),
			expected: "padded@example.com",
		},
		{
			name: "jwt_missing_email_claim",
			idToken: func() string {
				header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
				payload := base64.RawURLEncoding.EncodeToString([]byte(`{"name":"No Email"}`))
				sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
				return fmt.Sprintf("%s.%s.%s", header, payload, sig)
			}(),
			expected: "",
		},
		{
			name:     "empty_id_token",
			idToken:  "",
			expected: "",
		},
		{
			name:     "invalid_format_only_one_segment",
			idToken:  "onlyonesegment",
			expected: "",
		},
		{
			name:     "invalid_base64_payload",
			idToken:  "header.!!!not-base64!!!.signature",
			expected: "",
		},
		{
			name: "payload_is_not_json",
			idToken: func() string {
				header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
				payload := base64.RawURLEncoding.EncodeToString([]byte("plain text not json"))
				sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
				return fmt.Sprintf("%s.%s.%s", header, payload, sig)
			}(),
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := auth.ParseEmailFromIdToken(tc.idToken)
			if got != tc.expected {
				t.Errorf("ParseEmailFromIdToken() = %q, expected %q", got, tc.expected)
			}
		})
	}
}

func TestExchangeCodeForToken(t *testing.T) {
	tests := []struct {
		name        string
		handler     http.HandlerFunc
		expectError bool
		checkResp   func(t *testing.T, resp *auth.TokenExchangeResponse)
	}{
		{
			name: "successful_exchange",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				body, _ := io.ReadAll(r.Body)
				bodyStr := string(body)
				if !strings.Contains(bodyStr, "grant_type=authorization_code") || !strings.Contains(bodyStr, "code=test-code") {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token":  "mock-access-token-xyz",
					"refresh_token": "mock-refresh-token-abc",
					"expires_in":    3600,
					"token_type":    "Bearer",
					"id_token":      "mock.id.token",
				})
			},
			expectError: false,
			checkResp: func(t *testing.T, resp *auth.TokenExchangeResponse) {
				if resp.AccessToken != "mock-access-token-xyz" {
					t.Errorf("expected access_token 'mock-access-token-xyz', got %q", resp.AccessToken)
				}
				if resp.RefreshToken != "mock-refresh-token-abc" {
					t.Errorf("expected refresh_token 'mock-refresh-token-abc', got %q", resp.RefreshToken)
				}
			},
		},
		{
			name: "oauth_server_returns_400_bad_request",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Code expired"}`))
			},
			expectError: true,
		},
		{
			name: "oauth_server_returns_500_server_error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("internal error"))
			},
			expectError: true,
		},
		{
			name: "oauth_server_returns_invalid_json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("not json"))
			},
			expectError: true,
		},
		{
			name: "oauth_server_returns_missing_access_token",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"refresh_token":"abc"}`))
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(tc.handler)
			defer server.Close()

			origEndpoint := auth.TokenEndpoint
			auth.TokenEndpoint = server.URL
			defer func() { auth.TokenEndpoint = origEndpoint }()

			resp, err := auth.ExchangeCodeForToken("test-code", "http://127.0.0.1/callback")
			if tc.expectError && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.expectError && err != nil {
				t.Fatalf("expected success, got error: %v", err)
			}
			if tc.checkResp != nil && resp != nil {
				tc.checkResp(t, resp)
			}
		})
	}

	t.Run("network_connection_failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		serverURL := server.URL
		server.Close() // Close immediately to trigger connection refusal

		origEndpoint := auth.TokenEndpoint
		auth.TokenEndpoint = serverURL
		defer func() { auth.TokenEndpoint = origEndpoint }()

		_, err := auth.ExchangeCodeForToken("test-code", "http://127.0.0.1/callback")
		if err == nil {
			t.Fatalf("expected network failure error, got nil")
		}
	})
}

func makeMockJWT(email string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"email":%q}`, email)))
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	return fmt.Sprintf("%s.%s.%s", header, payload, sig)
}

func TestLoginWithReader_ManualTerminalInput(t *testing.T) {
	mockOAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "access-mock-123",
			"refresh_token": "refresh-mock-123",
			"expires_in":    3600,
			"token_type":    "Bearer",
			"id_token":      makeMockJWT("terminal-user@example.com"),
		})
	}))
	defer mockOAuth.Close()

	origEndpoint := auth.TokenEndpoint
	origOpener := auth.BrowserOpener
	origTimeout := auth.LoginTimeout
	auth.TokenEndpoint = mockOAuth.URL
	auth.BrowserOpener = func(url string) {}
	auth.LoginTimeout = 2 * time.Second
	defer func() {
		auth.TokenEndpoint = origEndpoint
		auth.BrowserOpener = origOpener
		auth.LoginTimeout = origTimeout
	}()

	t.Run("manual_raw_code_entry", func(t *testing.T) {
		pool, err := accounts.LoadPoolFrom(t.TempDir())
		if err != nil {
			t.Fatalf("LoadPoolFrom failed: %v", err)
		}

		in := strings.NewReader("4/raw-auth-code-123\n")
		if err := auth.LoginWithReader(pool, in); err != nil {
			t.Fatalf("LoginWithReader failed: %v", err)
		}

		if len(pool.Accounts) != 1 {
			t.Fatalf("expected 1 account in pool, got %d", len(pool.Accounts))
		}
		if pool.Accounts[0].Email != "terminal-user@example.com" {
			t.Errorf("expected email terminal-user@example.com, got %s", pool.Accounts[0].Email)
		}
		if pool.Accounts[0].AccessToken != "access-mock-123" {
			t.Errorf("expected access token access-mock-123, got %s", pool.Accounts[0].AccessToken)
		}
	})

	t.Run("manual_full_callback_url_entry", func(t *testing.T) {
		pool, err := accounts.LoadPoolFrom(t.TempDir())
		if err != nil {
			t.Fatalf("LoadPoolFrom failed: %v", err)
		}

		in := strings.NewReader("http://127.0.0.1:54321/callback?code=4%2Ffull-url-code-456&state=xyz\n")
		if err := auth.LoginWithReader(pool, in); err != nil {
			t.Fatalf("LoginWithReader failed: %v", err)
		}

		if len(pool.Accounts) != 1 {
			t.Fatalf("expected 1 account in pool, got %d", len(pool.Accounts))
		}
		if pool.Accounts[0].Email != "terminal-user@example.com" {
			t.Errorf("expected email terminal-user@example.com, got %s", pool.Accounts[0].Email)
		}
	})
}

func TestLoginWithReader_HTTPCallback(t *testing.T) {
	mockOAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "access-http-123",
			"refresh_token": "refresh-http-123",
			"expires_in":    3600,
			"token_type":    "Bearer",
			"id_token":      makeMockJWT("browser-user@example.com"),
		})
	}))
	defer mockOAuth.Close()

	origEndpoint := auth.TokenEndpoint
	origOpener := auth.BrowserOpener
	origTimeout := auth.LoginTimeout
	auth.TokenEndpoint = mockOAuth.URL
	auth.LoginTimeout = 2 * time.Second
	defer func() {
		auth.TokenEndpoint = origEndpoint
		auth.BrowserOpener = origOpener
		auth.LoginTimeout = origTimeout
	}()

	t.Run("browser_redirect_callback_success", func(t *testing.T) {
		pool, err := accounts.LoadPoolFrom(t.TempDir())
		if err != nil {
			t.Fatalf("LoadPoolFrom failed: %v", err)
		}

		authURLChan := make(chan string, 1)
		auth.BrowserOpener = func(u string) {
			authURLChan <- u
		}

		errChan := make(chan error, 1)
		go func() {
			// Provide an empty/blocking reader so only HTTP callback satisfies login
			pipeR, _ := io.Pipe()
			defer pipeR.Close()
			errChan <- auth.LoginWithReader(pool, pipeR)
		}()

		var callbackURL string
		select {
		case u := <-authURLChan:
			parsed, err := url.Parse(u)
			if err != nil {
				t.Fatalf("failed to parse auth URL: %v", err)
			}
			redirectURI := parsed.Query().Get("redirect_uri")
			callbackURL = redirectURI + "?code=mock-browser-code-789"
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for BrowserOpener invocation")
		}

		// Make HTTP GET request to local callback server
		resp, err := http.Get(callbackURL)
		if err != nil {
			t.Fatalf("HTTP GET callback failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK from callback, got %d", resp.StatusCode)
		}

		select {
		case err := <-errChan:
			if err != nil {
				t.Fatalf("LoginWithReader returned error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for LoginWithReader completion")
		}

		if len(pool.Accounts) != 1 {
			t.Fatalf("expected 1 account in pool, got %d", len(pool.Accounts))
		}
		if pool.Accounts[0].Email != "browser-user@example.com" {
			t.Errorf("expected email browser-user@example.com, got %s", pool.Accounts[0].Email)
		}
	})

	t.Run("browser_redirect_callback_returns_oauth_error", func(t *testing.T) {
		pool, err := accounts.LoadPoolFrom(t.TempDir())
		if err != nil {
			t.Fatalf("LoadPoolFrom failed: %v", err)
		}

		authURLChan := make(chan string, 1)
		auth.BrowserOpener = func(u string) {
			authURLChan <- u
		}

		errChan := make(chan error, 1)
		go func() {
			pipeR, _ := io.Pipe()
			defer pipeR.Close()
			errChan <- auth.LoginWithReader(pool, pipeR)
		}()

		var callbackURL string
		select {
		case u := <-authURLChan:
			parsed, _ := url.Parse(u)
			callbackURL = parsed.Query().Get("redirect_uri") + "?error=access_denied"
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for BrowserOpener invocation")
		}

		resp, err := http.Get(callbackURL)
		if err != nil {
			t.Fatalf("HTTP GET callback failed: %v", err)
		}
		defer resp.Body.Close()

		select {
		case err := <-errChan:
			if err == nil || !strings.Contains(err.Error(), "access_denied") {
				t.Fatalf("expected OAuth access_denied error, got %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for LoginWithReader error")
		}
	})
}

func TestLoginWithReader_EdgeCases(t *testing.T) {
	t.Run("nil_pool_returns_error", func(t *testing.T) {
		err := auth.LoginWithReader(nil, strings.NewReader("code"))
		if err == nil {
			t.Fatal("expected error with nil pool, got nil")
		}
	})

	t.Run("login_timeout", func(t *testing.T) {
		pool, _ := accounts.LoadPoolFrom(t.TempDir())

		origTimeout := auth.LoginTimeout
		origOpener := auth.BrowserOpener
		auth.LoginTimeout = 50 * time.Millisecond
		auth.BrowserOpener = func(string) {}
		defer func() {
			auth.LoginTimeout = origTimeout
			auth.BrowserOpener = origOpener
		}()

		pipeR, _ := io.Pipe()
		defer pipeR.Close()

		start := time.Now()
		err := auth.LoginWithReader(pool, pipeR)
		duration := time.Since(start)

		if err == nil || !strings.Contains(err.Error(), "hết thời gian chờ") {
			t.Fatalf("expected timeout error, got %v", err)
		}
		if duration > 1*time.Second {
			t.Errorf("login timeout took too long: %v", duration)
		}
	})
}
