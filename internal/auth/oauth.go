package auth

import (
	"agymux/internal/accounts"
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Default Client Scopes for Antigravity & Gemini Code Assist
const DefaultOAuthScopes = "openid email profile https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/cclog https://www.googleapis.com/auth/experimentsandconfigs https://www.googleapis.com/auth/aicode"

// Configurable package variables for testing and customization
var (
	// TokenEndpoint overrides accounts.TokenEndpoint if non-empty (useful for hermetic tests)
	TokenEndpoint string

	// ClientID overrides accounts.DefaultClientID if non-empty
	ClientID string

	// ClientSecret overrides accounts.DefaultClientSecret if non-empty
	ClientSecret string

	// StdinReader is the input reader used by Login for manual terminal entry (defaults to os.Stdin)
	StdinReader io.Reader = os.Stdin

	// BrowserOpener opens the auth URL in the system browser. Can be overridden in tests.
	BrowserOpener func(url string) = openBrowser

	// HTTPClient is used for OAuth token exchange requests
	HTTPClient = &http.Client{Timeout: 15 * time.Second}

	// LoginTimeout is the maximum duration to wait for OAuth callback or manual code entry
	LoginTimeout = 3 * time.Minute
)

func getTokenEndpoint() string {
	if TokenEndpoint != "" {
		return TokenEndpoint
	}
	return accounts.TokenEndpoint
}

func getClientID() string {
	if ClientID != "" {
		return ClientID
	}
	return accounts.DefaultClientID
}

func getClientSecret() string {
	if ClientSecret != "" {
		return ClientSecret
	}
	return accounts.DefaultClientSecret
}

func getHTTPClient() *http.Client {
	if HTTPClient != nil {
		return HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func getLoginTimeout() time.Duration {
	if LoginTimeout > 0 {
		return LoginTimeout
	}
	return 3 * time.Minute
}

type TokenExchangeResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	IdToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
}

type IdTokenClaims struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

// Login initiates the Google OAuth 2.0 flow using StdinReader as input for manual entry.
func Login(pool *accounts.Pool) error {
	return LoginWithReader(pool, StdinReader)
}

// LoginWithReader initiates the Google OAuth 2.0 flow using the provided reader for manual entry.
// It opens an ephemeral HTTP callback listener and simultaneously runs a concurrent prompt
// on the provided reader, allowing pasting of raw authorization code or full callback URL.
func LoginWithReader(pool *accounts.Pool, in io.Reader) error {
	if pool == nil {
		return fmt.Errorf("pool tài khoản không được để nil")
	}
	if in == nil {
		in = os.Stdin
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("không thể mở cổng lắng nghe: %w", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	authURL := fmt.Sprintf(
		"https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&access_type=offline&prompt=consent",
		getClientID(),
		url.QueryEscape(redirectURI),
		url.QueryEscape(DefaultOAuthScopes),
	)

	fmt.Println("\n=======================================================")
	fmt.Println(" 🔑 ĐĂNG NHẬP GOOGLE CHO AGYMUX")
	fmt.Println("=======================================================")
	fmt.Println(" Đang mở trình duyệt để đăng nhập tài khoản Google...")
	fmt.Println(" Nếu trình duyệt không tự mở (hoặc đang dùng SSH/remote), copy link sau:")
	fmt.Printf("\n %s\n\n", authURL)
	fmt.Println(" Sau khi đăng nhập, nếu trình duyệt không tự chuyển về terminal:")
	fmt.Println(" 👉 Dán Authorization Code hoặc toàn bộ Callback URL vào đây:")
	fmt.Print(" Nhập Code hoặc Callback URL > ")

	if BrowserOpener != nil {
		BrowserOpener(authURL)
	}

	type authResult struct {
		code        string
		redirectURI string
	}

	resultChan := make(chan authResult, 1)
	errChan := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/callback" {
				http.NotFound(w, r)
				return
			}

			code := r.URL.Query().Get("code")
			if code == "" {
				errMsg := r.URL.Query().Get("error")
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "Lỗi đăng nhập: %s", errMsg)
				select {
				case errChan <- fmt.Errorf("OAuth error: %s", errMsg):
				default:
				}
				return
			}

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, `<!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding:50px;background:#f5f5f5;">
				<div style="background:white;padding:30px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1);max-width:500px;margin:auto;">
					<h2 style="color:#2e7d32;">✓ Đăng nhập thành công!</h2>
					<p>Tài khoản Google đã được nạp thành công vào agymux.</p>
					<p style="color:#666;">Bạn có thể đóng tab này và quay lại Terminal để tiếp tục.</p>
				</div>
			</body></html>`)

			select {
			case resultChan <- authResult{code: code, redirectURI: redirectURI}:
			default:
			}
		}),
	}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			select {
			case errChan <- err:
			default:
			}
		}
	}()

	// Terminal manual input goroutine
	go func() {
		scanner := bufio.NewScanner(in)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}

			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			code, pastedURI := ExtractCodeAndURI(line)
			if code != "" {
				if pastedURI == "" {
					pastedURI = redirectURI
				}
				select {
				case resultChan <- authResult{code: code, redirectURI: pastedURI}:
				case <-ctx.Done():
				}
				return
			}

			fmt.Println("\n⚠️ Không tìm thấy authorization code hợp lệ trong chuỗi vừa nhập.")
			fmt.Print("👉 Vui lòng dán lại Code hoặc Callback URL > ")
		}
	}()

	var res authResult
	select {
	case res = <-resultChan:
	case err := <-errChan:
		return err
	case <-time.After(getLoginTimeout()):
		return fmt.Errorf("hết thời gian chờ đăng nhập (timeout %v)", getLoginTimeout())
	}

	// Shut down local callback server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)

	fmt.Println("\nĐang đổi Authorization Code lấy Token...")
	tokenResp, err := ExchangeCodeForToken(res.code, res.redirectURI)
	if err != nil {
		return fmt.Errorf("lỗi đổi token: %w", err)
	}

	email := ParseEmailFromIdToken(tokenResp.IdToken)
	if email == "" {
		email = "google-account-" + time.Now().Format("20060102-150405")
	}

	acc := &accounts.Account{
		Email:        email,
		RefreshToken: tokenResp.RefreshToken,
		AccessToken:  tokenResp.AccessToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		AddedAt:      time.Now(),
	}

	if err := pool.AddAccount(acc); err != nil {
		return fmt.Errorf("lỗi lưu tài khoản: %w", err)
	}

	fmt.Printf("\n🎉 THÀNH CÔNG! Đã thêm tài khoản [%s] vào agymux pool!\n\n", email)
	return nil
}

// ExtractCodeAndURI extracts the authorization code and optional redirect URI from input.
// If input is a full URL, it returns the code and the base URL (scheme://host/path) as redirectURI.
// Otherwise, it returns the extracted code and an empty redirectURI.
func ExtractCodeAndURI(input string) (string, string) {
	input = strings.TrimSpace(input)
	input = strings.Trim(input, "\"'")
	if input == "" {
		return "", ""
	}

	// 1. Try parsing full URL with scheme
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		if u, err := url.Parse(input); err == nil {
			code := u.Query().Get("code")
			if code != "" {
				redirect := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
				return code, redirect
			}
			if u.Query().Get("error") != "" {
				return "", ""
			}
		}
	}

	return ExtractCode(input), ""
}

// ExtractCode extracts an authorization code from either a raw code string or a full callback URL.
func ExtractCode(input string) string {
	input = strings.TrimSpace(input)
	input = strings.Trim(input, "\"'")
	if input == "" {
		return ""
	}

	// 1. If it contains a query string (?code=...)
	if idx := strings.Index(input, "?"); idx != -1 {
		queryString := input[idx+1:]
		if values, err := url.ParseQuery(queryString); err == nil {
			if code := values.Get("code"); code != "" {
				return code
			}
			if values.Get("error") != "" {
				return ""
			}
		}
	}

	// 2. If it contains code= without ? (e.g. "code=4/0AeanS...&scope=...")
	if strings.HasPrefix(input, "code=") || strings.Contains(input, "&code=") {
		queryString := input
		if idx := strings.Index(input, "code="); idx != -1 && idx > 0 {
			queryString = input[idx:]
		}
		if values, err := url.ParseQuery(queryString); err == nil {
			if code := values.Get("code"); code != "" {
				return code
			}
		}
	}

	// 3. Try parsing as full URL with scheme
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		if u, err := url.Parse(input); err == nil {
			if code := u.Query().Get("code"); code != "" {
				return code
			}
			if u.Query().Get("error") != "" {
				return ""
			}
		}
	}

	// 4. If it looks like a URL or callback path but has no code param
	if strings.Contains(input, "/callback") || strings.Contains(input, "127.0.0.1") || strings.Contains(input, "localhost") {
		return ""
	}

	// 5. Otherwise, treat as raw authorization code
	return input
}

// ExchangeCodeForToken sends a POST request to the token endpoint to exchange the authorization code.
func ExchangeCodeForToken(code, redirectURI string) (*TokenExchangeResponse, error) {
	data := url.Values{
		"code":          {code},
		"client_id":     {getClientID()},
		"client_secret": {getClientSecret()},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
	}

	req, err := http.NewRequest("POST", getTokenEndpoint(), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("không thể tạo HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := getHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lỗi kết nối tới OAuth server: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("lỗi đọc phản hồi từ OAuth server: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Google OAuth returned status %d: %s", resp.StatusCode, string(body))
	}

	var tr TokenExchangeResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("lỗi giải mã JSON phản hồi OAuth: %w (body: %s)", err, string(body))
	}

	if tr.AccessToken == "" {
		return nil, fmt.Errorf("phản hồi OAuth không chứa access_token")
	}

	return &tr, nil
}

func exchangeCodeForToken(code, redirectURI string) (*TokenExchangeResponse, error) {
	return ExchangeCodeForToken(code, redirectURI)
}

// ParseEmailFromIdToken decodes the payload of a JWT ID token and extracts the email claim.
func ParseEmailFromIdToken(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return ""
	}

	payloadSegment := parts[1]
	payload, err := base64.RawURLEncoding.DecodeString(payloadSegment)
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(payloadSegment)
		if err != nil {
			return ""
		}
	}

	var claims IdTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Email
}

func parseEmailFromIdToken(idToken string) string {
	return ParseEmailFromIdToken(idToken)
}

func openBrowser(url string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default:
		cmd = "xdg-open"
		args = []string{url}
	}

	_ = exec.Command(cmd, args...).Start()
}
