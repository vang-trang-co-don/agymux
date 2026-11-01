package accounts

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default Client ID and Secret for Google Antigravity / Cloud Code
var (
	DefaultClientID     = getEnvOrXOR("AGYMUX_CLIENT_ID", []byte{107, 106, 109, 107, 106, 106, 108, 106, 108, 106, 111, 99, 107, 119, 46, 55, 50, 41, 41, 51, 52, 104, 50, 104, 107, 54, 57, 40, 63, 104, 105, 111, 44, 46, 53, 54, 53, 48, 50, 110, 61, 110, 106, 105, 63, 42, 116, 59, 42, 42, 41, 116, 61, 53, 53, 61, 54, 63, 47, 41, 63, 40, 57, 53, 52, 46, 63, 52, 46, 116, 57, 53, 55}, 0x5a)
	DefaultClientSecret = getEnvOrXOR("AGYMUX_CLIENT_SECRET", []byte{29, 21, 25, 9, 10, 2, 119, 17, 111, 98, 28, 13, 8, 110, 98, 108, 22, 62, 22, 16, 107, 55, 22, 24, 98, 41, 2, 25, 110, 32, 108, 43, 30, 27, 60}, 0x5a)
)

func getEnvOrXOR(envKey string, raw []byte, k byte) string {
	if val := os.Getenv(envKey); val != "" {
		return val
	}
	res := make([]byte, len(raw))
	for i, b := range raw {
		res[i] = b ^ k
	}
	return string(res)
}

const (
	DefaultTokenEndpoint = "https://oauth2.googleapis.com/token"
	DefaultCooldownTime  = 30 * time.Minute
	ConfigDirEnv         = "AGYMUX_CONFIG_DIR"

	StatusActive   = "Active"
	StatusStandby  = "Standby"
	StatusCooldown = "Cooldown"

	TierFree  = "free"
	TierPro   = "pro"
	TierUltra = "ultra"
)

// TierWeight returns a numeric priority for an account tier.
// Higher values indicate higher priority (e.g. Ultra > Pro > Free).
func TierWeight(tier string) int {
	norm := strings.ToLower(strings.TrimSpace(tier))
	switch {
	case strings.Contains(norm, "ultra"):
		return 30
	case strings.Contains(norm, "pro") || strings.Contains(norm, "paid") || strings.Contains(norm, "premium"):
		return 20
	default:
		return 10
	}
}

// TokenEndpoint is the OAuth2 token endpoint URL (variable for mock testing).
var TokenEndpoint = DefaultTokenEndpoint

type Account struct {
	Email         string    `json:"email"`
	RefreshToken  string    `json:"refresh_token"`
	AccessToken   string    `json:"access_token"`
	ExpiresAt     time.Time `json:"expires_at"`
	CooldownUntil time.Time `json:"cooldown_until"`
	AddedAt       time.Time `json:"added_at"`
	Tier          string    `json:"tier,omitempty"`
}

func (a *Account) Weight() int {
	if a == nil {
		return 0
	}
	return TierWeight(a.Tier)
}

type Pool struct {
	mu            sync.Mutex
	configDir     string
	configPath    string
	tokenEndpoint string
	Accounts      []*Account `json:"accounts"`
	CurrentIdx    int        `json:"current_idx"`
}

func GetConfigDir() string {
	if env := os.Getenv(ConfigDirEnv); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".agymux")
}

func LoadPool() (*Pool, error) {
	return LoadPoolFrom(GetConfigDir())
}

func LoadPoolFrom(configDir string) (*Pool, error) {
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, fmt.Errorf("không thể tạo thư mục %s: %w", configDir, err)
	}

	p := &Pool{
		configDir:  configDir,
		configPath: filepath.Join(configDir, "accounts.json"),
		Accounts:   make([]*Account, 0),
		CurrentIdx: 0,
	}

	data, err := os.ReadFile(p.configPath)
	if os.IsNotExist(err) {
		return p, nil
	} else if err != nil {
		return nil, fmt.Errorf("lỗi đọc %s: %w", p.configPath, err)
	}

	if err := json.Unmarshal(data, p); err != nil {
		return nil, fmt.Errorf("lỗi parse JSON %s: %w", p.configPath, err)
	}

	return p, nil
}

func (p *Pool) SetTokenEndpoint(endpoint string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenEndpoint = endpoint
}

func (p *Pool) getTokenEndpoint() string {
	if p != nil && p.tokenEndpoint != "" {
		return p.tokenEndpoint
	}
	return TokenEndpoint
}

func (p *Pool) ConfigDir() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.configDir
}

func (p *Pool) ConfigPath() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.configPath
}

func (p *Pool) Save() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.saveLocked()
}

func (p *Pool) AddAccount(acc *Account) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if already exists, update if so
	found := false
	for i, existing := range p.Accounts {
		if existing.Email == acc.Email {
			if acc.Tier == "" && existing.Tier != "" {
				acc.Tier = existing.Tier
			}
			p.Accounts[i] = acc
			found = true
			break
		}
	}
	if !found {
		p.Accounts = append(p.Accounts, acc)
	}

	return p.saveLocked()
}

func (p *Pool) SetAccountTier(email string, tier string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, acc := range p.Accounts {
		if acc.Email == email {
			acc.Tier = tier
			return p.saveLocked()
		}
	}
	return fmt.Errorf("không tìm thấy tài khoản với email: %s", email)
}

func (p *Pool) HasAvailableCandidate(excludeEmails map[string]bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	for _, acc := range p.Accounts {
		if excludeEmails != nil && excludeEmails[acc.Email] {
			continue
		}
		if !acc.CooldownUntil.After(now) {
			return true
		}
	}
	return false
}

func (p *Pool) AccountCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.Accounts)
}

func (p *Pool) IsAccountInCooldown(email string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	for _, acc := range p.Accounts {
		if acc.Email == email {
			return acc.CooldownUntil.After(now)
		}
	}
	return false
}

func (p *Pool) RemoveAccount(index int) (*Account, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.removeAccountLocked(index)
}

func (p *Pool) removeAccountLocked(index int) (*Account, error) {
	if index < 0 || index >= len(p.Accounts) {
		return nil, fmt.Errorf("chỉ số tài khoản không hợp lệ (%d)", index+1)
	}

	removed := p.Accounts[index]
	p.Accounts = append(p.Accounts[:index], p.Accounts[index+1:]...)
	if index < p.CurrentIdx {
		p.CurrentIdx--
	} else if p.CurrentIdx >= len(p.Accounts) {
		p.CurrentIdx = 0
	}

	if err := p.saveLocked(); err != nil {
		return removed, err
	}
	return removed, nil
}

func (p *Pool) RemoveByEmail(email string) (*Account, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, acc := range p.Accounts {
		if acc.Email == email {
			return p.removeAccountLocked(i)
		}
	}
	return nil, fmt.Errorf("không tìm thấy tài khoản với email: %s", email)
}

func (p *Pool) List() {
	p.ListTo(os.Stdout)
}

func (p *Pool) ListTo(w io.Writer) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.Accounts) == 0 {
		fmt.Fprintln(w, "Chưa có tài khoản nào trong pool.")
		fmt.Fprintln(w, "👉 Dùng 'agymux login' để thêm tài khoản!")
		return
	}

	fmt.Fprintln(w, "======================================================")
	fmt.Fprintf(w, " Danh sách tài khoản agymux pool (%d tài khoản)\n", len(p.Accounts))
	fmt.Fprintln(w, "======================================================")
	now := time.Now()
	for i, acc := range p.Accounts {
		tag := "[ ]"
		if i == p.CurrentIdx {
			tag = "[★ ACTIVE]"
		}

		var status string
		if acc.CooldownUntil.After(now) {
			remaining := acc.CooldownUntil.Sub(now).Round(time.Minute)
			if remaining < time.Minute {
				remaining = time.Minute
			}
			status = fmt.Sprintf("Cooldown (còn %v)", remaining)
		} else if i == p.CurrentIdx {
			status = StatusActive
		} else {
			status = StatusStandby
		}

		tierTag := ""
		if acc.Tier != "" {
			tierTag = fmt.Sprintf(" [%s]", acc.Tier)
		}

		fmt.Fprintf(w, " %2d. %-10s %-32s [%s]%s\n", i+1, tag, acc.Email, status, tierTag)
	}
	fmt.Fprintln(w, "======================================================")
}

func (p *Pool) GetActiveToken(excludeEmails ...map[string]bool) (string, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var exclude map[string]bool
	if len(excludeEmails) > 0 {
		exclude = excludeEmails[0]
	}
	return p.getActiveTokenLocked(exclude)
}

func (p *Pool) getActiveTokenLocked(exclude map[string]bool) (string, string, error) {
	if len(p.Accounts) == 0 {
		return "", "", fmt.Errorf("không có tài khoản nào trong pool")
	}

	if p.CurrentIdx < 0 || p.CurrentIdx >= len(p.Accounts) {
		p.CurrentIdx = 0
	}

	now := time.Now()

	// 1. Find all accounts not in cooldown and not excluded
	var readyIndices []int
	maxWeight := -1
	for i, acc := range p.Accounts {
		if exclude != nil && exclude[acc.Email] {
			continue
		}
		if !acc.CooldownUntil.After(now) {
			readyIndices = append(readyIndices, i)
			w := acc.Weight()
			if w > maxWeight {
				maxWeight = w
			}
		}
	}

	// 2. If ready accounts exist, prioritize highest tier accounts
	if len(readyIndices) > 0 {
		var bestIndices []int
		for _, idx := range readyIndices {
			if p.Accounts[idx].Weight() == maxWeight {
				bestIndices = append(bestIndices, idx)
			}
		}

		// Keep CurrentIdx if it is among the highest-tier ready accounts
		selectedIdx := -1
		for _, idx := range bestIndices {
			if idx == p.CurrentIdx {
				selectedIdx = idx
				break
			}
		}

		// Otherwise, select the next available one round-robin starting after CurrentIdx
		if selectedIdx == -1 {
			for i := 0; i < len(p.Accounts); i++ {
				cand := (p.CurrentIdx + i) % len(p.Accounts)
				for _, idx := range bestIndices {
					if cand == idx {
						selectedIdx = idx
						break
					}
				}
				if selectedIdx != -1 {
					break
				}
			}
		}

		if selectedIdx == -1 {
			selectedIdx = bestIndices[0]
		}

		origIdx := p.CurrentIdx
		p.CurrentIdx = selectedIdx
		acc := p.Accounts[p.CurrentIdx]
		needsSave := origIdx != p.CurrentIdx
		if acc.AccessToken == "" || acc.ExpiresAt.Before(now.Add(2*time.Minute)) {
			token, err := p.refreshAccessTokenLocked(acc.RefreshToken)
			if err != nil {
				acc.CooldownUntil = now.Add(5 * time.Minute)
				_ = p.saveLocked()
				return p.getActiveTokenLocked(exclude)
			}
			acc.AccessToken = token.AccessToken
			acc.ExpiresAt = now.Add(time.Duration(token.ExpiresIn) * time.Second)
			needsSave = true
		}
		if needsSave {
			_ = p.saveLocked()
		}
		return acc.AccessToken, acc.Email, nil
	}

	// 3. All non-excluded accounts are in cooldown!
	// Cooldown Deadlock Resolution: select the account with the earliest CooldownUntil
	var candPool []int
	for i, acc := range p.Accounts {
		if exclude == nil || !exclude[acc.Email] {
			candPool = append(candPool, i)
		}
	}
	if len(candPool) == 0 {
		for i := range p.Accounts {
			candPool = append(candPool, i)
		}
	}

	minCooldown := p.Accounts[candPool[0]].CooldownUntil
	for _, idx := range candPool {
		acc := p.Accounts[idx]
		if acc.CooldownUntil.Before(minCooldown) {
			minCooldown = acc.CooldownUntil
		}
	}

	var candidates []int
	maxCandWeight := -1
	for _, idx := range candPool {
		acc := p.Accounts[idx]
		// Accounts within 1 second of earliest cooldown
		if acc.CooldownUntil.Sub(minCooldown) <= time.Second {
			candidates = append(candidates, idx)
			if acc.Weight() > maxCandWeight {
				maxCandWeight = acc.Weight()
			}
		}
	}

	bestCandidate := -1
	for _, idx := range candidates {
		if idx == p.CurrentIdx && p.Accounts[idx].Weight() == maxCandWeight {
			bestCandidate = idx
			break
		}
	}

	if bestCandidate == -1 {
		for i := 1; i <= len(p.Accounts); i++ {
			cand := (p.CurrentIdx + i) % len(p.Accounts)
			for _, idx := range candidates {
				if cand == idx && p.Accounts[idx].Weight() == maxCandWeight {
					bestCandidate = idx
					break
				}
			}
			if bestCandidate != -1 {
				break
			}
		}
	}

	if bestCandidate == -1 && len(candidates) > 0 {
		bestCandidate = candidates[0]
	}
	if bestCandidate == -1 {
		bestCandidate = p.CurrentIdx
	}

	origIdx := p.CurrentIdx
	p.CurrentIdx = bestCandidate
	acc := p.Accounts[p.CurrentIdx]
	needsSave := origIdx != p.CurrentIdx
	if acc.AccessToken == "" || acc.ExpiresAt.Before(now.Add(2*time.Minute)) {
		token, err := p.refreshAccessTokenLocked(acc.RefreshToken)
		if err != nil {
			acc.CooldownUntil = now.Add(5 * time.Minute)
			_ = p.saveLocked()
			if exclude == nil {
				exclude = make(map[string]bool)
			}
			exclude[acc.Email] = true
			hasRemaining := false
			for _, idx := range candPool {
				if !exclude[p.Accounts[idx].Email] {
					hasRemaining = true
					break
				}
			}
			if hasRemaining {
				return p.getActiveTokenLocked(exclude)
			}
			if acc.AccessToken != "" && acc.ExpiresAt.After(now) {
				return acc.AccessToken, acc.Email, nil
			}
			return "", "", fmt.Errorf("không thể làm mới token cho tài khoản %s: %w", acc.Email, err)
		}
		acc.AccessToken = token.AccessToken
		acc.ExpiresAt = now.Add(time.Duration(token.ExpiresIn) * time.Second)
		needsSave = true
	}
	if needsSave {
		_ = p.saveLocked()
	}
	return acc.AccessToken, acc.Email, nil
}

func (p *Pool) RotateOnQuota(reason string, cooldownDuration ...time.Duration) (string, string, error) {
	return p.RotateAccountOnQuota("", reason, cooldownDuration...)
}

func (p *Pool) RotateAccountOnQuota(failedEmail string, reason string, cooldownDuration ...time.Duration) (string, string, error) {
	duration := DefaultCooldownTime
	if len(cooldownDuration) > 0 && cooldownDuration[0] > 0 {
		duration = cooldownDuration[0]
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	return p.rotateAccountOnQuotaLocked(failedEmail, reason, duration, len(p.Accounts)+1)
}

// RotateOnAuthFailure rotates away from the active account or refreshes in place when a 401 is received.
func (p *Pool) RotateOnAuthFailure(reason string, cooldownDuration ...time.Duration) (bool, string, string, error) {
	return p.RotateAccountOnAuthFailure("", reason, cooldownDuration...)
}

// RotateAccountOnAuthFailure handles HTTP 401 Unauthorized errors from upstream.
// It first invalidates the cached access token for failedEmail.
// If failedEmail has a valid refresh token, it attempts to refresh it in place:
//   - If refresh succeeds, it returns (true, token, email, nil) indicating the same account was refreshed.
//   - If refresh fails, it places failedEmail on cooldown and rotates to the next available account,
//     returning (false, token, email, nil).
func (p *Pool) RotateAccountOnAuthFailure(failedEmail string, reason string, cooldownDuration ...time.Duration) (bool, string, string, error) {
	duration := DefaultCooldownTime
	if len(cooldownDuration) > 0 && cooldownDuration[0] > 0 {
		duration = cooldownDuration[0]
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	return p.rotateAccountOnAuthFailureLocked(failedEmail, reason, duration)
}

func (p *Pool) rotateAccountOnAuthFailureLocked(failedEmail string, reason string, duration time.Duration) (bool, string, string, error) {
	if len(p.Accounts) == 0 {
		return false, "", "", fmt.Errorf("không có tài khoản nào trong pool")
	}

	if p.CurrentIdx < 0 || p.CurrentIdx >= len(p.Accounts) {
		p.CurrentIdx = 0
	}

	targetIdx := p.CurrentIdx
	if failedEmail != "" {
		found := false
		for i, acc := range p.Accounts {
			if acc.Email == failedEmail {
				targetIdx = i
				found = true
				break
			}
		}
		if !found {
			// Account not found or already removed
			tok, em, err := p.getActiveTokenLocked(nil)
			return false, tok, em, err
		}
	}

	targetAcc := p.Accounts[targetIdx]
	// Invalidate the rejected access token immediately
	targetAcc.AccessToken = ""
	targetAcc.ExpiresAt = time.Time{}

	now := time.Now()

	// 1. Attempt to refresh this account in place if it has a refresh token
	if targetAcc.RefreshToken != "" {
		tokenResp, err := p.refreshAccessTokenLocked(targetAcc.RefreshToken)
		if err == nil && tokenResp.AccessToken != "" {
			targetAcc.AccessToken = tokenResp.AccessToken
			targetAcc.ExpiresAt = now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
			_ = p.saveLocked()
			return true, targetAcc.AccessToken, targetAcc.Email, nil
		}
	}

	// 2. Refresh failed: refresh token is revoked/invalid. Put on cooldown and rotate.
	if len(p.Accounts) == 1 {
		p.Accounts[targetIdx].CooldownUntil = now.Add(duration)
		_ = p.saveLocked()
		return false, "", "", fmt.Errorf("chỉ có 1 tài khoản trong pool và xác thực thất bại: %s", reason)
	}

	// 3. Rotate to next best candidate using existing rotation engine
	tok, em, err := p.rotateAccountOnQuotaLocked(failedEmail, reason, duration, len(p.Accounts)+1)
	return false, tok, em, err
}

func (p *Pool) rotateAccountOnQuotaLocked(failedEmail string, reason string, duration time.Duration, remainingAttempts int) (string, string, error) {
	if remainingAttempts <= 0 {
		return "", "", fmt.Errorf("không thể làm mới token cho bất kỳ tài khoản nào")
	}

	if len(p.Accounts) == 0 {
		return "", "", fmt.Errorf("không có tài khoản nào trong pool")
	}

	if len(p.Accounts) == 1 {
		p.Accounts[0].CooldownUntil = time.Now().Add(duration)
		_ = p.saveLocked()
		return "", "", fmt.Errorf("chỉ có 1 tài khoản trong pool, không thể xoay tua")
	}

	if p.CurrentIdx < 0 || p.CurrentIdx >= len(p.Accounts) {
		p.CurrentIdx = 0
	}

	targetIdx := p.CurrentIdx
	if failedEmail != "" {
		found := false
		for i, acc := range p.Accounts {
			if acc.Email == failedEmail {
				targetIdx = i
				found = true
				break
			}
		}
		if !found {
			// Failed account is no longer in the pool (e.g. logged out while in flight).
			// Do NOT penalize the current active account!
			return p.getActiveTokenLocked(nil)
		}
	}

	now := time.Now()
	p.Accounts[targetIdx].CooldownUntil = now.Add(duration)

	// If failedEmail was specified and p.CurrentIdx has already been rotated away
	// to another healthy account (e.g. by another concurrent request), keep that healthy account!
	if failedEmail != "" && targetIdx != p.CurrentIdx && !p.Accounts[p.CurrentIdx].CooldownUntil.After(now) {
		nextAcc := p.Accounts[p.CurrentIdx]
		if nextAcc.AccessToken == "" || nextAcc.ExpiresAt.Before(now.Add(2*time.Minute)) {
			token, err := p.refreshAccessTokenLocked(nextAcc.RefreshToken)
			if err != nil {
				nextAcc.CooldownUntil = now.Add(5 * time.Minute)
				_ = p.saveLocked()
				return p.rotateAccountOnQuotaLocked(failedEmail, reason, duration, remainingAttempts-1)
			}
			nextAcc.AccessToken = token.AccessToken
			nextAcc.ExpiresAt = now.Add(time.Duration(token.ExpiresIn) * time.Second)
		}
		_ = p.saveLocked()
		return nextAcc.AccessToken, nextAcc.Email, nil
	}

	// Find candidates among other accounts (excluding targetIdx)
	var readyIndices []int
	maxWeight := -1
	for i := 1; i < len(p.Accounts); i++ {
		idx := (targetIdx + i) % len(p.Accounts)
		acc := p.Accounts[idx]
		if !acc.CooldownUntil.After(now) {
			readyIndices = append(readyIndices, idx)
			w := acc.Weight()
			if w > maxWeight {
				maxWeight = w
			}
		}
	}

	var nextIdx int
	if len(readyIndices) > 0 {
		// Select next highest-tier account in round-robin order
		for _, idx := range readyIndices {
			if p.Accounts[idx].Weight() == maxWeight {
				nextIdx = idx
				break
			}
		}
	} else {
		// All other accounts are in cooldown!
		// Select the candidate among idx != targetIdx with the earliest CooldownUntil
		minCooldown := time.Time{}
		for i := 1; i < len(p.Accounts); i++ {
			idx := (targetIdx + i) % len(p.Accounts)
			acc := p.Accounts[idx]
			if minCooldown.IsZero() || acc.CooldownUntil.Before(minCooldown) {
				minCooldown = acc.CooldownUntil
			}
		}

		var candidates []int
		maxCandWeight := -1
		for i := 1; i < len(p.Accounts); i++ {
			idx := (targetIdx + i) % len(p.Accounts)
			acc := p.Accounts[idx]
			if acc.CooldownUntil.Sub(minCooldown) <= time.Second {
				candidates = append(candidates, idx)
				if acc.Weight() > maxCandWeight {
					maxCandWeight = acc.Weight()
				}
			}
		}

		for _, idx := range candidates {
			if p.Accounts[idx].Weight() == maxCandWeight {
				nextIdx = idx
				break
			}
		}
	}

	p.CurrentIdx = nextIdx
	nextAcc := p.Accounts[p.CurrentIdx]

	if nextAcc.AccessToken == "" || nextAcc.ExpiresAt.Before(now.Add(2*time.Minute)) {
		token, err := p.refreshAccessTokenLocked(nextAcc.RefreshToken)
		if err != nil {
			nextAcc.CooldownUntil = now.Add(5 * time.Minute)
			_ = p.saveLocked()
			return p.rotateAccountOnQuotaLocked(failedEmail, reason, duration, remainingAttempts-1)
		}
		nextAcc.AccessToken = token.AccessToken
		nextAcc.ExpiresAt = now.Add(time.Duration(token.ExpiresIn) * time.Second)
	}
	_ = p.saveLocked()

	return nextAcc.AccessToken, nextAcc.Email, nil
}

func (p *Pool) saveLocked() error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmpFile := p.configPath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmpFile, p.configPath)
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func (p *Pool) refreshAccessTokenLocked(refreshToken string) (*TokenResponse, error) {
	return doRefreshToken(p.getTokenEndpoint(), refreshToken)
}

func refreshAccessToken(refreshToken string) (*TokenResponse, error) {
	return doRefreshToken(TokenEndpoint, refreshToken)
}

func doRefreshToken(endpoint, refreshToken string) (*TokenResponse, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh token rỗng")
	}

	data := url.Values{
		"client_id":     {DefaultClientID},
		"client_secret": {DefaultClientSecret},
		"refresh_token": {refreshToken},
		"grant_type":    {"refresh_token"},
	}

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lỗi kết nối tới OAuth server: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OAuth error (%d): %s", resp.StatusCode, string(body))
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

var retryDelayRe = regexp.MustCompile(`(?i)(?:retry\s+(?:after|in)|try\s+again\s+in|wait\s+(?:for\s+)?|backoff\s+(?:for\s+)?)\s*[:=]?\s*(\d+(?:\.\d+)?)\s*(s|sec|second|seconds|m|min|minute|minutes)?`)

// ParseQuotaCooldown analyzes HTTP headers and Google RPC error details/messages
// to determine the cooldown duration and whether the rate limit is transient.
func ParseQuotaCooldown(header http.Header, body []byte) (time.Duration, bool) {
	now := time.Now()

	// 1. Check Retry-After header
	if header != nil {
		if ra := header.Get("Retry-After"); ra != "" {
			ra = strings.TrimSpace(ra)
			if d, err := time.ParseDuration(ra); err == nil && d >= 0 {
				return sanitizeCooldown(d), true
			}
			trimmed := strings.TrimSuffix(ra, "s")
			if f, err := strconv.ParseFloat(trimmed, 64); err == nil && f >= 0 {
				return sanitizeCooldown(time.Duration(f * float64(time.Second))), true
			}
			if t, err := http.ParseTime(ra); err == nil {
				dur := t.Sub(now)
				if dur < 0 {
					dur = 5 * time.Second
				}
				return sanitizeCooldown(dur), dur <= 10*time.Minute
			}
		}

		// 2. Check X-Goog-Retry-After or Retry-After-Seconds
		for _, key := range []string{"X-Goog-Retry-After", "Retry-After-Seconds"} {
			if val := header.Get(key); val != "" {
				val = strings.TrimSpace(val)
				if d, err := time.ParseDuration(val); err == nil && d >= 0 {
					return sanitizeCooldown(d), true
				}
				if f, err := strconv.ParseFloat(val, 64); err == nil && f >= 0 {
					return sanitizeCooldown(time.Duration(f * float64(time.Second))), true
				}
			}
		}
	}

	// 3. Inspect JSON body (Google RPC Status / Error)
	if len(body) > 0 {
		type quotaViolation struct {
			Subject     string `json:"subject"`
			Description string `json:"description"`
		}

		type rpcDetail struct {
			Type            string            `json:"@type"`
			RetryDelay      interface{}       `json:"retryDelay"`
			RetryDelaySnake interface{}       `json:"retry_delay"`
			Reason          string            `json:"reason"`
			Metadata        map[string]string `json:"metadata"`
			Violations      []quotaViolation  `json:"violations"`
		}

		type rpcPayload struct {
			Code    int         `json:"code"`
			Message string      `json:"message"`
			Status  string      `json:"status"`
			Details []rpcDetail `json:"details"`
			Error   *struct {
				Code    int         `json:"code"`
				Message string      `json:"message"`
				Status  string      `json:"status"`
				Details []rpcDetail `json:"details"`
			} `json:"error"`
		}

		var payload rpcPayload
		if err := json.Unmarshal(body, &payload); err == nil {
			var details []rpcDetail
			var message string
			if payload.Error != nil {
				details = payload.Error.Details
				message = payload.Error.Message
			} else {
				details = payload.Details
				message = payload.Message
			}

			// Check details
			for _, d := range details {
				// RetryInfo
				if strings.Contains(d.Type, "RetryInfo") {
					delayVal := d.RetryDelay
					if delayVal == nil {
						delayVal = d.RetryDelaySnake
					}
					if delayVal != nil {
						if dur := parseDurationVal(delayVal); dur > 0 {
							return sanitizeCooldown(dur), true
						}
					}
				}

				// QuotaFailure
				if strings.Contains(d.Type, "QuotaFailure") {
					for _, v := range d.Violations {
						if dur := extractRetryDelayFromMessage(v.Description); dur > 0 {
							return sanitizeCooldown(dur), true
						}
						vUpper := strings.ToUpper(v.Description)
						if strings.Contains(vUpper, "RATE LIMIT") || strings.Contains(vUpper, "PER MINUTE") {
							return 1 * time.Minute, true
						}
					}
				}

				// ErrorInfo
				if strings.Contains(d.Type, "ErrorInfo") {
					if d.Metadata != nil {
						if resetStr := d.Metadata["reset_time"]; resetStr != "" {
							if resetT, err := time.Parse(time.RFC3339, resetStr); err == nil {
								dur := resetT.Sub(now)
								if dur > 0 {
									return sanitizeCooldown(dur), dur <= 10*time.Minute
								}
							} else if sec, err := strconv.ParseInt(resetStr, 10, 64); err == nil && sec > 0 {
								var resetT time.Time
								if sec > 10000000000 {
									resetT = time.UnixMilli(sec)
								} else {
									resetT = time.Unix(sec, 0)
								}
								dur := resetT.Sub(now)
								if dur > 0 {
									return sanitizeCooldown(dur), dur <= 10*time.Minute
								}
							}
						}
						for _, delayKey := range []string{"retry_delay", "quota_reset_delay"} {
							if delayVal := d.Metadata[delayKey]; delayVal != "" {
								if dur := parseDurationVal(delayVal); dur > 0 {
									return sanitizeCooldown(dur), true
								}
							}
						}
					}
					if strings.Contains(strings.ToUpper(d.Reason), "RATE_LIMIT") {
						return 1 * time.Minute, true
					}
				}
			}

			// Check Error message for embedded retry delays
			if dur := extractRetryDelayFromMessage(message); dur > 0 {
				return sanitizeCooldown(dur), true
			}

			msgUpper := strings.ToUpper(message)
			if strings.Contains(msgUpper, "RATE LIMIT") || strings.Contains(msgUpper, "PER MINUTE") {
				return 1 * time.Minute, true
			}
		}

		// Also check raw body string if message wasn't parsed by JSON
		if dur := extractRetryDelayFromMessage(string(body)); dur > 0 {
			return sanitizeCooldown(dur), true
		}
		bodyUpper := strings.ToUpper(string(body))
		if strings.Contains(bodyUpper, "RATE LIMIT") || strings.Contains(bodyUpper, "PER MINUTE") {
			return 1 * time.Minute, true
		}
	}

	// Default fallback: long-term quota exhaustion (30m)
	return DefaultCooldownTime, false
}

func parseDurationVal(v interface{}) time.Duration {
	switch val := v.(type) {
	case string:
		val = strings.TrimSpace(val)
		if d, err := time.ParseDuration(val); err == nil && d > 0 {
			return d
		}
		if strings.HasSuffix(val, "s") {
			val = strings.TrimSuffix(val, "s")
		}
		if f, err := strconv.ParseFloat(val, 64); err == nil && f > 0 {
			return time.Duration(f * float64(time.Second))
		}
	case float64:
		if val > 0 {
			return time.Duration(val * float64(time.Second))
		}
	case map[string]interface{}:
		var secs float64
		if s, ok := val["seconds"]; ok {
			switch sv := s.(type) {
			case float64:
				secs = sv
			case string:
				secs, _ = strconv.ParseFloat(sv, 64)
			}
		}
		var nanos float64
		if n, ok := val["nanos"]; ok {
			switch nv := n.(type) {
			case float64:
				nanos = nv
			case string:
				nanos, _ = strconv.ParseFloat(nv, 64)
			}
		}
		total := secs*float64(time.Second) + nanos
		if total > 0 {
			return time.Duration(total)
		}
	}
	return 0
}

func extractRetryDelayFromMessage(msg string) time.Duration {
	matches := retryDelayRe.FindStringSubmatch(msg)
	if len(matches) >= 2 {
		numStr := matches[1]
		unit := ""
		if len(matches) >= 3 {
			unit = strings.ToLower(matches[2])
		}
		f, err := strconv.ParseFloat(numStr, 64)
		if err == nil && f > 0 {
			if strings.HasPrefix(unit, "m") {
				return time.Duration(f * float64(time.Minute))
			}
			return time.Duration(f * float64(time.Second))
		}
	}
	return 0
}

func sanitizeCooldown(d time.Duration) time.Duration {
	if d < 5*time.Second {
		return 5 * time.Second
	}
	if d > 24*time.Hour {
		return 24 * time.Hour
	}
	return d
}

