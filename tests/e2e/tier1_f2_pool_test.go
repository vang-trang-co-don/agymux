package e2e_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"agymux/internal/accounts"
)

// TestTier1_F2_01_EmptyPoolInitialization verifies an empty pool is initialized properly.
func TestTier1_F2_01_EmptyPoolInitialization(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	pool, err := accounts.LoadPool()
	if err != nil {
		t.Fatalf("LoadPool failed: %v", err)
	}

	if pool == nil {
		t.Fatal("expected non-nil Pool")
	}
	if len(pool.Accounts) != 0 {
		t.Errorf("expected 0 accounts, got %d", len(pool.Accounts))
	}
	if pool.CurrentIdx != 0 {
		t.Errorf("expected current_idx 0, got %d", pool.CurrentIdx)
	}

	// Active token on empty pool should return error
	_, _, err = pool.GetActiveToken()
	if err == nil {
		t.Error("expected error getting active token on empty pool, got nil")
	}
}

// TestTier1_F2_02_AddAccountAndPersistence verifies adding accounts persists atomically.
func TestTier1_F2_02_AddAccountAndPersistence(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	pool, err := accounts.LoadPool()
	if err != nil {
		t.Fatalf("LoadPool failed: %v", err)
	}

	acc1 := &accounts.Account{
		Email:        "alpha@example.com",
		RefreshToken: "ref_alpha",
		AccessToken:  "acc_alpha",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		AddedAt:      time.Now(),
	}

	if err := pool.AddAccount(acc1); err != nil {
		t.Fatalf("AddAccount failed: %v", err)
	}

	configPath := filepath.Join(tempHome, ".agymux", "accounts.json")
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("accounts.json missing: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected accounts.json permissions 0600, got %o", perm)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read accounts.json: %v", err)
	}

	var savedPool accounts.Pool
	if err := json.Unmarshal(data, &savedPool); err != nil {
		t.Fatalf("failed to parse saved accounts.json: %v", err)
	}

	if len(savedPool.Accounts) != 1 {
		t.Fatalf("expected 1 account in file, got %d", len(savedPool.Accounts))
	}
	if savedPool.Accounts[0].Email != "alpha@example.com" {
		t.Errorf("expected email alpha@example.com, got %s", savedPool.Accounts[0].Email)
	}
}

// TestTier1_F2_03_AccountDeduplicationOnAdd verifies adding the same email updates
// existing tokens rather than appending duplicate accounts.
func TestTier1_F2_03_AccountDeduplicationOnAdd(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	pool, err := accounts.LoadPool()
	if err != nil {
		t.Fatalf("LoadPool failed: %v", err)
	}

	acc1 := &accounts.Account{
		Email:        "user@example.com",
		RefreshToken: "old_refresh",
		AccessToken:  "old_access",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		AddedAt:      time.Now(),
	}
	_ = pool.AddAccount(acc1)

	acc1Updated := &accounts.Account{
		Email:        "user@example.com",
		RefreshToken: "new_refresh",
		AccessToken:  "new_access",
		ExpiresAt:    time.Now().Add(2 * time.Hour),
		AddedAt:      time.Now(),
	}
	_ = pool.AddAccount(acc1Updated)

	if len(pool.Accounts) != 1 {
		t.Fatalf("expected 1 account after deduplication, got %d", len(pool.Accounts))
	}
	if pool.Accounts[0].AccessToken != "new_access" {
		t.Errorf("expected updated token 'new_access', got %q", pool.Accounts[0].AccessToken)
	}
	if pool.Accounts[0].RefreshToken != "new_refresh" {
		t.Errorf("expected updated refresh token 'new_refresh', got %q", pool.Accounts[0].RefreshToken)
	}
}

// TestTier1_F2_04_ActiveTokenSelectionPriority verifies that an account not in
// cooldown is selected as active token.
func TestTier1_F2_04_ActiveTokenSelectionPriority(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	pool, err := accounts.LoadPool()
	if err != nil {
		t.Fatalf("LoadPool failed: %v", err)
	}

	now := time.Now()
	acc1 := &accounts.Account{
		Email:         "acc1@example.com",
		AccessToken:   "token_acc1",
		RefreshToken:  "ref_acc1",
		ExpiresAt:     now.Add(1 * time.Hour),
		CooldownUntil: now.Add(20 * time.Minute), // In cooldown
	}
	acc2 := &accounts.Account{
		Email:         "acc2@example.com",
		AccessToken:   "token_acc2",
		RefreshToken:  "ref_acc2",
		ExpiresAt:     now.Add(1 * time.Hour),
		CooldownUntil: time.Time{}, // Ready
	}

	_ = pool.AddAccount(acc1)
	_ = pool.AddAccount(acc2)
	pool.CurrentIdx = 0

	token, email, err := pool.GetActiveToken()
	if err != nil {
		t.Fatalf("GetActiveToken failed: %v", err)
	}

	if email != "acc2@example.com" {
		t.Errorf("expected acc2 to be selected because acc1 is in cooldown, got %s", email)
	}
	if token != "token_acc2" {
		t.Errorf("expected token_acc2, got %s", token)
	}
	if pool.CurrentIdx != 1 {
		t.Errorf("expected CurrentIdx updated to 1, got %d", pool.CurrentIdx)
	}
}

// TestTier1_F2_05_RotateOnQuota30MinCooldown verifies RotateOnQuota puts current
// account in ~30m cooldown and advances CurrentIdx.
func TestTier1_F2_05_RotateOnQuota30MinCooldown(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	pool, err := accounts.LoadPool()
	if err != nil {
		t.Fatalf("LoadPool failed: %v", err)
	}

	now := time.Now()
	acc1 := &accounts.Account{
		Email:       "acc1@example.com",
		AccessToken: "token_acc1",
		ExpiresAt:   now.Add(1 * time.Hour),
	}
	acc2 := &accounts.Account{
		Email:       "acc2@example.com",
		AccessToken: "token_acc2",
		ExpiresAt:   now.Add(1 * time.Hour),
	}
	_ = pool.AddAccount(acc1)
	_ = pool.AddAccount(acc2)
	pool.CurrentIdx = 0

	token, email, err := pool.RotateOnQuota("test 429 quota exhausted")
	if err != nil {
		t.Fatalf("RotateOnQuota failed: %v", err)
	}

	if email != "acc2@example.com" {
		t.Errorf("expected rotated email acc2@example.com, got %s", email)
	}
	if token != "token_acc2" {
		t.Errorf("expected token_acc2, got %s", token)
	}

	// acc1 should now have CooldownUntil set to ~30 mins from now
	remaining := time.Until(acc1.CooldownUntil)
	if remaining < 28*time.Minute || remaining > 31*time.Minute {
		t.Errorf("expected cooldown ~30m, got %v", remaining)
	}
	if pool.CurrentIdx != 1 {
		t.Errorf("expected CurrentIdx 1, got %d", pool.CurrentIdx)
	}
}

// TestTier1_F2_06_RemoveByIndexAndEmail verifies removal operations and index bounds.
func TestTier1_F2_06_RemoveByIndexAndEmail(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	pool, err := accounts.LoadPool()
	if err != nil {
		t.Fatalf("LoadPool failed: %v", err)
	}

	_ = pool.AddAccount(&accounts.Account{Email: "first@example.com"})
	_ = pool.AddAccount(&accounts.Account{Email: "second@example.com"})
	_ = pool.AddAccount(&accounts.Account{Email: "third@example.com"})

	// Remove middle account by email
	removed, err := pool.RemoveByEmail("second@example.com")
	if err != nil {
		t.Fatalf("RemoveByEmail failed: %v", err)
	}
	if removed.Email != "second@example.com" {
		t.Errorf("expected removed email second@example.com, got %s", removed.Email)
	}
	if len(pool.Accounts) != 2 {
		t.Fatalf("expected 2 accounts remaining, got %d", len(pool.Accounts))
	}

	// Remove by index (0)
	removed, err = pool.RemoveAccount(0)
	if err != nil {
		t.Fatalf("RemoveAccount(0) failed: %v", err)
	}
	if removed.Email != "first@example.com" {
		t.Errorf("expected first@example.com removed, got %s", removed.Email)
	}
	if len(pool.Accounts) != 1 {
		t.Fatalf("expected 1 account remaining, got %d", len(pool.Accounts))
	}

	// Invalid index error handling
	_, err = pool.RemoveAccount(99)
	if err == nil {
		t.Error("expected error removing out-of-bounds index, got nil")
	}

	// Invalid email error handling
	_, err = pool.RemoveByEmail("nonexistent@example.com")
	if err == nil {
		t.Error("expected error removing non-existent email, got nil")
	}
}
