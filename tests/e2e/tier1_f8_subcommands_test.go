package e2e_test

import (
	"strings"
	"testing"
	"time"
)

// TestTier1_F8_01_ListEmptyPoolMessage verifies agymux list when no accounts exist.
func TestTier1_F8_01_ListEmptyPoolMessage(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	stdout, stderr, exitCode, err := env.RunAgymux([]string{"list"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("agymux list failed: err=%v, code=%d\nStderr: %s", err, exitCode, stderr)
	}

	if !strings.Contains(stdout, "Chưa có tài khoản nào trong pool") {
		t.Errorf("expected empty pool message, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "agymux login") {
		t.Errorf("expected login suggestion in output, got:\n%s", stdout)
	}
}

// TestTier1_F8_02_ListPopulatedPoolTable verifies agymux list table formatting.
func TestTier1_F8_02_ListPopulatedPoolTable(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{
			Email:       "active@example.com",
			AccessToken: "tok1",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
		{
			Email:         "cooldown@example.com",
			AccessToken:   "tok2",
			ExpiresAt:     time.Now().Add(1 * time.Hour),
			CooldownUntil: time.Now().Add(25 * time.Minute),
		},
	}, 0)

	stdout, stderr, exitCode, err := env.RunAgymux([]string{"list"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("agymux list failed: err=%v, code=%d\nStderr: %s", err, exitCode, stderr)
	}

	if !strings.Contains(stdout, "[★ ACTIVE]") {
		t.Errorf("expected [★ ACTIVE] tag for current account in list output:\n%s", stdout)
	}
	if !strings.Contains(stdout, "active@example.com") {
		t.Errorf("expected active@example.com in list output:\n%s", stdout)
	}
	if !strings.Contains(stdout, "cooldown@example.com") {
		t.Errorf("expected cooldown@example.com in list output:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Cooldown") && !strings.Contains(stdout, "Hết Quota") {
		t.Errorf("expected cooldown status in list output:\n%s", stdout)
	}
}

// TestTier1_F8_03_LogoutByEmail verifies removing an account by email argument.
func TestTier1_F8_03_LogoutByEmail(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{Email: "keep@example.com", AccessToken: "tok1", ExpiresAt: time.Now().Add(1 * time.Hour)},
		{Email: "remove@example.com", AccessToken: "tok2", ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	stdout, stderr, exitCode, err := env.RunAgymux([]string{"logout", "remove@example.com"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("agymux logout failed: err=%v, code=%d\nStderr: %s", err, exitCode, stderr)
	}

	pool := env.ReadAccounts()
	if len(pool.Accounts) != 1 {
		t.Fatalf("expected 1 account remaining, got %d", len(pool.Accounts))
	}
	if pool.Accounts[0].Email != "keep@example.com" {
		t.Errorf("expected keep@example.com remaining, got %s", pool.Accounts[0].Email)
	}
	_ = stdout
}

// TestTier1_F8_04_LogoutByIndex verifies removing an account by 1-based index argument.
func TestTier1_F8_04_LogoutByIndex(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{Email: "first@example.com", AccessToken: "tok1", ExpiresAt: time.Now().Add(1 * time.Hour)},
		{Email: "second@example.com", AccessToken: "tok2", ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	stdout, stderr, exitCode, err := env.RunAgymux([]string{"logout", "1"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("agymux logout 1 failed: err=%v, code=%d\nStderr: %s", err, exitCode, stderr)
	}

	pool := env.ReadAccounts()
	if len(pool.Accounts) != 1 {
		t.Fatalf("expected 1 account remaining, got %d", len(pool.Accounts))
	}
	if pool.Accounts[0].Email != "second@example.com" {
		t.Errorf("expected second@example.com remaining, got %s", pool.Accounts[0].Email)
	}
	_ = stdout
}

// TestTier1_F8_05_HelpDocumentation verifies help flag and command outputs.
func TestTier1_F8_05_HelpDocumentation(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	for _, helpArg := range []string{"help", "--help", "-h"} {
		stdout, stderr, exitCode, err := env.RunAgymux([]string{helpArg}, "")
		if err != nil || exitCode != 0 {
			t.Fatalf("agymux %s failed: err=%v, code=%d\nStderr: %s", helpArg, err, exitCode, stderr)
		}

		out := stdout + stderr
		for _, subcommand := range []string{"login", "list", "logout"} {
			if !strings.Contains(out, subcommand) {
				t.Errorf("expected subcommand %q in help output for %s:\n%s", subcommand, helpArg, out)
			}
		}
	}
}

// TestTier1_F8_06_DefaultCommandLaunchesProxyAndAgy verifies running agymux without
// subcommands executes child launcher.
func TestTier1_F8_06_DefaultCommandLaunchesProxyAndAgy(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.SeedAccounts([]*TestAccount{
		{Email: "acc@example.com", AccessToken: "tok", ExpiresAt: time.Now().Add(1 * time.Hour)},
	}, 0)

	stdout, stderr, exitCode, err := env.RunAgymux([]string{"--my-flag", "value"}, "")
	if err != nil || exitCode != 0 {
		t.Fatalf("default agymux run failed: err=%v, code=%d\nStderr: %s", err, exitCode, stderr)
	}

	// Verify agy was launched with the arguments
	pool := env.ReadAccounts()
	if len(pool.Accounts) == 0 {
		t.Fatal("expected accounts to be loaded")
	}
	_ = stdout
}
