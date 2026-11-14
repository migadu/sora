package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"golang.org/x/crypto/bcrypt"
)

// A config without [uploader] max_attempts gets the server's default, as cmd/sora does.
// With zero, every pending upload would count as parked (attempts >= 0): `backends status`
// and `uploader status` report them all as given up, and `uploader resolve` treats live
// uploads as written off.
func TestLoadAdminConfig_DefaultsUploaderMaxAttempts(t *testing.T) {
	keepBcryptCost(t)
	want := config.NewDefaultConfig().Uploader.MaxAttempts
	if want <= 0 {
		t.Fatalf("test setup: server default max_attempts is %d", want)
	}

	for _, tc := range []struct {
		name, toml string
		want       int
	}{
		{"no uploader section", "[database]\n", want},
		{"uploader without max_attempts", "[uploader]\npath = \"/var/spool/sora\"\n", want},
		{"explicit max_attempts", "[uploader]\nmax_attempts = 7\n", 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.toml), 0o600); err != nil {
				t.Fatal(err)
			}
			var cfg AdminConfig
			if err := loadAdminConfig(path, &cfg); err != nil {
				t.Fatalf("loadAdminConfig: %v", err)
			}
			if cfg.Uploader.MaxAttempts != tc.want {
				t.Fatalf("Uploader.MaxAttempts = %d, want %d", cfg.Uploader.MaxAttempts, tc.want)
			}
		})
	}
}

// keepBcryptCost restores db.BcryptCost when t ends; every test that calls
// loadAdminConfig takes it. loadAdminConfig applies the file's bcrypt_cost (12 when
// unset) process-wide, while the integration build of this package hashes at
// bcrypt.MinCost (integration_tests/common): without the restore every later test
// that creates an account hashes at cost 12, several times slower (more under -race).
func keepBcryptCost(t *testing.T) {
	t.Helper()
	saved := db.BcryptCost
	t.Cleanup(func() { db.BcryptCost = saved })
}

// TestLoadAdminConfig_AppliesBcryptCost (#316): passwords sora-admin hashes (accounts
// create/update, credentials add) use the top-level bcrypt_cost, as the server's do. With
// the package default instead, a backend rehashes the password at the user's next login
// because the cost differs.
func TestLoadAdminConfig_AppliesBcryptCost(t *testing.T) {
	keepBcryptCost(t)
	defaults := config.NewDefaultConfig()

	for _, tc := range []struct {
		name, toml string
		want       int
	}{
		{"bcrypt_cost 10", "bcrypt_cost = 10\n", 10},
		{"bcrypt_cost 11", "bcrypt_cost = 11\n", 11},
		{"unset is the server default", "[database]\n", defaults.GetBcryptCost()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.toml), 0o600); err != nil {
				t.Fatal(err)
			}
			var cfg AdminConfig
			if err := loadAdminConfig(path, &cfg); err != nil {
				t.Fatalf("loadAdminConfig: %v", err)
			}
			hash, err := db.GenerateBcryptHash("correct horse battery staple")
			if err != nil {
				t.Fatalf("GenerateBcryptHash: %v", err)
			}
			cost, err := bcrypt.Cost([]byte(strings.TrimPrefix(hash, "{BLF-CRYPT}")))
			if err != nil {
				t.Fatalf("bcrypt.Cost(%q): %v", hash, err)
			}
			if cost != tc.want {
				t.Fatalf("new password hashed with cost %d, want %d", cost, tc.want)
			}
		})
	}
}
