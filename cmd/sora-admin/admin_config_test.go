package main

import (
	"os"
	"path/filepath"
	"reflect"
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

// sora-admin acts on the server's spool, cache and database, so a setting the config file
// leaves out must resolve to the value the server runs with, not to the zero value. With
// [uploader] path unset, `uploader resolve` looked for staged bodies relative to its working
// directory, found none, and deleted the messages of parked uploads whose bodies were intact
// in the server's spool; with [local_cache] path unset the cache commands failed.
func TestLoadAdminConfigUsesServerDefaults(t *testing.T) {
	defaults := config.NewDefaultConfig()

	for _, tc := range []struct {
		name, toml          string
		uploads, localCache string
	}{
		{"no uploader or local_cache section", "[database]\n", config.DefaultUploaderPath, config.DefaultLocalCachePath},
		{"sections without a path", "[uploader]\nmax_attempts = 7\n\n[local_cache]\ncapacity = \"2gb\"\n", config.DefaultUploaderPath, config.DefaultLocalCachePath},
		{"explicit paths", "[uploader]\npath = \"/srv/sora/uploads\"\n\n[local_cache]\npath = \"/srv/sora/cache\"\n", "/srv/sora/uploads", "/srv/sora/cache"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadAdminConfigFromString(t, tc.toml)
			if cfg.Uploader.Path != tc.uploads {
				t.Errorf("[uploader] path = %q, want %q", cfg.Uploader.Path, tc.uploads)
			}
			if cfg.LocalCache.Path != tc.localCache {
				t.Errorf("[local_cache] path = %q, want %q", cfg.LocalCache.Path, tc.localCache)
			}
		})
	}

	// A [database.write] table takes the server's defaults for the keys it leaves out, so
	// sora-admin connects to the database the server uses.
	t.Run("database keys the table leaves out", func(t *testing.T) {
		cfg := loadAdminConfigFromString(t, "[database.write]\nhosts = [\"db1.example.com\"]\n")
		want := *defaults.Database.Write
		want.Hosts = []string{"db1.example.com"}
		if cfg.Database.Write == nil {
			t.Fatal("[database.write] dropped although the file defines it")
		}
		if got := *cfg.Database.Write; !reflect.DeepEqual(got, want) {
			t.Errorf("[database.write] = %+v, want the server's %+v", got, want)
		}
	})

	// The server runs without an endpoint the file does not define (a proxy has no
	// database); sora-admin must not connect to the built-in localhost one instead.
	t.Run("database endpoints the file does not define", func(t *testing.T) {
		cfg := loadAdminConfigFromString(t, "[database]\nquery_timeout = \"10s\"\n")
		if cfg.Database.Write != nil || cfg.Database.Read != nil {
			t.Errorf("[database] endpoints = write %+v, read %+v; want none, as the server", cfg.Database.Write, cfg.Database.Read)
		}
	})
}

// An explicit max_attempts the server refuses to start with is refused here too. It used to
// read as the default, and resolving with 0 would count every pending upload as parked.
func TestLoadAdminConfigRefusesNonPositiveMaxAttempts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[uploader]\nmax_attempts = 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var cfg AdminConfig
	err := loadAdminConfig(path, &cfg)
	if err == nil || !strings.Contains(err.Error(), "max_attempts") {
		t.Fatalf("loadAdminConfig = %v, want the [uploader] max_attempts error the server starts with", err)
	}
}
