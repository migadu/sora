package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/errors"
)

// [auth_cache] path is created with its directory. For a file: URI the directory created
// was filepath.Dir of the URI, a relative path starting with "file:", so a "file:" tree
// appeared in the working directory while the directory the URI names was never created,
// and the cache failed to open in it (#1397).
func TestInitializeServicesCreatesAuthCacheDirectoryOfFileURI(t *testing.T) {
	dir := t.TempDir()
	dbFile := filepath.Join(dir, "missing", "auth_cache.db")
	// A remote_lookup proxy without lookup_local_users needs no database.
	body := `
[auth_cache]
enabled = true
path = ` + strconv.Quote("file:"+dbFile) + `

[[server]]
type = "imap_proxy"
name = "auth-cache-proxy"
addr = "127.0.0.1:0"
remote_addrs = ["127.0.0.1:1"]

[server.remote_lookup]
enabled = true
url = "http://127.0.0.1:1/lookup/$email"
`
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.NewDefaultConfig() // seeded as main seeds it
	if err := config.LoadConfigFromFile(path, &cfg); err != nil {
		t.Fatalf("load config: %v", err)
	}

	wd := t.TempDir()
	t.Chdir(wd)
	ctx, cancel := context.WithCancel(context.Background())
	deps, err := initializeServices(ctx, cfg, errors.NewErrorHandler())
	if err != nil {
		cancel()
		t.Fatalf("initializeServices: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		deps.healthIntegration.Stop()
		if deps.authCacheInstance != nil {
			deps.authCacheInstance.Close()
		}
	})

	if deps.authCacheInstance == nil {
		t.Error("the auth cache did not open")
	}
	if info, err := os.Stat(dbFile); err != nil {
		t.Errorf("auth cache file %s: %v", dbFile, err)
	} else if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("auth cache file %s has mode %o, want 600", dbFile, mode)
	}
	if entries, err := os.ReadDir(wd); err != nil || len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("working directory holds %q (err %v), want nothing", names, err)
	}
}
