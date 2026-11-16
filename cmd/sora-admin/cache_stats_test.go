package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
)

// cacheTree lists every directory under dir, and every file with its size and
// modification time.
func cacheTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	tree := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			tree[path] = "dir"
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		tree[path] = fmt.Sprintf("%s %d %s", info.Mode(), info.Size(), info.ModTime())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

// sora-admin cache stats runs next to the server that owns the cache. It reads the
// cache's index and changes nothing: no purge cycle, no new files, and no database
// connection, which only the server's purge loop needs.
func TestCacheStatsIsReadOnly(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "local cache #1")
	c, err := cache.New(cachePath, 1<<30, 1<<20, time.Hour, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	bodies := map[string]string{strings.Repeat("ab", 32): "first body", strings.Repeat("cd", 32): "second body"}
	for hash, body := range bodies {
		if err := c.Put(hash, []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	before := cacheTree(t, cachePath)

	var cfg AdminConfig
	cfg.LocalCache.Path = cachePath
	cfg.LocalCache.Capacity = "256b" // a purge cycle would evict both objects
	out := captureStdout(t, func() error { return showCacheStats(context.Background(), cfg) })

	if !strings.Contains(out, "Object count:       2\n") || !strings.Contains(out, "Total size:         21 bytes") {
		t.Errorf("stats do not report the two objects:\n%s", out)
	}
	time.Sleep(500 * time.Millisecond) // a purge cycle started in the background would have run
	after := cacheTree(t, cachePath)
	for path, was := range before {
		if now, ok := after[path]; !ok {
			t.Errorf("cache stats removed %s", path)
		} else if now != was {
			t.Errorf("cache stats changed %s", path)
		}
	}
	for path := range after {
		// A reader of a WAL-mode SQLite database shares its -wal and -shm files, and
		// creates them when no other connection holds the database open; a running
		// server always does.
		if strings.HasSuffix(path, "-wal") || strings.HasSuffix(path, "-shm") {
			continue
		}
		if _, ok := before[path]; !ok {
			t.Errorf("cache stats created %s", path)
		}
	}

	c, err = cache.New(cachePath, 1<<30, 1<<20, time.Hour, time.Hour, nil)
	if err != nil {
		t.Fatalf("the server cannot open the cache after cache stats: %v", err)
	}
	defer c.Close()
	if err := c.Put(strings.Repeat("ef", 32), []byte("third body")); err != nil {
		t.Fatalf("the server cannot write the cache after cache stats: %v", err)
	}
}

// A path that holds no cache is reported as such, not created.
func TestCacheStatsDoesNotCreateACache(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "cache")

	var cfg AdminConfig
	cfg.LocalCache.Path = cachePath
	if err := showCacheStats(context.Background(), cfg); err == nil {
		t.Error("cache stats reported on a path that holds no cache")
	}
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Errorf("cache stats created %s (stat: %v)", cachePath, err)
	}
}

// The usual case: the server holds the cache open, and wrote to it last.
func TestCacheStatsNextToARunningServer(t *testing.T) {
	cachePath := t.TempDir()
	server, err := cache.New(cachePath, 1<<30, 1<<20, time.Hour, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.Put(strings.Repeat("ab", 32), []byte("first body")); err != nil {
		t.Fatal(err)
	}
	if err := server.Put(strings.Repeat("cd", 32), []byte("second body")); err != nil {
		t.Fatal(err)
	}

	var cfg AdminConfig
	cfg.LocalCache.Path = cachePath
	out := captureStdout(t, func() error { return showCacheStats(context.Background(), cfg) })
	if !strings.Contains(out, "Object count:       2\n") || !strings.Contains(out, "Total size:         21 bytes") {
		t.Errorf("stats do not report the two objects:\n%s", out)
	}

	if err := server.Put(strings.Repeat("ef", 32), []byte("third body")); err != nil {
		t.Fatalf("the server cannot write after cache stats: %v", err)
	}
}
