package imap

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/server/uploader"
)

// A training worker reads a moved body where FETCH finds it on this node, the body
// cache and then the uploader's staging file, before asking S3, and skips a local
// copy whose size disagrees with the message.
func TestOpenTrainingBodyReadsWholeLocalCopiesFirst(t *testing.T) {
	const body = "Subject: Buy now\r\n\r\nCheap.\r\n"
	const accountID = 7
	hash := strings.Repeat("ab", 32)

	// No S3: a read that reaches it panics and fails the test.
	newServer := func(t *testing.T) *IMAPServer {
		t.Helper()
		c, err := cache.New(t.TempDir(), 1<<20, 1<<20, time.Hour, time.Hour, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		up, err := uploader.NewWithS3Interface(t.TempDir(), 1, 1, 1, time.Second, 0, "test", nil, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return &IMAPServer{cache: c, uploader: up}
	}
	put := func(t *testing.T, path, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	read := func(t *testing.T, srv *IMAPServer) string {
		t.Helper()
		r, err := srv.openTrainingBody(context.Background(), hash, accountID, "example.com/user/"+hash, len(body))
		if err != nil {
			t.Fatalf("openTrainingBody: %v", err)
		}
		defer r.Close()
		data, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	t.Run("from the body cache", func(t *testing.T) {
		srv := newServer(t)
		put(t, srv.cache.GetPathForContentHash(hash), body)
		if got := read(t, srv); got != body {
			t.Errorf("read %q, want %q", got, body)
		}
	})

	t.Run("from the staging file of an upload still pending", func(t *testing.T) {
		srv := newServer(t)
		put(t, srv.uploader.FilePath(hash, accountID), body)
		if got := read(t, srv); got != body {
			t.Errorf("read %q, want %q", got, body)
		}
	})

	t.Run("a truncated cache file is skipped", func(t *testing.T) {
		srv := newServer(t)
		put(t, srv.cache.GetPathForContentHash(hash), body[:5])
		put(t, srv.uploader.FilePath(hash, accountID), body)
		if got := read(t, srv); got != body {
			t.Errorf("read %q, want %q", got, body)
		}
	})
}
