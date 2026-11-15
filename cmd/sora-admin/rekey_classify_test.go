package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/testutils"
)

func sha256Hex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// TestClassifyStoredBody: a body stored under its SHA-256 digest (an older import) is told
// apart from one under its BLAKE3 digest and from a corrupt one, and the BLAKE3 digest it
// belongs under is returned in every case.
func TestClassifyStoredBody(t *testing.T) {
	body := []byte("From: a@example.com\r\nSubject: hello\r\n\r\nbody\r\n")
	blake3 := helpers.HashContent(body)

	for _, tc := range []struct {
		name    string
		keyHash string
		want    storedBodyKind
	}{
		{"blake3 key", blake3, storedBodyBLAKE3},
		{"sha256 key", sha256Hex(body), storedBodyLegacySHA256},
		{"neither", sha256Hex([]byte("other bytes")), storedBodyMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind, got := classifyStoredBody(body, tc.keyHash)
			if kind != tc.want {
				t.Errorf("kind = %d, want %d", kind, tc.want)
			}
			if got != blake3 {
				t.Errorf("BLAKE3 digest = %s, want %s", got, blake3)
			}
		})
	}
}

// TestVerifyS3ContentLegacySHA256Key: `verify s3 --deep` and `verify hash` must not call an
// intact body stored under its SHA-256 digest corrupt (their advice for corrupt objects is
// to restore from backup or expunge).
func TestVerifyS3ContentLegacySHA256Key(t *testing.T) {
	store, err := testutils.NewFileBasedS3Mock(filepath.Join(t.TempDir(), "s3"))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("From: a@example.com\r\nSubject: hello\r\n\r\nbody\r\n")
	put := func(hash string, content []byte) string {
		key := helpers.NewS3Key("example.com", "user", hash)
		if err := store.Put(key, bytes.NewReader(content), int64(len(content))); err != nil {
			t.Fatal(err)
		}
		return key
	}

	blake3Key := put(helpers.HashContent(body), body)
	if _, err := verifyS3Content(store, blake3Key, helpers.HashContent(body)); err != nil {
		t.Errorf("BLAKE3-keyed body: %v, want nil", err)
	}

	legacyKey := put(sha256Hex(body), body)
	size, err := verifyS3Content(store, legacyKey, sha256Hex(body))
	if !errors.Is(err, errLegacySHA256Key) {
		t.Errorf("SHA-256-keyed body: %v, want errLegacySHA256Key", err)
	}
	if size != len(body) {
		t.Errorf("size = %d, want %d", size, len(body))
	}

	corruptHash := sha256Hex([]byte("the original body"))
	corruptKey := put(corruptHash, []byte("something else"))
	_, err = verifyS3Content(store, corruptKey, corruptHash)
	if err == nil || errors.Is(err, errLegacySHA256Key) || !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("corrupt body: %v, want a corruption error", err)
	}
}

func TestParseRekeyCursor(t *testing.T) {
	got, err := parseRekeyCursor("example.com/first/last/abc123")
	if err != nil {
		t.Fatal(err)
	}
	want := db.ContentObject{S3Domain: "example.com", S3Localpart: "first/last", ContentHash: "abc123"}
	if got != want {
		t.Errorf("parseRekeyCursor = %+v, want %+v", got, want)
	}
	if got.Key() != "example.com/first/last/abc123" {
		t.Errorf("Key() = %q, want the input back", got.Key())
	}
	for _, bad := range []string{"", "abc123", "example.com/abc123", "/user/abc123", "example.com/user/"} {
		if _, err := parseRekeyCursor(bad); err == nil {
			t.Errorf("parseRekeyCursor(%q) succeeded, want an error", bad)
		}
	}
}

// TestOldObjectDelayCoversWriteTimeout: the old object outlives every write transaction that
// may still copy the old hash, however long the configured write_timeout lets one run.
func TestOldObjectDelayCoversWriteTimeout(t *testing.T) {
	for _, tc := range []struct{ writeTimeout, want time.Duration }{
		{10 * time.Second, 30 * time.Second},
		{15 * time.Second, 30 * time.Second},
		{60 * time.Second, 2 * time.Minute},
	} {
		if got := oldObjectDelayFor(tc.writeTimeout); got != tc.want {
			t.Errorf("oldObjectDelayFor(%s) = %s, want %s", tc.writeTimeout, got, tc.want)
		}
	}
}
