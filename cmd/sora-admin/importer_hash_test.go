package main

import (
	"encoding/hex"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/migadu/sora/helpers"
)

// A configured limit above the storage ceiling is clamped before adding the
// overflow-detection byte. MaxInt64+1 otherwise makes LimitReader return EOF
// immediately, incorrectly hashing an ordinary message as empty.
func TestImportHashHugeConfiguredLimit(t *testing.T) {
	content := []byte("From: a@example.com\r\nSubject: limit\r\n\r\nbody\r\n")
	path := filepath.Join(t.TempDir(), "message")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	hash, size, err := hashFile(path, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	if hash != helpers.HashContent(content) || size != int64(len(content)) {
		t.Fatalf("hashFile = (%s, %d), want (%s, %d)", hash, size, helpers.HashContent(content), len(content))
	}
}

// bzip2MessageHex is `printf 'From: a@example.com\r\nSubject: bz\r\n\r\nbody\r\n' | bzip2 -9`:
// the standard library has no bzip2 writer.
const (
	bzip2PlainMessage = "From: a@example.com\r\nSubject: bz\r\n\r\nbody\r\n"
	bzip2MessageHex   = "425a683931415926535902881ce50000075f80001240010010410008003e16d670200021aa69fa89a0f48d07ea7aa141a346832034900df73a8e8ab506cd931aa4afee2820a774710ebf8bb9229c284801440e7280"
)

// TestImportHashIsDeliveryHash pins the importer's content hash to the one every other
// path uses (helpers.HashContent, BLAKE3): it names the S3 object and the content_hash
// of the row, so a different digest makes `verify` call every imported body corrupt and
// keeps an imported copy from ever deduplicating with a delivered one. The scan-time hash
// must also be taken over the same decompressed bytes the upload sends, bzip2 included.
func TestImportHashIsDeliveryHash(t *testing.T) {
	plain := []byte("From: a@example.com\r\nSubject: hash\r\n\r\nbody\r\n")
	bz, err := hex.DecodeString(bzip2MessageHex)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		onDisk  []byte
		message []byte
	}{
		{"uncompressed", plain, plain},
		{"gzip", mustGzip(plain), plain},
		{"bzip2", bz, []byte(bzip2PlainMessage)},
	}

	dir := t.TempDir()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name)
			if err := os.WriteFile(path, tt.onDisk, 0o600); err != nil {
				t.Fatal(err)
			}
			want := helpers.HashContent(tt.message)

			got, size, err := hashFile(path, 0)
			if err != nil {
				t.Fatalf("hashFile: %v", err)
			}
			if got != want {
				t.Errorf("hashFile = %s, want helpers.HashContent of the message %s", got, want)
			}
			if size != int64(len(tt.message)) {
				t.Errorf("hashFile size = %d, want the message size %d", size, len(tt.message))
			}

			// The upload hashes what decompressIfNeeded returns; it must be the same
			// message, or every file is reported as changed since the scan.
			content, err := decompressIfNeeded(tt.onDisk)
			if err != nil {
				t.Fatalf("decompressIfNeeded: %v", err)
			}
			if string(content) != string(tt.message) {
				t.Errorf("decompressIfNeeded = %q, want %q", content, tt.message)
			}
		})
	}
}
