package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// readMessageOf writes onDisk to a file and returns readMessage of it.
func readMessageOf(t *testing.T, onDisk []byte) ([]byte, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "message")
	if err := os.WriteFile(path, onDisk, 0o600); err != nil {
		t.Fatal(err)
	}
	return readMessage(path, 0)
}

func TestReadMessageDecompresses(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		wantContent string
		wantErr     bool
	}{
		{
			name:        "uncompressed content",
			input:       []byte("Hello, World!"),
			wantContent: "Hello, World!",
			wantErr:     false,
		},
		{
			name:        "gzip compressed content",
			input:       mustGzip([]byte("Hello, compressed world!")),
			wantContent: "Hello, compressed world!",
			wantErr:     false,
		},
		{
			name:        "empty content",
			input:       []byte{},
			wantContent: "",
			wantErr:     false,
		},
		{
			name:        "invalid gzip header",
			input:       []byte{0x1f, 0x8b, 0xff, 0xff}, // Invalid gzip data
			wantContent: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readMessageOf(t, tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("readMessage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && string(got) != tt.wantContent {
				t.Errorf("readMessage() = %v, want %v", string(got), tt.wantContent)
			}
		})
	}
}

// mustGzip is a helper to gzip compress data for testing
func mustGzip(data []byte) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		panic(err)
	}
	if err := gw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func TestDecompressRealDovecotMessage(t *testing.T) {
	// Simulate a real Dovecot compressed email message
	originalEmail := `From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Wed, 5 Jun 2024 10:00:00 +0000
Message-ID: <test@example.com>

This is the body of the test email.
It has multiple lines.
And some content.
`
	compressed := mustGzip([]byte(originalEmail))

	// Test decompression
	decompressed, err := readMessageOf(t, compressed)
	if err != nil {
		t.Fatalf("Failed to decompress: %v", err)
	}

	if string(decompressed) != originalEmail {
		t.Errorf("Decompressed content doesn't match original.\nGot: %s\nWant: %s", decompressed, originalEmail)
	}

	// Verify the compressed data starts with gzip magic number
	if len(compressed) < 2 || compressed[0] != 0x1f || compressed[1] != 0x8b {
		t.Errorf("Compressed data doesn't have gzip magic number")
	}
}

// The batch holds what readMessage returns until the insert, so the buffer it reads into
// must not keep much more than the message. A decompressed size is known only once read,
// and a buffer that grows by doubling keeps up to twice the message. A plain file is
// allocated at its size, and one above the limit is read to one byte past it, which must
// not grow that buffer a second time (#834).
func TestReadMessageAllocatesAboutTheMessage(t *testing.T) {
	t.Run("compressed message", func(t *testing.T) {
		message := append([]byte("From: a@example.com\r\nSubject: big\r\n\r\n"),
			bytes.Repeat([]byte("0123456789abcdefghijklmnopqrstu\r\n"), (2<<20+1<<10)/33)...)
		got, err := readMessageOf(t, mustGzip(message))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, message) {
			t.Fatalf("readMessage returned %d bytes that differ from the %d-byte message", len(got), len(message))
		}
		if spare := cap(got) - len(got); spare > len(got)/2 {
			t.Errorf("readMessage holds a %d-byte message in %d bytes", len(got), cap(got))
		}
	})

	t.Run("plain file above the limit", func(t *testing.T) {
		// limit+bytes.MinRead is a whole number of pages: a buffer of that size has
		// bytes.MinRead-1 bytes left after the byte past the limit, and grows to read
		// the end of the limited reader.
		const limit = 4<<20 - bytes.MinRead
		path := filepath.Join(t.TempDir(), "message")
		if err := os.WriteFile(path, []byte("From: a@example.com\r\n\r\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(path, 16<<20); err != nil {
			t.Fatal(err)
		}

		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, err := readMessage(path, limit)
		runtime.ReadMemStats(&after)

		if !errors.Is(err, errMessageTooLarge) {
			t.Fatalf("readMessage error = %v, want errMessageTooLarge", err)
		}
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > limit+limit/2 {
			t.Errorf("refusing a file above the %d-byte limit allocated %d bytes", limit, alloc)
		}
	})
}
