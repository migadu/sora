package main

import (
	"bytes"
	"compress/gzip"
	"testing"
)

func TestDecompressIfNeeded(t *testing.T) {
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
			got, err := decompressIfNeeded(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("decompressIfNeeded() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && string(got) != tt.wantContent {
				t.Errorf("decompressIfNeeded() = %v, want %v", string(got), tt.wantContent)
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
	decompressed, err := decompressIfNeeded(compressed)
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
