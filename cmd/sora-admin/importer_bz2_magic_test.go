package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"testing/iotest"

	"github.com/migadu/sora/helpers"
)

// emptyBzip2Stream is `printf '' | bzip2 -9`: "BZh9" followed by the 6-byte
// end-of-stream magic 0x17, 0x72, 0x45, 0x38, 0x50, 0x90 (sqrt(pi)) and a zero
// 32-bit combined CRC.
var emptyBzip2Stream = []byte("BZh9\x17\x72\x45\x38\x50\x90\x00\x00\x00\x00")

// TestMaildirBzip2MagicDetection verifies that maildirContentReader matches
// Dovecot's is_compressed_bz2() (src/lib-compression/compression.c): bzip2
// detection requires at least 10 bytes — "BZh", block-size digit '1'..'9', and
// either the 6-byte compressed-block header magic "1AY&SY" (0x31, 0x41, 0x59,
// 0x26, 0x53, 0x59) or the 6-byte end-of-stream magic (0x17, 0x72, 0x45, 0x38,
// 0x50, 0x90). Plain messages that merely start with "BZh[1-9]" must not be
// misidentified as bzip2 and rejected as corrupt.
func TestMaildirBzip2MagicDetection(t *testing.T) {
	const bzMessage = "From: a@example.com\r\nSubject: bz\r\n\r\nbody\r\n"

	tests := []struct {
		name           string
		onDisk         []byte
		wantCompressed bool
		wantContent    string
		wantReadErr    bool
	}{
		{
			name:           "plain message starting with BZh1 header",
			onDisk:         []byte("BZh1: Subject\r\n\r\nBody\r\n"),
			wantCompressed: false,
			wantContent:    "BZh1: Subject\r\n\r\nBody\r\n",
		},
		{
			name:           "plain message starting with BZh9 prefix",
			onDisk:         []byte("BZh9-report: quarterly summary\r\n\r\nHello\r\n"),
			wantCompressed: false,
			wantContent:    "BZh9-report: quarterly summary\r\n\r\nHello\r\n",
		},
		{
			name:           "short 4-byte BZh9 input",
			onDisk:         []byte("BZh9"),
			wantCompressed: false,
			wantContent:    "BZh9",
		},
		{
			name:           "9-byte partial bzip2 block prefix",
			onDisk:         []byte("BZh91AY&S"),
			wantCompressed: false,
			wantContent:    "BZh91AY&S",
		},
		{
			name:           "invalid block size digit 0 with block magic",
			onDisk:         []byte("BZh01AY&SYplain"),
			wantCompressed: false,
			wantContent:    "BZh01AY&SYplain",
		},
		{
			name:           "valid non-empty bzip2 stream",
			onDisk:         mustDecodeHex(t, bzip2MessageHex),
			wantCompressed: true,
			wantContent:    bzMessage,
		},
		{
			name:           "valid empty bzip2 stream",
			onDisk:         emptyBzip2Stream,
			wantCompressed: true,
			wantContent:    "",
		},
		{
			name:           "truncated bzip2 block stream fails loudly",
			onDisk:         []byte("BZh11AY&SY\xff\xff"),
			wantCompressed: true,
			wantReadErr:    true,
		},
		{
			name:           "truncated bzip2 empty stream fails loudly",
			onDisk:         []byte("BZh1\x17\x72\x45\x38\x50\x90"),
			wantCompressed: true,
			wantReadErr:    true,
		},
	}

	dir := t.TempDir()
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, oneByte := range []bool{false, true} {
				var src io.Reader = bytes.NewReader(tt.onDisk)
				if oneByte {
					src = iotest.OneByteReader(src)
				}
				rc, compressed, err := maildirContentReader(src)
				if err != nil {
					t.Fatalf("maildirContentReader(oneByte=%v) error = %v", oneByte, err)
				}
				got, readErr := io.ReadAll(rc)
				_ = rc.Close()

				if compressed != tt.wantCompressed {
					t.Errorf("maildirContentReader(oneByte=%v) compressed = %v, want %v", oneByte, compressed, tt.wantCompressed)
				}
				if tt.wantReadErr {
					if readErr == nil {
						t.Errorf("maildirContentReader(oneByte=%v) ReadAll succeeded with %q, want error", oneByte, got)
					}
					continue
				}
				if readErr != nil {
					t.Fatalf("maildirContentReader(oneByte=%v) ReadAll error = %v", oneByte, readErr)
				}
				if string(got) != tt.wantContent {
					t.Errorf("maildirContentReader(oneByte=%v) content = %q, want %q", oneByte, got, tt.wantContent)
				}
			}

			path := filepath.Join(dir, strconv.Itoa(i))
			if err := os.WriteFile(path, tt.onDisk, 0o600); err != nil {
				t.Fatal(err)
			}
			hash, size, hashErr := hashFile(path, 0)
			dec, decErr := decompressIfNeeded(tt.onDisk)
			if tt.wantReadErr {
				if hashErr == nil || decErr == nil {
					t.Errorf("hashFile err=%v, decompressIfNeeded err=%v; want both non-nil", hashErr, decErr)
				}
				return
			}
			if hashErr != nil {
				t.Fatalf("hashFile error = %v", hashErr)
			}
			if decErr != nil {
				t.Fatalf("decompressIfNeeded error = %v", decErr)
			}
			if wantHash := helpers.HashContent([]byte(tt.wantContent)); hash != wantHash {
				t.Errorf("hashFile hash = %s, want %s", hash, wantHash)
			}
			if size != int64(len(tt.wantContent)) {
				t.Errorf("hashFile size = %d, want %d", size, len(tt.wantContent))
			}
			if string(dec) != tt.wantContent {
				t.Errorf("decompressIfNeeded = %q, want %q", dec, tt.wantContent)
			}
		})
	}
}
