package main

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/migadu/sora/helpers"
)

// dovecotMessage is the message the reference fixtures below hold.
const dovecotMessage = "From: a@example.com\r\nTo: b@example.com\r\nSubject: dovecot\r\n\r\nbody body body body body body body body body body\r\n"

// Fixtures made of dovecotMessage by the reference C libraries Dovecot links against:
//   - dovecotLZ4BlockHex: the LZ4 block liblz4 1.10 makes of it, LZ4_compress_default as
//     Dovecot's ostream-lz4.c calls it per chunk; cut from `lz4 -l` output (legacy format:
//     4-byte magic, 4-byte little-endian block length, block).
//   - zstdMessageHex: `zstd -c < message` (libzstd 1.5.7, streaming like Dovecot's
//     ostream-zstd, so the frame carries no content size).
//   - xzMessageHex: `xz -c < message` (liblzma 5.8.3).
const (
	dovecotLZ4BlockHex = "fa0b46726f6d3a2061406578616d706c652e636f6d0d0a546f3a20621300ff0a5375626a6563743a20646f7665636f740d0a0d0a626f647920050016506f64790d0a"
	zstdMessageHex     = "28b52ffd0458fd0100540346726f6d3a2061406578616d706c652e636f6d0d0a546f3a20625375626a6563743a20646f7665636f740d0a0d0a626f6479200d0a020085620e4d9e78ce2d1572"
	xzMessageHex       = "fd377a585a000004e6d6b44604c0446f2101160000000000000000006d42caa5e0006e003c5d00231c89e6f7d7b59d9a6c475ebc49091fa1c8633572936f1805bc056a7d3670bacdacacfdd9cbff586e4e7427d3650b8f32b76f589fe5baeea042ad2000eb7f67f5a270606c0001606f45a276981fb6f37d010000000004595a"
)

// dovecotLZ4File lays out a file the way Dovecot's ostream-lz4.c writes one
// (src/lib-compression/iostream-lz4.h): the magic "Dovecot-LZ4\x0d\x2a\x9b\xc5", the
// largest uncompressed chunk size, then per chunk a 4-byte big-endian length and an LZ4
// block. Dovecot writes 64 KiB chunks.
func dovecotLZ4File(maxChunk uint32, blocks ...[]byte) []byte {
	out := []byte("Dovecot-LZ4\x0d\x2a\x9b\xc5")
	out = binary.BigEndian.AppendUint32(out, maxChunk)
	for _, b := range blocks {
		out = binary.BigEndian.AppendUint32(out, uint32(len(b)))
		out = append(out, b...)
	}
	return out
}

// lz4LiteralBlock encodes b as an LZ4 block of literals only: a single, final sequence
// whose token carries the literal count (15, then 255-byte extensions) and no match. Any
// LZ4 decoder reads it, so a test can lay out chunks of any size.
func lz4LiteralBlock(b []byte) []byte {
	n := len(b)
	if n < 15 {
		return append([]byte{byte(n << 4)}, b...)
	}
	out := []byte{0xf0}
	for n -= 15; n >= 255; n -= 255 {
		out = append(out, 255)
	}
	out = append(out, byte(n))
	return append(out, b...)
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestMaildirDovecotCompression covers the compressions Dovecot's zlib (2.4:
// mail_compress) plugin stores maildir files in beyond gzip and bzip2. They are detected
// by magic bytes, as Dovecot's compression_detect_handler() does, never by file name.
// Dovecot's lz4 is not the LZ4 frame format but its own header and chunk layout, and zstd
// is what current Dovecot setups write: both are read, and the scan (hashFile) and the
// upload (decompressIfNeeded) must see the same message. xz, which only Dovecot 2.2 wrote,
// is refused by name instead of being imported as a garbled message.
func TestMaildirDovecotCompression(t *testing.T) {
	// Three Dovecot-sized chunks: 64 KiB, 64 KiB and the rest.
	large := []byte("From: a@example.com\r\nSubject: large\r\n\r\n" + strings.Repeat("0123456789abcdef\r\n", 9000))
	var chunks [][]byte
	for rest := large; len(rest) > 0; {
		n := min(len(rest), 64<<10)
		chunks = append(chunks, lz4LiteralBlock(rest[:n]))
		rest = rest[n:]
	}
	lz4Block := mustDecodeHex(t, dovecotLZ4BlockHex)
	lz4File := dovecotLZ4File(64<<10, lz4Block)

	tests := []struct {
		name    string
		onDisk  []byte
		message string
		wantErr string // substring; empty when the file must read as message
	}{
		{name: "dovecot lz4", onDisk: lz4File, message: dovecotMessage},
		{name: "dovecot lz4, several chunks", onDisk: dovecotLZ4File(64<<10, chunks...), message: string(large)},
		{
			name: "dovecot lz4, chunk that decompresses to nothing",
			onDisk: dovecotLZ4File(64<<10,
				lz4LiteralBlock([]byte("From: a")), lz4LiteralBlock(nil), lz4LiteralBlock([]byte("@example.com\r\n"))),
			message: "From: a@example.com\r\n",
		},
		{name: "dovecot lz4, empty message", onDisk: dovecotLZ4File(64 << 10), message: ""},
		{name: "zstd", onDisk: mustDecodeHex(t, zstdMessageHex), message: dovecotMessage},

		{name: "xz", onDisk: mustDecodeHex(t, xzMessageHex), wantErr: "xz-compressed maildir file is not supported"},
		{name: "lz4 frame", onDisk: []byte{0x04, 0x22, 0x4d, 0x18, 0x64, 0x40, 0xa7}, wantErr: "lz4-compressed maildir file is not supported"},
		// A raw block of "hello" in a frame that asks for a 256 MiB window: above the
		// 128 MiB libzstd (and so Dovecot) decodes by default, ZSTD_WINDOWLOG_LIMIT_DEFAULT.
		{name: "zstd window above libzstd's default limit", onDisk: []byte("\x28\xb5\x2f\xfd\x00\x90\x29\x00\x00hello"), wantErr: "window size"},

		{name: "dovecot lz4, truncated header", onDisk: lz4File[:17], wantErr: "lz4"},
		{name: "dovecot lz4, zero max chunk size", onDisk: dovecotLZ4File(0, lz4Block), wantErr: "lz4"},
		{name: "dovecot lz4, max chunk size above 1 MiB", onDisk: dovecotLZ4File(1<<20+1, lz4Block), wantErr: "lz4"},
		{name: "dovecot lz4, zero chunk length", onDisk: append(dovecotLZ4File(64<<10), 0, 0, 0, 0), wantErr: "lz4"},
		{name: "dovecot lz4, chunk length above 1 MiB", onDisk: append(dovecotLZ4File(64<<10), 0, 0x10, 0, 1), wantErr: "lz4"},
		{name: "dovecot lz4, truncated chunk", onDisk: lz4File[:len(lz4File)-10], wantErr: "lz4"},
		{name: "dovecot lz4, truncated chunk length", onDisk: append(dovecotLZ4File(64<<10, lz4Block), 0, 0), wantErr: "lz4"},
		{name: "dovecot lz4, chunk larger than the header's max", onDisk: dovecotLZ4File(16, lz4LiteralBlock([]byte("From: a@example.com"))), wantErr: "lz4"},
		{name: "dovecot lz4, corrupted block", onDisk: dovecotLZ4File(64<<10, []byte{0x50, 'a', 'b'}), wantErr: "lz4"},
	}

	dir := t.TempDir()
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, strconv.Itoa(i))
			if err := os.WriteFile(path, tt.onDisk, 0o600); err != nil {
				t.Fatal(err)
			}

			hash, size, hashErr := hashFile(path, 0)
			content, decErr := decompressIfNeeded(tt.onDisk)

			if tt.wantErr != "" {
				if hashErr == nil || !strings.Contains(hashErr.Error(), tt.wantErr) {
					t.Errorf("hashFile error = %v, want one containing %q", hashErr, tt.wantErr)
				}
				if decErr == nil || !strings.Contains(decErr.Error(), tt.wantErr) {
					t.Errorf("decompressIfNeeded error = %v, want one containing %q", decErr, tt.wantErr)
				}
				return
			}

			if hashErr != nil {
				t.Fatalf("hashFile: %v", hashErr)
			}
			if want := helpers.HashContent([]byte(tt.message)); hash != want {
				t.Errorf("hashFile = %s, want helpers.HashContent of the message %s", hash, want)
			}
			if size != int64(len(tt.message)) {
				t.Errorf("hashFile size = %d, want the message size %d", size, len(tt.message))
			}
			if decErr != nil {
				t.Fatalf("decompressIfNeeded: %v", decErr)
			}
			if string(content) != tt.message {
				t.Errorf("decompressIfNeeded = %.60q (%d bytes), want %.60q (%d bytes)", content, len(content), tt.message, len(tt.message))
			}
		})
	}
}

// TestMaildirZstdDecoderReuse: on the first block of a frame a zstd decoder allocates its
// history, the frame's window plus up to 1 MiB: 3 MiB for the 2 MiB window Dovecot's
// default level (ZSTD_CLEVEL_DEFAULT, streamed without a size) writes, however small the
// message. The scan and the upload both read every file, so a decoder per file allocated
// that twice per message: about 6.5 MB of garbage for this 111-byte one. Decoders are
// reused instead.
func TestMaildirZstdDecoderReuse(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector makes sync.Pool drop a share of what is put back")
	}
	onDisk := mustDecodeHex(t, zstdMessageHex)
	path := filepath.Join(t.TempDir(), "m")
	if err := os.WriteFile(path, onDisk, 0o600); err != nil {
		t.Fatal(err)
	}
	scanAndUpload := func() {
		if _, _, err := hashFile(path, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := decompressIfNeeded(onDisk); err != nil {
			t.Fatal(err)
		}
	}
	scanAndUpload() // the first decoder is allocated once

	const files = 20
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range files {
		scanAndUpload()
	}
	runtime.ReadMemStats(&after)
	if perFile := (after.TotalAlloc - before.TotalAlloc) / files; perFile > 1<<20 {
		t.Errorf("scanning and uploading a %d-byte zstd message allocates %d bytes, want under 1 MiB",
			len(dovecotMessage), perFile)
	}
}

// TestMaildirZstdConcurrentFiles reads zstd files of different sizes, and corrupt ones,
// from several goroutines at once, as the scan's and the upload's workers do: a reused
// decoder must never be shared by two files, nor carry a failed file's state into the next.
func TestMaildirZstdConcurrentFiles(t *testing.T) {
	large := []byte("From: a@example.com\r\nSubject: large\r\n\r\n" + strings.Repeat("0123456789abcdef\r\n", 9000))
	enc, err := zstd.NewWriter(nil, zstd.WithWindowSize(1<<21))
	if err != nil {
		t.Fatal(err)
	}
	small := mustDecodeHex(t, zstdMessageHex)
	files := []struct {
		onDisk  []byte
		message []byte // nil when reading must fail
	}{
		{onDisk: small, message: []byte(dovecotMessage)},
		{onDisk: enc.EncodeAll(large, nil), message: large},
		{onDisk: small[:len(small)-6]}, // truncated
		{onDisk: append(append([]byte{}, small[:20]...), 0xff, 0xff, 0xff, 0xff)},
	}
	dir := t.TempDir()
	for i, f := range files {
		if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(i)), f.onDisk, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range 40 {
				i := (g + n) % len(files)
				f := files[i]
				hash, _, hashErr := hashFile(filepath.Join(dir, strconv.Itoa(i)), 0)
				content, decErr := decompressIfNeeded(f.onDisk)
				if f.message == nil {
					if hashErr == nil || decErr == nil {
						t.Errorf("file %d: hashFile error %v, decompressIfNeeded error %v, want both to fail", i, hashErr, decErr)
					}
					continue
				}
				if hashErr != nil || decErr != nil {
					t.Errorf("file %d: hashFile error %v, decompressIfNeeded error %v", i, hashErr, decErr)
					continue
				}
				if want := helpers.HashContent(f.message); hash != want {
					t.Errorf("file %d: hashFile = %s, want %s", i, hash, want)
				}
				if string(content) != string(f.message) {
					t.Errorf("file %d: decompressIfNeeded returned %d bytes that differ from the %d-byte message", i, len(content), len(f.message))
				}
			}
		}()
	}
	wg.Wait()
}
