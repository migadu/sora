package main

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"
)

// newSingleMessageMaildir returns a maildir holding onDisk as its one message, and that
// message's file name.
func newSingleMessageMaildir(t *testing.T, onDisk []byte) (maildirPath, name string) {
	t.Helper()
	maildirPath = filepath.Join(t.TempDir(), "Maildir")
	for _, dir := range []string{"cur", "new", "tmp"} {
		require.NoError(t, os.MkdirAll(filepath.Join(maildirPath, dir), 0755))
	}
	name = "1700000001.M1P1.host:2,S"
	require.NoError(t, os.WriteFile(filepath.Join(maildirPath, "cur", name), onDisk, 0644))
	return maildirPath, name
}

// gzipOfSize returns a gzip file whose message is header followed by zeros, size bytes
// in all: a few hundred KB on disk however large the message.
func gzipOfSize(t *testing.T, header string, size int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	require.NoError(t, err)
	_, err = gw.Write([]byte(header))
	require.NoError(t, err)
	zeros := make([]byte, 1<<20)
	for left := size - int64(len(header)); left > 0; {
		n := min(left, int64(len(zeros)))
		_, err = gw.Write(zeros[:n])
		require.NoError(t, err)
		left -= n
	}
	require.NoError(t, gw.Close())
	return buf.Bytes()
}

// TestScanStopsAtTheImportSizeBound: a compressed maildir file of a few hundred bytes can
// decompress to gigabytes (bzip2 streams also concatenate), and Dovecot treats a message
// its owner APPENDed that starts with a compression magic as compressed. The scan must
// stop reading a message at the bound the import refuses it at, the import message limit
// or the upload's 256 MiB decompression bound (decompressIfNeeded), whichever is lower,
// and fail it as too large, instead of decompressing and hashing all of it first.
func TestScanStopsAtTheImportSizeBound(t *testing.T) {
	const header = "From: a@example.com\r\nSubject: bomb\r\n\r\n"
	const uploadBound = 256 << 20 // decompressIfNeeded's bound

	scan := func(t *testing.T, onDisk []byte, maxSize int64) (pending int, reasons []string) {
		t.Helper()
		maildirPath, _ := newSingleMessageMaildir(t, onDisk)
		importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{MaxMessageSize: maxSize})
		require.NoError(t, importer.scanMaildir())
		require.NoError(t, importer.sqliteDB.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&pending))
		for _, f := range importer.failedPaths {
			reasons = append(reasons, f.reason)
		}
		return pending, reasons
	}
	wantTooLarge := func(t *testing.T, pending int, reasons []string) {
		t.Helper()
		if pending != 0 {
			t.Errorf("the scan recorded the message for import; want it refused as too large")
		}
		if len(reasons) != 1 || !strings.Contains(reasons[0], "message too large") {
			t.Errorf("scan failures = %q, want one that says \"message too large\"", reasons)
		}
	}

	t.Run("stops at the message limit", func(t *testing.T) {
		const limit = 64 << 10
		// The gzip stream breaks right after the message: a scan that reads past the
		// limit reaches the break and fails on it, one that stops there never sees it.
		onDisk := append(gzipOfSize(t, header, 2*limit), "not a gzip member"...)
		pending, reasons := scan(t, onDisk, limit)
		wantTooLarge(t, pending, reasons)
	})

	t.Run("a message of exactly the limit is taken", func(t *testing.T) {
		const limit = 64 << 10
		pending, reasons := scan(t, gzipOfSize(t, header, limit), limit)
		if pending != 1 || len(reasons) != 0 {
			t.Errorf("pending = %d, failures = %q; want the message recorded", pending, reasons)
		}
	})

	bomb := gzipOfSize(t, header, uploadBound+1)
	t.Run("upload bound without a message limit", func(t *testing.T) {
		pending, reasons := scan(t, bomb, 0)
		wantTooLarge(t, pending, reasons)
	})
	t.Run("upload bound under a higher message limit", func(t *testing.T) {
		pending, reasons := scan(t, bomb, 1<<30)
		wantTooLarge(t, pending, reasons)
	})
}

// TestDryRunShowsTheSubjectOfACompressedMessage: the dry run previews each message's
// Subject. For a file Dovecot stored compressed it must read the message the import
// reads (maildirContentReader), not the compressed bytes on disk.
func TestDryRunShowsTheSubjectOfACompressedMessage(t *testing.T) {
	message := func(subject string) []byte {
		return []byte("From: a@example.com\r\nTo: b@example.com\r\nSubject: " + subject + "\r\n\r\nbody\r\n")
	}
	zenc, err := zstd.NewWriter(nil)
	require.NoError(t, err)
	defer zenc.Close()

	tests := []struct {
		name    string
		onDisk  []byte
		subject string
	}{
		{"plain", message("plain one"), "plain one"},
		{"gzip", mustGzip(message("gzip one")), "gzip one"},
		{"bzip2", mustDecodeHex(t, bzip2MessageHex), "bz"},
		{"dovecot lz4", dovecotLZ4File(64<<10, lz4LiteralBlock(message("lz4 one"))), "lz4 one"},
		{"zstd", zenc.EncodeAll(message("zstd one"), nil), "zstd one"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maildirPath, name := newSingleMessageMaildir(t, tt.onDisk)
			importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{DryRun: true})
			out := captureStdout(t, importer.Run)

			want := "IMPORT " + name + "\n      Subject: " + tt.subject + "\n"
			if !strings.Contains(out, want) {
				t.Errorf("dry run output does not contain %q:\n%s", want, out)
			}
		})
	}
}
