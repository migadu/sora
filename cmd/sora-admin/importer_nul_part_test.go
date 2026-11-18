package main

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/server/delivery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestImportNULPartStoredEncoded: a maildir message whose binary part holds a
// NUL is imported as APPEND and delivery store it, with that part base64
// encoded (helpers.EncodeNULParts, #2051), so FETCH BODY never sends the NUL in
// an ordinary literal (RFC 9051 §4.3). The scan's hash must be that of the
// stored bytes, or the file is "changed since the scan" on every run and never
// deduplicates with a delivered copy.
func TestImportNULPartStoredEncoded(t *testing.T) {
	message := []byte("From: user@example.org\r\nMime-Version: 1.0\r\n" +
		"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n" +
		"\x00-\xe4\n\r\n\n")
	stored, changed, _ := helpers.EncodeNULParts(message, nil)
	require.True(t, changed, "EncodeNULParts left the fixture unchanged")

	for _, tt := range []struct {
		name   string
		onDisk []byte
	}{
		{"uncompressed", message},
		{"gzip", mustGzip(message)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			maildirPath, _ := newSingleMessageMaildir(t, tt.onDisk)
			importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
			require.NoError(t, importer.scanMaildir())
			var msg msgInfo
			require.NoError(t, importer.sqliteDB.QueryRow(`SELECT path, filename, hash, size, mailbox FROM messages`).
				Scan(&msg.path, &msg.filename, &msg.hash, &msg.size, &msg.mailbox))

			uploaded := importer.readBatch([]msgInfo{msg})
			require.Len(t, uploaded, 1, "failures: %v", importer.failedPaths)
			content := uploaded[0].content
			if bytes.IndexByte(content, 0) >= 0 {
				t.Fatalf("the import stores the NUL-bearing part as it is: %q", content)
			}
			assert.Equal(t, string(stored), string(content))
			assert.Equal(t, helpers.HashContent(stored), msg.hash, "scan hash is not the stored message's")
			assert.Equal(t, msg.hash, uploaded[0].msg.hash, "upload saw the file as changed since the scan")
		})
	}
}

// TestImportNULPartStoredSizeBound: the size limits stay on the message as
// read, but the re-encoded message must still be storable (messages.size is an
// INTEGER). The scan and the upload both refuse a file whose stored form is
// over that bound, before metadata extraction or upload, and nothing of it is
// cached or uploaded. The bound is lowered to just below the stored size here;
// the real one (consts.MaxStoredMessageSize) needs a file of about 1.5 GiB.
func TestImportNULPartStoredSizeBound(t *testing.T) {
	message := []byte("From: user@example.org\r\nMime-Version: 1.0\r\n" +
		"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n" +
		"\x00-\xe4\n\r\n\n")
	stored, changed, _ := helpers.EncodeNULParts(message, nil)
	require.True(t, changed, "EncodeNULParts left the fixture unchanged")
	require.Greater(t, len(stored), len(message), "fixture must grow when re-encoded")
	lowerBound := func(t *testing.T) {
		saved := checkStoredImportSize
		checkStoredImportSize = func(size int) error {
			if size >= len(stored) {
				return fmt.Errorf("%w: %d bytes", delivery.ErrMessageTooLarge, size)
			}
			return nil
		}
		t.Cleanup(func() { checkStoredImportSize = saved })
	}
	newImporter := func(t *testing.T) *Importer {
		maildirPath, _ := newSingleMessageMaildir(t, message)
		// The raw-input limit admits the file exactly.
		return newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{MaxMessageSize: int64(len(message))})
	}
	cached := func(t *testing.T, importer *Importer) int {
		var n int
		require.NoError(t, importer.sqliteDB.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n))
		return n
	}

	t.Run("scan", func(t *testing.T) {
		importer := newImporter(t)
		lowerBound(t)
		require.NoError(t, importer.scanMaildir())
		assert.Zero(t, cached(t, importer), "a message too large to store was cached for upload")
		require.Len(t, importer.failedPaths, 1)
		assert.Contains(t, importer.failedPaths[0].reason, "too large")
	})

	t.Run("upload", func(t *testing.T) {
		// Scanned while the message was storable, as an earlier run would have.
		importer := newImporter(t)
		require.NoError(t, importer.scanMaildir())
		require.Equal(t, 1, cached(t, importer))
		var msg msgInfo
		require.NoError(t, importer.sqliteDB.QueryRow(`SELECT path, filename, hash, size, mailbox FROM messages`).
			Scan(&msg.path, &msg.filename, &msg.hash, &msg.size, &msg.mailbox))

		lowerBound(t)
		uploaded := importer.readBatch([]msgInfo{msg})
		assert.Empty(t, uploaded, "a message too large to store went on to upload")
		require.Len(t, importer.failedPaths, 1)
		assert.Contains(t, importer.failedPaths[0].reason, "too large")
	})
}
