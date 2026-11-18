package main

import (
	"bytes"
	"testing"

	"github.com/migadu/sora/helpers"
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
	stored, changed := helpers.EncodeNULParts(message)
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
