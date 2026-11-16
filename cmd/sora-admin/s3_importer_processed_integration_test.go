//go:build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
)

// TestS3Importer_MarksImportedObjectsProcessed imports more objects than the feeder's
// channel holds, so the feeder is still reading keys from the work database while the
// workers mark the first objects imported. Every object must end up marked processed
// and successful there; the updates used to fail with SQLITE_BUSY against the feeder's
// open read, and the run only logged a warning for each.
func TestS3Importer_MarksImportedObjectsProcessed(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()

	const email = "s3import-processed@example.com"
	createSimpleTestAccount(t, rdb, email, "testpassword123")
	_, s3storage := common.NewFakeS3Storage(t)

	si, err := NewS3Importer(context.Background(), rdb, s3storage, S3ImporterOptions{Email: email, Workers: 5, CleanupDB: true, InstanceID: "test-instance"})
	if err != nil {
		t.Fatal(err)
	}
	defer si.Close()

	const n = 300
	for i := 0; i < n; i++ {
		body := []byte(fmt.Sprintf("From: sender@example.org\r\n"+
			"To: %s\r\n"+
			"Subject: message %d\r\n"+
			"Date: Mon, 02 Nov 2026 10:00:00 +0000\r\n"+
			"Message-ID: <processed-%d@example.org>\r\n"+
			"\r\n"+
			"Message %d.\r\n", email, i, i, i))
		hash := helpers.HashContent(body)
		key := helpers.NewS3Key("example.com", "s3import-processed", hash)
		if err := s3storage.Put(key, bytes.NewReader(body), int64(len(body))); err != nil {
			t.Fatalf("put: %v", err)
		}
		if _, err := si.db.Exec(`INSERT INTO s3_objects (key, size, last_modified, etag, domain, local_part, content_hash)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, key, len(body), "2026-11-02T10:00:00Z", "etag",
			"example.com", "s3import-processed", hash); err != nil {
			t.Fatal(err)
		}
	}
	si.totalObjects = n

	if err := si.lookupAccount(); err != nil {
		t.Fatalf("lookupAccount: %v", err)
	}
	if err := si.importFromS3(); err != nil {
		t.Fatalf("import: %v", err)
	}
	if si.importedMessages != n || si.failedMessages != 0 {
		t.Fatalf("imported %d, failed %d; want %d imported", si.importedMessages, si.failedMessages, n)
	}

	var marked int
	if err := si.db.QueryRow(`SELECT COUNT(*) FROM s3_objects
		WHERE processed AND success AND error_message = 'imported successfully'`).Scan(&marked); err != nil {
		t.Fatal(err)
	}
	if marked != n {
		t.Errorf("%d of %d imported objects marked processed in the work database", marked, n)
	}
}
