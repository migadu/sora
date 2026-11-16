//go:build integration

package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
)

// TestS3Importer_SkipsObjectsOfAnotherUser: the importer files every object it is given
// under --email's prefix (messages.s3_domain/s3_localpart, CompleteS3Upload's key), so an
// object under another user's prefix must never reach --email's account. Two runs that
// shared a work database handed each other exactly such rows: b's message landed in a's
// INBOX, marked uploaded under a key with no object behind it.
func TestS3Importer_SkipsObjectsOfAnotherUser(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()
	ctx := context.Background()

	const emailA = "s3import-scope-a@example.com"
	const emailB = "s3import-scope-b@example.com"
	createSimpleTestAccount(t, rdb, emailA, "testpassword123")
	createSimpleTestAccount(t, rdb, emailB, "testpassword123")
	accountA, err := rdb.GetAccountIDByAddressWithRetry(ctx, emailA)
	if err != nil {
		t.Fatal(err)
	}

	_, s3storage := common.NewFakeS3Storage(t)
	body := []byte("From: sender@example.org\r\n" +
		"To: " + emailB + "\r\n" +
		"Subject: for b only\r\n" +
		"Date: Mon, 02 Nov 2026 10:00:00 +0000\r\n" +
		"Message-ID: <scope-b@example.org>\r\n" +
		"\r\n" +
		"This is b's mail.\r\n")
	hash := helpers.HashContent(body)
	keyB := helpers.NewS3Key("example.com", "s3import-scope-b", hash)
	if err := s3storage.Put(keyB, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatalf("put: %v", err)
	}

	si, err := NewS3Importer(ctx, rdb, s3storage, S3ImporterOptions{Email: emailA, Workers: 1, CleanupDB: true, InstanceID: "test-instance"})
	if err != nil {
		t.Fatal(err)
	}
	defer si.Close()
	// b's row, as b's scan records it.
	if _, err := si.db.Exec(`INSERT INTO s3_objects (key, size, last_modified, etag, domain, local_part, content_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, keyB, len(body), "2026-11-02T10:00:00Z", "etag",
		"example.com", "s3import-scope-b", hash); err != nil {
		t.Fatal(err)
	}
	si.totalObjects = 1

	if err := si.lookupAccount(); err != nil {
		t.Fatalf("lookupAccount: %v", err)
	}
	if err := si.importFromS3(); err != nil {
		t.Fatalf("import: %v", err)
	}
	if si.importedMessages != 0 {
		t.Errorf("imported %d messages, want 0", si.importedMessages)
	}

	var count int
	if err := rdb.QueryRowWithRetry(ctx,
		"SELECT COUNT(*) FROM messages WHERE account_id = $1", accountA).Scan(&count); err != nil {
		t.Fatalf("count messages: %v", err)
	}
	if count != 0 {
		t.Errorf("%s has %d messages after importing an object under %s's prefix, want 0", emailA, count, emailB)
	}
}
