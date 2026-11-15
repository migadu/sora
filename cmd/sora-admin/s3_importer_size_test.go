//go:build integration

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
)

// TestS3Importer_EncryptedObjectStoresMessageSize imports a body stored with S3
// encryption on. The stored object is the AES-256-GCM output (nonce + ciphertext +
// tag), so the size the bucket listing reports is 28 octets more than the message;
// messages.size must be the message's octet count, which is what FETCH BODY[]
// returns (RFC 9051 §2.3.4: RFC822.SIZE "SHOULD match the result of a "FETCH
// BODY[]" command").
func TestS3Importer_EncryptedObjectStoresMessageSize(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()
	ctx := context.Background()

	const email = "s3import-encrypted@example.com"
	createSimpleTestAccount(t, rdb, email, "testpassword123")
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, email)
	if err != nil {
		t.Fatal(err)
	}

	_, s3storage := common.NewFakeS3Storage(t)
	if err := s3storage.EnableEncryption(strings.Repeat("0f", 32)); err != nil {
		t.Fatal(err)
	}

	body := []byte("From: sender@example.org\r\n" +
		"To: " + email + "\r\n" +
		"Subject: encrypted import\r\n" +
		"Date: Mon, 02 Nov 2026 10:00:00 +0000\r\n" +
		"Message-ID: <encrypted-import@example.org>\r\n" +
		"\r\n" +
		"Hello from an encrypted bucket.\r\n")
	hash := helpers.HashContent(body)
	key := helpers.NewS3Key("example.com", "s3import-encrypted", hash)
	if err := s3storage.Put(key, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatalf("put: %v", err)
	}

	// The size the bucket scan records is the stored object's, as ListObjectsV2
	// reports it.
	head, err := s3storage.Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s3storage.BucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	stored := aws.ToInt64(head.ContentLength)
	if stored == int64(len(body)) {
		t.Fatalf("stored object is %d octets, the size of the message: not encrypted", stored)
	}

	si, err := NewS3Importer(rdb, s3storage, S3ImporterOptions{Email: email, Workers: 1, CleanupDB: true, InstanceID: "test-instance"})
	if err != nil {
		t.Fatal(err)
	}
	defer si.Close()
	if _, err := si.db.Exec(`INSERT INTO s3_objects (key, size, last_modified, etag, domain, local_part, content_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, key, stored, "2026-11-02T10:00:00Z", "etag",
		"example.com", "s3import-encrypted", hash); err != nil {
		t.Fatal(err)
	}
	si.totalObjects = 1

	if err := si.importFromS3(); err != nil {
		t.Fatalf("import: %v", err)
	}
	if si.importedMessages != 1 || si.failedMessages != 0 {
		t.Fatalf("imported %d, failed %d; want 1 imported", si.importedMessages, si.failedMessages)
	}

	var size int64
	if err := rdb.QueryRowWithRetry(ctx,
		"SELECT size FROM messages WHERE account_id = $1 AND content_hash = $2 AND expunged_at IS NULL",
		accountID, hash).Scan(&size); err != nil {
		t.Fatalf("query imported message: %v", err)
	}
	if size != int64(len(body)) {
		t.Errorf("messages.size = %d, want %d (the message's octets; the stored object is %d)", size, len(body), stored)
	}
}
