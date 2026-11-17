//go:build integration

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyCrossAccountRekeyAndHash reproduces #557 across verify s3 (both read-only
// checkS3ToDB and --fix-orphaned, including mixed-case --email) and verify hash:
// when Account A rekeys a shared body from SHA-256 to BLAKE3 while Account B still
// references the old S3 key under A's address, neither checkS3ToDB, --fix-orphaned,
// nor verify hash may treat the shared old object as orphaned.
func TestVerifyCrossAccountRekeyAndHash(t *testing.T) {
	f := newRekeyFixture(t)
	mem, endpoint := newMemS3(t)
	cfg := verifyTestConfig(t, endpoint)

	accountA, domain, localpart := f.account("verify-rekey-a")
	accountB, _, _ := f.account("verify-rekey-b")
	key := func(hash string) string { return helpers.NewS3Key(domain, localpart, hash) }

	sharedBody := f.body("shared-rekey-body")
	sum256 := sha256.Sum256(sharedBody)
	oldSHA := hex.EncodeToString(sum256[:])
	newBLAKE3 := helpers.HashContent(sharedBody)

	// Both accounts initially point at the legacy SHA-256 key under A's address.
	f.insert(accountA, "INBOX", domain, localpart, oldSHA, sharedBody, "<shared-a-"+f.nonce+"@example.org>")
	f.insert(accountB, "INBOX", domain, localpart, oldSHA, sharedBody, "<shared-b-"+f.nonce+"@example.org>")
	mem.put(key(oldSHA))
	// Overwrite with exact body bytes so deep/rekey content verification matches SHA-256.
	mem.mu.Lock()
	mem.objects[key(oldSHA)] = sharedBody
	mem.mu.Unlock()

	s3Storage, err := storage.New(cfg.S3.Endpoint, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, false, false, 5*time.Second)
	require.NoError(t, err)

	// Account A rekeys its messages to BLAKE3; Account B still references key(oldSHA).
	report, err := rekeyAccount(f.ctx, f.rdb, s3Storage, accountA, rekeyOptions{
		BodyDeletionProtocol: "global-hash-v1",
		DeleteOldObjects:     true,
		BatchSize:            100,
		Jobs:                 1,
	})
	require.NoError(t, err)
	require.Equal(t, 1, report.Rekeyed)
	require.Zero(t, report.OldDeleted)
	require.True(t, mem.has(key(newBLAKE3)), "rekey must write Account A's BLAKE3 object")
	require.True(t, mem.has(key(oldSHA)), "rekey must retain the old SHA-256 object while Account B references it")

	// Confirm Account A's per-user verification list no longer mentions oldSHA.
	aMsgs, err := f.rdb.GetAllMessagesForUserVerificationWithRetry(f.ctx, accountA)
	require.NoError(t, err)
	for _, m := range aMsgs {
		require.NotEqual(t, oldSHA, m.ContentHash)
	}

	// Add one genuine orphan under A's prefix.
	orphanHash := helpers.HashContent(f.body("true-orphan"))
	mem.put(key(orphanHash))

	// 1. checkS3ToDB with mixed-case email must normalize the S3 prefix, count CheckedS3ToDB,
	//    and classify ONLY orphanHash (never oldSHA or newBLAKE3).
	mixedEmail := strings.ToUpper(localpart) + "@" + strings.ToUpper(domain)
	res := &verificationResult{}
	require.NoError(t, checkS3ToDB(f.ctx, f.rdb, s3Storage, mixedEmail, res, 1000))
	assert.Equal(t, 3, res.ObjectsInS3)
	assert.Equal(t, 3, res.CheckedS3ToDB)
	assert.Equal(t, []string{key(orphanHash)}, res.OrphanedInS3)

	// 2. verify hash on Account A (with mixed-case email) for oldSHA must NOT call it orphaned.
	hashOut := captureStdout(t, func() error {
		return verifyContentHash(f.ctx, cfg, oldSHA, mixedEmail, false, false, "", "")
	})
	assert.NotContains(t, hashOut, "Orphaned S3 object",
		"verify hash must not report an object still referenced by Account B as orphaned:\n%s", hashOut)
	assert.Contains(t, hashOut, "Referenced by another account or pending upload",
		"verify hash should explain why the object is retained:\n%s", hashOut)

	// 3. verify s3 --fix-orphaned with mixed-case email deletes only orphanHash and keeps oldSHA.
	require.NoError(t, verifyS3Storage(f.ctx, cfg, mixedEmail, true, true, false, false, 1000, false))
	assert.True(t, mem.has(key(oldSHA)), "Account B's shared object must survive --fix-orphaned on Account A")
	assert.True(t, mem.has(key(newBLAKE3)), "Account A's rekeyed object must survive --fix-orphaned")
	assert.False(t, mem.has(key(orphanHash)), "genuine orphan must be deleted even when --email is mixed-case")
}

// TestVerifyCrossAccountPendingAndDetachedReferences covers:
//  1. A cross-account pending_uploads-only reference (0 message rows) in checkS3ToDB,
//     applyFixes, and verifyContentHash.
//  2. A detached-mailbox expunged message (mailbox_id IS NULL after mailbox purge, still
//     restorable within grace) in verifyContentHash.
//  3. Cross-account message and pending_uploads claims created AFTER checkS3ToDB and
//     BEFORE applyFixes deletes the candidate.
func TestVerifyCrossAccountPendingAndDetachedReferences(t *testing.T) {
	f := newRekeyFixture(t)
	mem, endpoint := newMemS3(t)
	cfg := verifyTestConfig(t, endpoint)

	accountA, domain, localpart := f.account("verify-xacct-a")
	accountB, _, _ := f.account("verify-xacct-b")
	emailA := localpart + "@" + domain
	key := func(hash string) string { return helpers.NewS3Key(domain, localpart, hash) }

	// 1. Cross-account pending_uploads-only reference.
	pendingBody := f.body("xacct-pending-only")
	pendingHash := helpers.HashContent(pendingBody)
	f.exec("INSERT INTO pending_uploads (instance_id, content_hash, size, account_id) VALUES ('verify-test', $1, $2, $3)",
		pendingHash, len(pendingBody), accountB)
	mem.mu.Lock()
	mem.objects[key(pendingHash)] = pendingBody
	mem.mu.Unlock()

	hashOut := captureStdout(t, func() error {
		return verifyContentHash(f.ctx, cfg, pendingHash, emailA, false, false, "", "")
	})
	assert.NotContains(t, hashOut, "Orphaned S3 object",
		"verify hash must not report a body with a cross-account pending upload as orphaned:\n%s", hashOut)
	assert.Contains(t, hashOut, "Referenced by another account or pending upload",
		"verify hash should report pending/cross-account retention:\n%s", hashOut)

	// 2. Detached-mailbox expunged message (mailbox_id IS NULL, mailbox_path retained).
	detachedBody := f.body("detached-expunged")
	detachedHash := helpers.HashContent(detachedBody)
	detachedMsgID := f.insert(accountA, "Archive", domain, localpart, detachedHash, detachedBody, "<detached-"+f.nonce+"@example.org>")
	f.exec("UPDATE messages SET expunged_at = now(), mailbox_id = NULL, mailbox_path = 'Archive' WHERE id = $1", detachedMsgID)
	mem.mu.Lock()
	mem.objects[key(detachedHash)] = detachedBody
	mem.mu.Unlock()

	detachedOut := captureStdout(t, func() error {
		return verifyContentHash(f.ctx, cfg, detachedHash, emailA, true, false, "", "")
	})
	assert.NotContains(t, detachedOut, "Orphaned S3 object",
		"verify hash must see restorable expunged messages whose mailbox was purged:\n%s", detachedOut)
	assert.Contains(t, detachedOut, "Expunged (pending cleanup): 1",
		"verify hash must count the detached expunged message:\n%s", detachedOut)

	// 3. Candidates classified as orphaned in checkS3ToDB, then claimed by Account B
	//    (via a message row and via a pending_uploads row) before applyFixes runs.
	lateMsgBody := f.body("late-xacct-msg")
	lateMsgHash := helpers.HashContent(lateMsgBody)
	mem.put(key(lateMsgHash))

	latePendingBody := f.body("late-xacct-pending")
	latePendingHash := helpers.HashContent(latePendingBody)
	mem.put(key(latePendingHash))

	s3Storage, err := storage.New(cfg.S3.Endpoint, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, false, false, 5*time.Second)
	require.NoError(t, err)

	res := &verificationResult{}
	require.NoError(t, checkS3ToDB(f.ctx, f.rdb, s3Storage, emailA, res, 1000))
	assert.ElementsMatch(t, []string{key(lateMsgHash), key(latePendingHash)}, res.OrphanedInS3)

	// Account B claims both between checkS3ToDB and applyFixes.
	f.insert(accountB, "INBOX", domain, localpart, lateMsgHash, lateMsgBody, "<late-b-"+f.nonce+"@example.org>")
	f.exec("INSERT INTO pending_uploads (instance_id, content_hash, size, account_id) VALUES ('verify-test', $1, $2, $3)",
		latePendingHash, len(latePendingBody), accountB)

	require.NoError(t, applyFixes(f.ctx, f.rdb, s3Storage, accountA, res, true, false))
	assert.Zero(t, res.FixedOrphaned)
	assert.True(t, mem.has(key(lateMsgHash)), "cross-account message claim before delete must keep object")
	assert.True(t, mem.has(key(latePendingHash)), "cross-account pending upload before delete must keep object")
}
