//go:build integration

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyHashPrimaryEmailChangeScopesByS3Key proves verifyContentHash scopes DB
// message lookup to the inspected S3 key (s3_domain, s3_localpart, content_hash)
// rather than matching any row of the account with the same content_hash.
func TestVerifyHashPrimaryEmailChangeScopesByS3Key(t *testing.T) {
	f := newRekeyFixture(t)
	mem, endpoint := newMemS3(t)
	cfg := verifyTestConfig(t, endpoint)

	accountA, domain, oldLocal := f.account("verify-email-old")
	newLocal := "rekey-verify-email-new-" + f.nonce
	oldEmail := oldLocal + "@" + domain
	newEmail := newLocal + "@" + domain

	// Simulate primary email change old@example.com -> new@example.com while keeping old@example.com as alias.
	require.NoError(t, f.rdb.AddCredentialWithRetry(f.ctx, db.AddCredentialRequest{
		AccountID:   accountA,
		NewEmail:    newEmail,
		NewPassword: "password",
		NewHashType: "bcrypt",
		IsPrimary:   true,
	}))

	putExact := func(s3Key string, data []byte) {
		mem.mu.Lock()
		mem.objects[s3Key] = data
		mem.mu.Unlock()
	}

	t.Run("orphan_at_old_prefix_with_live_message_at_new_prefix", func(t *testing.T) {
		body := f.body("orphan-at-old-prefix")
		hash := helpers.HashContent(body)
		oldKey := helpers.NewS3Key(domain, oldLocal, hash)
		newKey := helpers.NewS3Key(domain, newLocal, hash)

		// Live uploaded message under new@example.com, plus an unreferenced S3 orphan at old@example.com.
		f.insert(accountA, "INBOX", domain, newLocal, hash, body, "<new-live-"+f.nonce+"@example.org>")
		putExact(newKey, body)
		putExact(oldKey, body)

		out := captureStdout(t, func() error {
			return verifyContentHash(f.ctx, cfg, hash, oldEmail, false, false, "", "")
		})
		assert.Contains(t, out, "Orphaned S3 object",
			"orphan at old S3 prefix must be reported orphaned even when account has same hash at new prefix:\n%s", out)
		assert.NotContains(t, out, "Everything looks good",
			"verify hash must not declare an unreferenced S3 orphan healthy:\n%s", out)
	})

	t.Run("healthy_mail_at_old_prefix_checked_under_new_prefix_and_sql_hint", func(t *testing.T) {
		body := f.body("healthy-at-old-prefix")
		hash := helpers.HashContent(body)
		oldKey := helpers.NewS3Key(domain, oldLocal, hash)

		// Healthy uploaded message stored under old@example.com; nothing under new@example.com.
		f.insert(accountA, "INBOX", domain, oldLocal, hash, body, "<old-healthy-"+f.nonce+"@example.org>")
		putExact(oldKey, body)

		outNew := captureStdout(t, func() error {
			return verifyContentHash(f.ctx, cfg, hash, newEmail, false, false, "", "")
		})
		assert.NotContains(t, outNew, "CRITICAL: Messages marked as uploaded but content missing from S3",
			"healthy mail at old prefix must not be reported as missing-from-S3 corruption under new prefix:\n%s", outNew)
		assert.Contains(t, outNew, "Database messages using this hash: 0",
			"no DB messages use new@example.com's S3 key:\n%s", outNew)

		// Also verify SQL repair hint scopes by s3_domain and s3_localpart when a message at oldKey is uploaded=false.
		notUpBody := f.body("not-uploaded-sql-hint")
		notUpHash := helpers.HashContent(notUpBody)
		notUpKey := helpers.NewS3Key(domain, oldLocal, notUpHash)
		notUpID := f.insert(accountA, "INBOX", domain, oldLocal, notUpHash, notUpBody, "<old-notup-"+f.nonce+"@example.org>")
		f.exec("UPDATE messages SET uploaded = FALSE WHERE id = $1", notUpID)
		putExact(notUpKey, notUpBody)

		outHint := captureStdout(t, func() error {
			return verifyContentHash(f.ctx, cfg, notUpHash, oldEmail, false, false, "", "")
		})
		assert.Contains(t, outHint, "s3_domain = '"+domain+"'",
			"SQL hint must scope UPDATE by s3_domain:\n%s", outHint)
		assert.Contains(t, outHint, "s3_localpart = '"+oldLocal+"'",
			"SQL hint must scope UPDATE by s3_localpart:\n%s", outHint)
	})
}

// TestVerifyHashReportsCorruptAndLegacyWhenReferencedByOtherAccount proves that
// len(messages) == 0 for the queried account never suppresses S3 corruption
// (!contentIntact) failures or legacy SHA-256 warnings in the summary.
func TestVerifyHashReportsCorruptAndLegacyWhenReferencedByOtherAccount(t *testing.T) {
	f := newRekeyFixture(t)
	mem, endpoint := newMemS3(t)
	cfg := verifyTestConfig(t, endpoint)

	_, domain, localA := f.account("verify-xacct-corrupt-a")
	accountB, _, _ := f.account("verify-xacct-corrupt-b")
	emailA := localA + "@" + domain

	t.Run("corrupt_object_referenced_by_other_account", func(t *testing.T) {
		origBody := f.body("xacct-corrupt-body")
		corruptHash := helpers.HashContent(origBody)
		s3Key := helpers.NewS3Key(domain, localA, corruptHash)

		// Account B references s3Key under Account A's prefix, while S3 serves corrupt bytes.
		f.insert(accountB, "INBOX", domain, localA, corruptHash, origBody, "<xacct-corrupt-"+f.nonce+"@example.org>")
		mem.mu.Lock()
		mem.objects[s3Key] = []byte("truncated-corrupt-bytes")
		mem.mu.Unlock()

		out := captureStdout(t, func() error {
			return verifyContentHash(f.ctx, cfg, corruptHash, emailA, false, false, "", "")
		})
		assert.Contains(t, out, "Referenced by another account or pending upload",
			"cross-account reference should still be noted:\n%s", out)
		assert.NotContains(t, out, "[OK] Referenced by another account",
			"corrupt S3 object must not emit an [OK] verdict:\n%s", out)
		assert.Contains(t, out, "[FAIL] CRITICAL: Object exists in S3 but its body is corrupt or unreadable",
			"corruption summary must not be suppressed when len(messages) == 0:\n%s", out)
	})

	t.Run("legacy_sha256_object_referenced_by_other_account", func(t *testing.T) {
		legacyBody := f.body("xacct-legacy-sha256-body")
		sum := sha256.Sum256(legacyBody)
		legacySHA := hex.EncodeToString(sum[:])
		s3Key := helpers.NewS3Key(domain, localA, legacySHA)

		f.insert(accountB, "INBOX", domain, localA, legacySHA, legacyBody, "<xacct-legacy-"+f.nonce+"@example.org>")
		mem.mu.Lock()
		mem.objects[s3Key] = legacyBody
		mem.mu.Unlock()

		out := captureStdout(t, func() error {
			return verifyContentHash(f.ctx, cfg, legacySHA, emailA, false, false, "", "")
		})
		assert.Contains(t, out, "Referenced by another account or pending upload",
			"cross-account reference should still be noted:\n%s", out)
		assert.Contains(t, out, "stored under its SHA-256 digest",
			"legacy SHA-256 summary warning must not be suppressed when len(messages) == 0:\n%s", out)
	})
}

// TestVerifyHashHistoricalPrefixAndNullSubject proves verifyContentHash handles:
//  1. A historical S3-prefix address that is no longer present in credentials
//     (consts.ErrUserNotFound fallback to global UnreferencedContentObjects check).
//  2. A message row with subject IS NULL when listing details.
func TestVerifyHashHistoricalPrefixAndNullSubject(t *testing.T) {
	f := newRekeyFixture(t)
	mem, endpoint := newMemS3(t)
	cfg := verifyTestConfig(t, endpoint)

	accountB, domain, localB := f.account("verify-hist-active")
	emailB := localB + "@" + domain

	t.Run("historical_address_removed_from_credentials", func(t *testing.T) {
		retiredLocal := "retired-prefix-" + f.nonce
		retiredEmail := retiredLocal + "@" + domain

		refBody := f.body("retired-referenced")
		refHash := helpers.HashContent(refBody)
		refKey := helpers.NewS3Key(domain, retiredLocal, refHash)
		f.insert(accountB, "INBOX", domain, retiredLocal, refHash, refBody, "<retired-ref-"+f.nonce+"@example.org>")
		mem.mu.Lock()
		mem.objects[refKey] = refBody
		mem.mu.Unlock()

		orphanBody := f.body("retired-orphan")
		orphanHash := helpers.HashContent(orphanBody)
		orphanKey := helpers.NewS3Key(domain, retiredLocal, orphanHash)
		mem.mu.Lock()
		mem.objects[orphanKey] = orphanBody
		mem.mu.Unlock()

		refOut := captureStdout(t, func() error {
			return verifyContentHash(f.ctx, cfg, refHash, retiredEmail, false, false, "", "")
		})
		assert.Contains(t, refOut, "Referenced by another account or pending upload",
			"referenced object under retired address must not fail with ErrUserNotFound:\n%s", refOut)
		assert.NotContains(t, refOut, "Orphaned S3 object",
			"referenced object under retired address must not be reported orphaned:\n%s", refOut)

		orphanOut := captureStdout(t, func() error {
			return verifyContentHash(f.ctx, cfg, orphanHash, retiredEmail, false, false, "", "")
		})
		assert.Contains(t, orphanOut, "Orphaned S3 object",
			"unreferenced object under retired address must be reported orphaned:\n%s", orphanOut)
	})

	t.Run("null_subject_message_in_verify_hash", func(t *testing.T) {
		nullBody := f.body("null-subject-verify-hash")
		nullHash := helpers.HashContent(nullBody)
		nullKey := helpers.NewS3Key(domain, localB, nullHash)
		msgID := f.insert(accountB, "INBOX", domain, localB, nullHash, nullBody, "<null-subj-"+f.nonce+"@example.org>")
		f.exec("UPDATE messages SET subject = NULL WHERE id = $1", msgID)
		mem.mu.Lock()
		mem.objects[nullKey] = nullBody
		mem.mu.Unlock()

		out := captureStdout(t, func() error {
			return verifyContentHash(f.ctx, cfg, nullHash, emailB, true, false, "", "")
		})
		assert.Contains(t, out, "[OK] Everything looks good",
			"NULL subject must not break verify hash:\n%s", out)
	})
}

// TestVerifyS3FixMissingSlashLocalpartAndConcurrentUploadFence proves:
//  1. verify s3 --fix-missing handles '/' in localparts without missing target rows
//     or corrupting unrelated accounts whose localpart matches a prefix segment.
//  2. applyFixes acquires exclusive S3 object locks (GetS3ObjectLockID(0, hash)),
//     rechecks ExistsContext, and guards against pending_uploads so concurrent upload
//     completions between checkDBToS3 and applyFixes preserve uploaded = TRUE.
func TestVerifyS3FixMissingSlashLocalpartAndConcurrentUploadFence(t *testing.T) {
	f := newRekeyFixture(t)

	isUploaded := func(msgID int64) bool {
		var uploaded bool
		require.NoError(t, f.rdb.QueryRowWithRetry(f.ctx, "SELECT uploaded FROM messages WHERE id = $1", msgID).Scan(&uploaded))
		return uploaded
	}

	t.Run("slash_localpart_and_prefix_isolation", func(t *testing.T) {
		mem, endpoint := newMemS3(t)
		cfg := verifyTestConfig(t, endpoint)

		domain := "example.com"
		slashLocal := "first/last-" + f.nonce
		slashEmail := slashLocal + "@" + domain
		slashAcct, err := f.rdb.CreateAccountWithRetry(f.ctx, db.CreateAccountRequest{
			Email: slashEmail, Password: "password", IsPrimary: true, HashType: "bcrypt",
		})
		require.NoError(t, err)
		require.NoError(t, f.rdb.CreateDefaultMailboxesWithRetry(f.ctx, slashAcct))

		victimLocal := "victim-" + f.nonce
		victimEmail := victimLocal + "@" + domain
		victimAcct, err := f.rdb.CreateAccountWithRetry(f.ctx, db.CreateAccountRequest{
			Email: victimEmail, Password: "password", IsPrimary: true, HashType: "bcrypt",
		})
		require.NoError(t, err)
		require.NoError(t, f.rdb.CreateDefaultMailboxesWithRetry(f.ctx, victimAcct))

		victimBody := f.body("victim-live-mail")
		victimHash := helpers.HashContent(victimBody)
		victimID := f.insert(victimAcct, "INBOX", domain, victimLocal, victimHash, victimBody, "<victim-"+f.nonce+"@example.org>")
		mem.put(helpers.NewS3Key(domain, victimLocal, victimHash))

		colliderLocal := victimLocal + "/" + victimHash
		colliderEmail := colliderLocal + "@" + domain
		colliderAcct, err := f.rdb.CreateAccountWithRetry(f.ctx, db.CreateAccountRequest{
			Email: colliderEmail, Password: "password", IsPrimary: true, HashType: "bcrypt",
		})
		require.NoError(t, err)
		require.NoError(t, f.rdb.CreateDefaultMailboxesWithRetry(f.ctx, colliderAcct))

		slashBody := f.body("slash-missing-mail")
		slashHash := helpers.HashContent(slashBody)
		slashMsgID := f.insert(slashAcct, "INBOX", domain, slashLocal, slashHash, slashBody, "<slash-"+f.nonce+"@example.org>")

		colliderBody := f.body("collider-missing-mail")
		colliderHash := helpers.HashContent(colliderBody)
		colliderMsgID := f.insert(colliderAcct, "INBOX", domain, colliderLocal, colliderHash, colliderBody, "<collider-"+f.nonce+"@example.org>")

		require.NoError(t, verifyS3Storage(f.ctx, cfg, slashEmail, true, false, true, false, 1000, false))
		require.NoError(t, verifyS3Storage(f.ctx, cfg, colliderEmail, true, false, true, false, 1000, false))

		assert.False(t, isUploaded(slashMsgID), "missing S3 object for first/last@example.com must be marked uploaded=false")
		assert.False(t, isUploaded(colliderMsgID), "missing S3 object for user/<64hex>@example.com must be marked uploaded=false")
		assert.True(t, isUploaded(victimID), "live uploaded mail of user@example.com must not be clobbered by user/<64hex>@example.com fix")
	})

	t.Run("concurrent_upload_completes_before_applyFixes", func(t *testing.T) {
		mem, _ := newMemS3(t)
		accountID, domain, localpart := f.account("verify-fix-missing-race")

		// 1. Message whose upload completes between checkDBToS3 and applyFixes.
		completedBody := f.body("race-completed-body")
		completedHash := helpers.HashContent(completedBody)
		completedKey := helpers.NewS3Key(domain, localpart, completedHash)
		completedID := f.insert(accountID, "INBOX", domain, localpart, completedHash, completedBody, "<race-done-"+f.nonce+"@example.org>")
		f.exec("UPDATE messages SET uploaded = FALSE WHERE id = $1", completedID)

		// 2. Message that acquires a pending_uploads row before applyFixes (upload still in flight, not in S3 yet).
		inflightBody := f.body("race-inflight-body")
		inflightHash := helpers.HashContent(inflightBody)
		inflightKey := helpers.NewS3Key(domain, localpart, inflightHash)
		inflightID := f.insert(accountID, "INBOX", domain, localpart, inflightHash, inflightBody, "<race-inflight-"+f.nonce+"@example.org>")

		// 3. Truly missing message (uploaded=TRUE, no S3 object, no pending upload).
		missingBody := f.body("truly-missing-body")
		missingHash := helpers.HashContent(missingBody)
		missingKey := helpers.NewS3Key(domain, localpart, missingHash)
		missingID := f.insert(accountID, "INBOX", domain, localpart, missingHash, missingBody, "<truly-missing-"+f.nonce+"@example.org>")

		// Intercept HEAD requests during applyFixes to verify the exclusive S3 object lock
		// on GetS3ObjectLockID(0, hash) is held while ExistsContext probes S3.
		observerDB, err := newAdminDatabase(f.ctx, adminTestDBConfig(t))
		require.NoError(t, err)
		defer observerDB.Close()

		var sawExclusiveLockOnCompleted atomic.Bool
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead && strings.HasSuffix(r.URL.Path, "/"+completedKey) {
				lockID := uint64(db.GetS3ObjectLockID(0, completedHash))
				var held bool
				checkErr := observerDB.QueryRowWithRetry(f.ctx, `
					SELECT EXISTS (
						SELECT 1 FROM pg_locks
						WHERE locktype = 'advisory'
						  AND granted
						  AND mode = 'ExclusiveLock'
						  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
						  AND classid = $1::bigint::oid
						  AND objid = $2::bigint::oid
						  AND objsubid = 1
					)
				`, int64(lockID>>32), int64(lockID&0xffffffff)).Scan(&held)
				if checkErr == nil && held {
					sawExclusiveLockOnCompleted.Store(true)
				}
			}
			mem.ServeHTTP(w, r)
		}))
		defer srv.Close()

		s3Storage, err := storage.New(strings.TrimPrefix(srv.URL, "http://"), "test-access-key", "test-secret-key", verifyTestBucket, false, false, 5*time.Second)
		require.NoError(t, err)

		// Phase 1: checkDBToS3 records all three keys in MissingFromS3.
		res := &verificationResult{}
		require.NoError(t, checkDBToS3(f.ctx, f.rdb, s3Storage, accountID, res, 1000, false))
		assert.ElementsMatch(t, []string{completedKey, inflightKey, missingKey}, res.MissingFromS3)

		// Reset head lock flag before applyFixes so only applyFixes's recheck counts.
		sawExclusiveLockOnCompleted.Store(false)

		// Between checkDBToS3 and applyFixes:
		// (a) Upload worker completes completedHash: leases pending_uploads, PUTs S3 object,
		//     calls CompleteLeasedS3Upload (setting uploaded=TRUE and deleting pending_uploads).
		var pendingID int64
		require.NoError(t, f.rdb.QueryRowWithRetry(f.ctx, `
			INSERT INTO pending_uploads (instance_id, content_hash, size, account_id)
			VALUES ('verify-race-worker', $1, $2, $3) RETURNING id
		`, completedHash, len(completedBody), accountID).Scan(&pendingID))
		gate, err := f.rdb.PassS3WriteGateWithRetry(f.ctx, pendingID, accountID, completedHash, "verify-race-worker", time.Minute)
		require.NoError(t, err)
		require.Equal(t, db.S3WriteOpen, gate)
		require.NoError(t, s3Storage.PutContext(f.ctx, completedKey, bytes.NewReader(completedBody), int64(len(completedBody))))
		require.NoError(t, f.rdb.CompleteLeasedS3UploadWithRetry(f.ctx, pendingID, "verify-race-worker", completedHash, accountID, []string{completedKey}))
		require.True(t, isUploaded(completedID), "precondition: upload worker marked completedID uploaded=TRUE")

		// (b) inflightHash receives a pending_uploads row before applyFixes runs.
		f.exec("INSERT INTO pending_uploads (instance_id, content_hash, size, account_id) VALUES ('verify-inflight', $1, $2, $3)",
			inflightHash, len(inflightBody), accountID)

		// Run applyFixes with fixMissing=true.
		require.NoError(t, applyFixes(f.ctx, f.rdb, s3Storage, accountID, res, false, true))

		assert.True(t, sawExclusiveLockOnCompleted.Load(), "applyFixes must hold exclusive S3 object lock during ExistsContext recheck")
		assert.True(t, isUploaded(completedID), "concurrently uploaded message must keep uploaded=TRUE")
		assert.True(t, isUploaded(inflightID), "message with active pending_uploads row must keep uploaded=TRUE")
		assert.False(t, isUploaded(missingID), "genuinely missing message must be marked uploaded=FALSE")
		assert.Equal(t, 1, res.FixedMissing, "only genuinely missing message should count as FixedMissing")
	})
}

// TestVerifyIDNULabelEmail proves both verifyS3Storage and verifyContentHash
// canonicalize U-label IDN domains (e.g. user@bücher.example -> user@xn--bcher-kva.example)
// before looking up the account in credentials.
func TestVerifyIDNULabelEmail(t *testing.T) {
	f := newRekeyFixture(t)
	mem, endpoint := newMemS3(t)
	cfg := verifyTestConfig(t, endpoint)

	localpart := "idn-" + f.nonce
	uLabelEmail := localpart + "@bücher.example"
	aLabelDomain := "xn--bcher-kva.example"

	accountID, err := f.rdb.CreateAccountWithRetry(f.ctx, db.CreateAccountRequest{
		Email: uLabelEmail, Password: "password", IsPrimary: true, HashType: "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, f.rdb.CreateDefaultMailboxesWithRetry(f.ctx, accountID))

	body := f.body("idn-u-label-mail")
	hash := helpers.HashContent(body)
	s3Key := helpers.NewS3Key(aLabelDomain, localpart, hash)
	f.insert(accountID, "INBOX", aLabelDomain, localpart, hash, body, "<idn-"+f.nonce+"@example.org>")
	mem.mu.Lock()
	mem.objects[s3Key] = body
	mem.mu.Unlock()

	t.Run("verify_s3_u_label", func(t *testing.T) {
		out := captureStdout(t, func() error {
			return verifyS3Storage(f.ctx, cfg, uLabelEmail, false, false, false, false, 1000, true)
		})
		assert.Contains(t, out, "[OK] No issues found. S3 storage is consistent.",
			"verify s3 must resolve U-label IDN --email:\n%s", out)
	})

	t.Run("verify_hash_u_label", func(t *testing.T) {
		out := captureStdout(t, func() error {
			return verifyContentHash(f.ctx, cfg, hash, uLabelEmail, false, false, "", "")
		})
		assert.Contains(t, out, "[OK] Everything looks good",
			"verify hash must resolve U-label IDN --email:\n%s", out)
	})
}
