//go:build integration

package imap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// crossAccountBodyCap is the most distinct messages one COPY or MOVE may carry into a
// mailbox of another account.
const crossAccountBodyCap = db.MaxCrossAccountBodies

// A COPY or MOVE into another account's mailbox holds two lock-table entries per distinct
// message until it commits, so one over the cap is refused with NO [LIMIT] (RFC 5530) and
// copies or moves nothing; a COPY may not be split, RFC 9051 §6.4.7: "partial copy MUST
// NOT be done".
func TestIMAP_CrossAccountCopyMoveOverTheBodyCapAnswersLimit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, contributor, fake := common.SetupIMAPServerWithRealS3(t)
	defer server.Close()
	ctx := context.Background()
	rdb := server.ResilientDB

	_, ownerID, shared := createOwnerWithSharedMailbox(t, server, contributor.Email, "lrswi")
	contributorID, err := rdb.GetAccountIDByAddressWithRetry(ctx, contributor.Email)
	require.NoError(t, err)

	cc, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer cc.Logout()
	require.NoError(t, cc.Login(contributor.Email, contributor.Password).Wait())

	// One appended message and crossAccountBodyCap copies of its row, each with a body of
	// its own, all of them marked uploaded under the contributor's key.
	const messages = crossAccountBodyCap + 1
	appendTo(t, cc, "INBOX", "Body cap", "cross-account body cap marker")
	server.WaitForUploads(t)
	var inboxID, sourceID int64
	require.NoError(t, rdb.QueryRowWithRetry(ctx, `
		SELECT m.mailbox_id, m.id FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
		WHERE mb.account_id = $1 AND mb.name = 'INBOX' AND m.expunged_at IS NULL`,
		contributorID).Scan(&inboxID, &sourceID))
	_, err = rdb.ExecWithRetry(ctx, `
		WITH inserted AS (
			INSERT INTO messages (account_id, uid, s3_domain, s3_localpart, content_hash, uploaded,
			                      recipients_json, message_id, in_reply_to, "references", subject,
			                      sent_date, sent_utc_offset, sent_date_unknown, internal_date, size,
			                      body_structure, subject_sort, from_name_sort, from_email_sort,
			                      to_name_sort, to_email_sort, cc_email_sort, extra_addresses,
			                      mailbox_id, mailbox_path, created_modseq)
			SELECT m.account_id, m.uid + g, m.s3_domain, m.s3_localpart, $2 || g, TRUE,
			       m.recipients_json, '<' || $2 || g || '@example.com>', m.in_reply_to, m."references", m.subject,
			       m.sent_date, m.sent_utc_offset, m.sent_date_unknown, m.internal_date, m.size,
			       m.body_structure, m.subject_sort, m.from_name_sort, m.from_email_sort,
			       m.to_name_sort, m.to_email_sort, m.cc_email_sort, m.extra_addresses,
			       m.mailbox_id, m.mailbox_path, nextval('messages_modseq')
			FROM messages m, generate_series(1, $3::int) AS g
			WHERE m.id = $1
			RETURNING id, mailbox_id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags, flags_changed_at, updated_modseq)
		SELECT id, mailbox_id, 0, '[]'::jsonb, now(), nextval('messages_modseq') FROM inserted`,
		sourceID, fmt.Sprintf("xacct-cap-%d-", common.GetTimestamp()), messages-1)
	require.NoError(t, err)
	_, err = rdb.ExecWithRetry(ctx, `UPDATE mailboxes SET highest_uid = highest_uid + $2 WHERE id = $1`, inboxID, messages-1)
	require.NoError(t, err)

	_, err = cc.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	all := imap.UIDSet{imap.UIDRange{Start: 1, Stop: 0}}

	count := func(accountID int64, mailbox string) int {
		var n int
		require.NoError(t, rdb.QueryRowWithRetry(ctx, `
			SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
			WHERE mb.account_id = $1 AND mb.name = $2 AND m.expunged_at IS NULL`,
			accountID, mailbox).Scan(&n))
		return n
	}
	requireLimit := func(command string, err error) {
		t.Helper()
		var imapErr *imap.Error
		if !errors.As(err, &imapErr) || imapErr.Type != imap.StatusResponseTypeNo || imapErr.Code != imap.ResponseCodeLimit {
			t.Errorf("UID %s of %d distinct messages into another user's mailbox: got %v, want NO [LIMIT]", command, messages, err)
		}
		if n := count(ownerID, shared); n != 0 {
			t.Errorf("UID %s over the cap left %d messages in the shared mailbox, want 0", command, n)
		}
		if n := count(contributorID, "INBOX"); n != messages {
			t.Errorf("UID %s over the cap left %d messages in INBOX, want %d", command, n, messages)
		}
	}

	objects := fake.ObjectCount()
	_, err = cc.Copy(all, shared).Wait()
	requireLimit("COPY", err)
	_, err = cc.Move(all, shared).Wait()
	requireLimit("MOVE", err)
	if n := fake.ObjectCount(); n != objects {
		t.Errorf("refused commands changed the S3 object count from %d to %d", objects, n)
	}

	// Legacy destination-owned rows still need source body admission. One row is
	// rekeyed, but all1001 distinct source bodies must count before any S3 copy.
	_, err = rdb.ExecWithRetry(ctx, `UPDATE messages SET account_id=$2 WHERE mailbox_id=$1 AND uid>1`, inboxID, ownerID)
	require.NoError(t, err)
	_, err = cc.Copy(all, shared).Wait()
	requireLimit("COPY mixed ownership", err)
	_, err = cc.Move(all, shared).Wait()
	requireLimit("MOVE mixed ownership", err)
	require.Equal(t, objects, fake.ObjectCount(), "mixed-ownership refusal must precede storage changes")
}

// Same-mailbox COPY and MOVE on a shared mailbox containing legacy contributor
// rows (msg.AccountID != destMailbox.AccountID) never re-key rows to the mailbox
// owner: COPY must be refused immediately without staging spool files, taking
// destination S3 locks, or copying S3 orphans; MOVE must succeed over >1,000
// uploaded rows plus local/remote pending rows and concurrent source rekeys
// without staging spool files, taking destination S3 locks, or touching S3.
func TestIMAP_SameMailboxMixedOwnershipCopyMoveSkipsCrossAccountStaging(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, contributor, fake := common.SetupIMAPServerWithRealS3(t)
	defer server.Close()
	ctx := context.Background()
	rdb := server.ResilientDB
	pool := rdb.GetDatabase().GetWritePool()

	ownerEmail, ownerID, shared := createOwnerWithSharedMailbox(t, server, contributor.Email, "lrswite")
	contributorID, err := rdb.GetAccountIDByAddressWithRetry(ctx, contributor.Email)
	require.NoError(t, err)
	ownerLocal, ownerDomain, _ := strings.Cut(ownerEmail, "@")
	ownerPrefix := ownerDomain + "/" + ownerLocal + "/"

	s3storage, err := storage.New(fake.Endpoint(), "test-access-key", "test-secret-key", "test-bucket", false, false, 10*time.Second)
	require.NoError(t, err)

	cc, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer cc.Logout()
	require.NoError(t, cc.Login(contributor.Email, contributor.Password).Wait())

	// Seed one real message so we have a valid template row + contributor S3 coordinates.
	appendTo(t, cc, "INBOX", "Template", "same-mailbox mixed-ownership marker")
	server.WaitForUploads(t)

	var templateID, sharedID int64
	var contribDomain, contribLocal string
	require.NoError(t, rdb.QueryRowWithRetry(ctx, `
		SELECT m.id, m.s3_domain, m.s3_localpart
		FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
		WHERE mb.account_id = $1 AND mb.name = 'INBOX' AND m.expunged_at IS NULL`,
		contributorID).Scan(&templateID, &contribDomain, &contribLocal))
	require.NoError(t, rdb.QueryRowWithRetry(ctx,
		`SELECT id FROM mailboxes WHERE account_id = $1 AND name = $2`,
		ownerID, shared).Scan(&sharedID))

	// Populate shared with (crossAccountBodyCap + 1) uploaded legacy contributor rows,
	// 1 locally-staged unuploaded legacy contributor row, and 1 remote-pending unuploaded
	// legacy contributor row.
	const uploadedCount = crossAccountBodyCap + 1
	seedTag := uint64(common.GetTimestamp())
	hashFor := func(i int) string {
		return fmt.Sprintf("%016x%048x", seedTag, i)
	}
	payload := []byte("From: a@example.com\r\nSubject: legacy\r\n\r\nlegacy body\r\n")
	for i := 1; i <= uploadedCount; i++ {
		h := hashFor(i)
		require.NoError(t, s3storage.Put(helpers.NewS3Key(contribDomain, contribLocal, h), bytes.NewReader(payload), int64(len(payload))))
	}
	localPendingHash := hashFor(uploadedCount + 1)
	remotePendingHash := hashFor(uploadedCount + 2)

	// Stage localPendingHash only under contributorID's spool path.
	contribSpoolPath := uploader.StagingFilePath(server.UploadPath, localPendingHash, contributorID)
	require.NoError(t, os.MkdirAll(filepath.Dir(contribSpoolPath), 0o755))
	require.NoError(t, os.WriteFile(contribSpoolPath, payload, 0o644))
	ownerSpoolPath := uploader.StagingFilePath(server.UploadPath, localPendingHash, ownerID)

	const totalRows = uploadedCount + 2
	hashes := make([]string, totalRows)
	uploadedFlags := make([]bool, totalRows)
	for i := 0; i < uploadedCount; i++ {
		hashes[i] = hashFor(i + 1)
		uploadedFlags[i] = true
	}
	hashes[uploadedCount] = localPendingHash
	uploadedFlags[uploadedCount] = false
	hashes[uploadedCount+1] = remotePendingHash
	uploadedFlags[uploadedCount+1] = false

	_, err = rdb.ExecWithRetry(ctx, `
		WITH seed AS (
			SELECT row_number() OVER () AS uid, h, u
			FROM unnest($3::text[], $4::boolean[]) WITH ORDINALITY AS t(h, u, ord)
		),
		inserted AS (
			INSERT INTO messages (account_id, uid, s3_domain, s3_localpart, content_hash, uploaded,
			                      recipients_json, message_id, in_reply_to, "references", subject,
			                      sent_date, sent_utc_offset, sent_date_unknown, internal_date, size,
			                      body_structure, subject_sort, from_name_sort, from_email_sort,
			                      to_name_sort, to_email_sort, cc_email_sort, extra_addresses,
			                      mailbox_id, mailbox_path, created_modseq)
			SELECT $5, s.uid, m.s3_domain, m.s3_localpart, s.h, s.u,
			       m.recipients_json, '<' || s.h || '@example.com>', m.in_reply_to, m."references", m.subject,
			       m.sent_date, m.sent_utc_offset, m.sent_date_unknown, m.internal_date, $6,
			       m.body_structure, m.subject_sort, m.from_name_sort, m.from_email_sort,
			       m.to_name_sort, m.to_email_sort, m.cc_email_sort, m.extra_addresses,
			       $2, $7, nextval('messages_modseq')
			FROM messages m CROSS JOIN seed s
			WHERE m.id = $1
			RETURNING id, mailbox_id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags, flags_changed_at, updated_modseq)
		SELECT id, mailbox_id, 0, '[]'::jsonb, now(), nextval('messages_modseq') FROM inserted`,
		templateID, sharedID, hashes, uploadedFlags, contributorID, len(payload), shared)
	require.NoError(t, err)
	_, err = rdb.ExecWithRetry(ctx, `UPDATE mailboxes SET highest_uid = $2 WHERE id = $1`, sharedID, totalRows)
	require.NoError(t, err)
	_, err = rdb.ExecWithRetry(ctx, `
		INSERT INTO pending_uploads (account_id, content_hash, size, instance_id, attempts)
		VALUES ($1, $2, $4, 'stalled-local-node', 0), ($1, $3, $4, 'remote-node', 1)`,
		contributorID, localPendingHash, remotePendingHash, len(payload))
	require.NoError(t, err)

	_, err = cc.Select(shared, nil).Wait()
	require.NoError(t, err)
	all := imap.UIDSet{imap.UIDRange{Start: 1, Stop: 0}}

	// runWithOwnerLockHeld runs fn while holding the exclusive destination S3 lock
	// on ownerID's first body hash. If fn tries LockS3ObjectsSharedInTx(ownerID, ...),
	// pg_blocking_pids detects it immediately and releases the lock so the test never hangs.
	runWithOwnerLockHeld := func(t *testing.T, fn func() error) (blocked bool, err error) {
		t.Helper()
		lockTx, txErr := pool.Begin(ctx)
		require.NoError(t, txErr)
		defer func() { _ = lockTx.Rollback(ctx) }()
		var lockPID int
		require.NoError(t, lockTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&lockPID))
		_, txErr = lockTx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, db.GetS3ObjectLockID(ownerID, hashes[0]))
		require.NoError(t, txErr)

		done := make(chan error, 1)
		go func() { done <- fn() }()

		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		deadline := time.NewTimer(2 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case opErr := <-done:
				return false, opErr
			case <-ticker.C:
				var waiting bool
				_ = pool.QueryRow(ctx,
					`SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))`,
					lockPID).Scan(&waiting)
				if waiting {
					_ = lockTx.Rollback(ctx)
					return true, <-done
				}
			case <-deadline.C:
				_ = lockTx.Rollback(ctx)
				return true, <-done
			}
		}
	}

	t.Run("COPY", func(t *testing.T) {
		// Isolate COPY to the 1,001 uploaded rows + 1 locally-staged row so an unfixed
		// build reaches S3 CopyObject on all 1,001 hashes before db.CopyMessages fails.
		copySet := imap.UIDSet{imap.UIDRange{Start: 1, Stop: imap.UID(uploadedCount + 1)}}
		blocked, copyErr := runWithOwnerLockHeld(t, func() error {
			_, err := cc.Copy(copySet, shared).Wait()
			return err
		})
		var imapErr *imap.Error
		require.ErrorAs(t, copyErr, &imapErr)
		require.Equal(t, imap.StatusResponseTypeNo, imapErr.Type)
		require.Contains(t, imapErr.Text, "Cannot copy messages to the same mailbox")
		assert.False(t, blocked, "same-mailbox COPY must not acquire LockS3ObjectsSharedInTx on destination owner")
		assert.Empty(t, fake.Keys(ownerPrefix), "same-mailbox COPY must not copy S3 orphan objects to owner")
		_, statErr := os.Stat(ownerSpoolPath)
		assert.ErrorIs(t, statErr, os.ErrNotExist, "same-mailbox COPY must not link orphan spool files into owner staging")
	})

	// Clean any artifacts if COPY subtest failed on an unfixed build so MOVE tests its own behavior cleanly.
	for _, k := range fake.Keys(ownerPrefix) {
		_ = s3storage.Delete(k)
	}
	_ = os.Remove(ownerSpoolPath)

	t.Run("MOVE", func(t *testing.T) {
		moveData, moveErr := cc.Move(all, shared).Wait()
		require.NoError(t, moveErr, "same-mailbox MOVE over mixed-ownership uploaded + pending rows must succeed")
		require.NotNil(t, moveData)
		require.Empty(t, fake.Keys(ownerPrefix), "same-mailbox MOVE must not copy S3 orphan objects to owner")
		_, statErr := os.Stat(ownerSpoolPath)
		require.ErrorIs(t, statErr, os.ErrNotExist, "same-mailbox MOVE must not link orphan spool files into owner staging")

		var liveContributorRows, ownerPendingRows int
		require.NoError(t, rdb.QueryRowWithRetry(ctx,
			`SELECT count(*) FROM messages WHERE mailbox_id = $1 AND account_id = $2 AND expunged_at IS NULL AND s3_domain = $3 AND s3_localpart = $4`,
			sharedID, contributorID, contribDomain, contribLocal).Scan(&liveContributorRows))
		require.Equal(t, totalRows, liveContributorRows, "same-mailbox MOVE must preserve contributor ownership and S3 keys")
		require.NoError(t, rdb.QueryRowWithRetry(ctx,
			`SELECT count(*) FROM pending_uploads WHERE account_id = $1`, ownerID).Scan(&ownerPendingRows))
		require.Zero(t, ownerPendingRows, "same-mailbox MOVE must not queue pending_uploads for owner")
	})

	t.Run("MOVE concurrent rekey", func(t *testing.T) {
		var targetUID int64
		var oldHash string
		require.NoError(t, rdb.QueryRowWithRetry(ctx,
			`SELECT uid, content_hash FROM messages WHERE mailbox_id = $1 AND uploaded AND expunged_at IS NULL ORDER BY uid LIMIT 1`,
			sharedID).Scan(&targetUID, &oldHash))
		newHash := hashFor(totalRows + 99)
		require.NoError(t, s3storage.Put(helpers.NewS3Key(contribDomain, contribLocal, newHash), bytes.NewReader(payload), int64(len(payload))))

		// Hold contributor's content-rekey lock so IMAPSession.Move reads oldHash first,
		// then blocks at lockRekeySources while the concurrent rekey renames oldHash -> newHash.
		rekeyTx, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = rekeyTx.Rollback(ctx) }()
		var rekeyPID int
		require.NoError(t, rekeyTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&rekeyPID))
		_, err = rekeyTx.Exec(ctx, `SELECT pg_advisory_xact_lock($1::int4, hashint8($2::bigint))`,
			consts.SoraContentRekeyLockClassID, contributorID)
		require.NoError(t, err)

		moveDone := make(chan error, 1)
		go func() {
			_, err := cc.Move(imap.UIDSetNum(imap.UID(targetUID)), shared).Wait()
			moveDone <- err
		}()
		require.Eventually(t, func() bool {
			var waiting bool
			_ = pool.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))`,
				rekeyPID).Scan(&waiting)
			return waiting
		}, 5*time.Second, 10*time.Millisecond, "MOVE must wait on contributor rekey guard")

		_, err = rekeyTx.Exec(ctx,
			`UPDATE messages SET content_hash = $3 WHERE account_id = $1 AND content_hash = $2`,
			contributorID, oldHash, newHash)
		require.NoError(t, err)
		require.NoError(t, rekeyTx.Commit(ctx))

		require.NoError(t, <-moveDone, "same-mailbox MOVE must succeed even if import rekey renamed the legacy contributor row")
		require.Empty(t, fake.Keys(ownerPrefix), "same-mailbox MOVE after rekey must not touch owner S3 keys")
	})
}

