package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func setupSoftDeletedAccountForDependentsTest(t *testing.T, db *Database, deletedAt time.Time, tag string) (accountID, inboxID int64) {
	t.Helper()
	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	accountID, err = db.CreateAccount(ctx, tx, CreateAccountRequest{
		Email:     fmt.Sprintf("hard_delete_%s_%d@example.com", tag, time.Now().UnixNano()),
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "INBOX", nil))
	_, err = tx.Exec(ctx, `UPDATE accounts SET deleted_at = $2 WHERE id = $1`, accountID, deletedAt)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	inbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)

	// A test that fails before finalization must not leave soft-deleted accounts at the
	// marker, where subsequent grace-period queries would pick them up.
	t.Cleanup(func() {
		for _, q := range []string{
			`DELETE FROM messages_fts_v2 WHERE account_id = $1`,
			`DELETE FROM messages WHERE account_id = $1`,
			`DELETE FROM pending_uploads WHERE account_id = $1`,
			`DELETE FROM sieve_scripts WHERE account_id = $1`,
			`DELETE FROM vacation_responses WHERE account_id = $1`,
			`DELETE FROM mailboxes WHERE account_id = $1`,
			`DELETE FROM credentials WHERE account_id = $1`,
			`DELETE FROM accounts WHERE id = $1`,
		} {
			if _, err := db.GetWritePool().Exec(context.Background(), q, accountID); err != nil {
				t.Errorf("cleanup of account %d: %s: %v", accountID, q, err)
			}
		}
	})

	return accountID, inbox.ID
}

func insertUnuploadedMessageForDependentsTest(t *testing.T, db *Database, accountID, mailboxID int64, hash string, createdAt time.Time) {
	t.Helper()
	ctx := context.Background()
	_, err := db.GetWritePool().Exec(ctx, `
		WITH inserted AS (
			INSERT INTO messages (
				account_id, mailbox_id, uid, content_hash, sent_date, internal_date,
				size, uploaded, s3_domain, s3_localpart, message_id, body_structure,
				recipients_json, created_modseq, created_at
			)
			VALUES ($1, $2, 1, $3, now(), now(), 100, FALSE, 'example.com', $4, $5, 'body', '[]', nextval('messages_modseq'), $6)
			RETURNING id, mailbox_id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags)
		SELECT id, mailbox_id, 0 FROM inserted
	`, accountID, mailboxID, hash, fmt.Sprintf("user-%d", accountID), "<"+hash+"@example.com>", createdAt)
	require.NoError(t, err)
}

// TestHardDeleteInterruptedBeforeDependentsStepResumes stops the cleaner's chunked hard
// delete right after the step that removed the account's last mailbox (which still returns
// done = false, leaving deleteAccountDependents for the next step). ListSoftDeletedAccountsForHardDelete
// must list the account again so the next cycle removes its unleased pending_uploads,
// sieve_scripts, and vacation_responses; once those are gone, the account is not listed
// again and CleanupFailedUploads can reap its expunged non-uploaded message so finalization
// completes.
func TestHardDeleteInterruptedBeforeDependentsStepResumes(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(db.Close)
	ctx := context.Background()

	marker := finalizeTestMarker(t, db)
	grace := time.Since(marker.Add(time.Minute))
	const (
		failedUploadGrace = 24 * time.Hour
		maxAttempts       = 5
		liveness          = time.Hour
	)

	accountID, inboxID := setupSoftDeletedAccountForDependentsTest(t, db, marker, "deps")
	ts := time.Now().UnixNano()
	hash := fmt.Sprintf("hard_delete_deps_hash_%d", ts)
	instanceID := fmt.Sprintf("hard-delete-deps-instance-%d", ts)
	insertUnuploadedMessageForDependentsTest(t, db, accountID, inboxID, hash, time.Now().Add(-25*time.Hour))

	_, err := db.GetWritePool().Exec(ctx, `
		INSERT INTO pending_uploads (account_id, content_hash, size, instance_id, attempts, last_attempt)
		VALUES ($1, $2, 100, $3, 0, NULL)
	`, accountID, hash, instanceID)
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, `
		INSERT INTO sieve_scripts (account_id, active, name, script)
		VALUES ($1, TRUE, 'main', 'keep;')
	`, accountID)
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, `
		INSERT INTO vacation_responses (account_id, sender_address, response_identity, response_date)
		VALUES ($1, 'sender@example.com', 'v1', now())
	`, accountID)
	require.NoError(t, err)

	// Also cover accounts whose messages were already uploaded (no pending_uploads), where
	// only sieve_scripts or vacation_responses remain after the last mailbox is removed.
	sieveOnlyID, _ := setupSoftDeletedAccountForDependentsTest(t, db, marker.Add(time.Second), "sieve")
	_, err = db.GetWritePool().Exec(ctx, `
		INSERT INTO sieve_scripts (account_id, active, name, script)
		VALUES ($1, TRUE, 'only', 'keep;')
	`, sieveOnlyID)
	require.NoError(t, err)

	vacationOnlyID, _ := setupSoftDeletedAccountForDependentsTest(t, db, marker.Add(2*time.Second), "vacation")
	_, err = db.GetWritePool().Exec(ctx, `
		INSERT INTO vacation_responses (account_id, sender_address, response_identity, response_date)
		VALUES ($1, 'sender@example.com', 'v1', now())
	`, vacationOnlyID)
	require.NoError(t, err)

	listed := func() []int64 {
		ids, err := db.ListSoftDeletedAccountsForHardDelete(ctx, grace, 100000)
		require.NoError(t, err)
		return ids
	}
	step := func(id int64) bool {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		done, err := db.HardDeleteAccountStep(ctx, tx, id, 1)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return done
	}
	ownedMailboxes := func(id int64) int {
		var n int
		require.NoError(t, db.GetWritePool().QueryRow(ctx,
			`SELECT count(*) FROM mailboxes WHERE account_id = $1`, id).Scan(&n))
		return n
	}
	dependentCounts := func(id int64) (pending, sieve, vacation, messages int) {
		require.NoError(t, db.GetWritePool().QueryRow(ctx, `
			SELECT (SELECT count(*) FROM pending_uploads WHERE account_id = $1),
			       (SELECT count(*) FROM sieve_scripts WHERE account_id = $1),
			       (SELECT count(*) FROM vacation_responses WHERE account_id = $1),
			       (SELECT count(*) FROM messages WHERE account_id = $1)
		`, id).Scan(&pending, &sieve, &vacation, &messages))
		return
	}
	runCleanupFailedUploads := func() {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = db.CleanupFailedUploads(ctx, tx, failedUploadGrace, maxAttempts, liveness)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	}

	// Step each account until its last mailbox is removed, stopping right before the
	// subsequent deleteAccountDependents step.
	for _, id := range []int64{accountID, sieveOnlyID, vacationOnlyID} {
		for steps := 0; ownedMailboxes(id) > 0; steps++ {
			require.Less(t, steps, 20, "mailbox purge steps must terminate")
			require.False(t, step(id), "the step that removes the last mailbox returns done = false")
		}
	}

	pending, sieve, vacation, messages := dependentCounts(accountID)
	require.Equal(t, 1, pending, "precondition: unleased pending_uploads row remains before dependents step")
	require.Equal(t, 1, sieve, "precondition: sieve_scripts row remains before dependents step")
	require.Equal(t, 1, vacation, "precondition: vacation_responses row remains before dependents step")
	require.Equal(t, 1, messages, "precondition: expunged non-uploaded message remains")

	// While the unleased pending_uploads row remains (attempts = 0, last_attempt = NULL on
	// an instance with no heartbeat row), CleanupFailedUploads treats it as live and keeps
	// the message, blocking finalization.
	runCleanupFailedUploads()
	_, _, _, messages = dependentCounts(accountID)
	require.Equal(t, 1, messages, "CleanupFailedUploads spares the message while the pending upload row stands")

	ids := listed()
	require.Contains(t, ids, accountID,
		"an interrupted hard delete with unleased pending_uploads/dependents left must be listed again")
	require.Contains(t, ids, sieveOnlyID,
		"an interrupted hard delete with sieve_scripts left must be listed again")
	require.Contains(t, ids, vacationOnlyID,
		"an interrupted hard delete with vacation_responses left must be listed again")

	// Next cycle runs the remaining dependents step to completion.
	for _, id := range []int64{accountID, sieveOnlyID, vacationOnlyID} {
		require.True(t, step(id), "the dependents step finishes the hard delete")
	}

	pending, sieve, vacation, messages = dependentCounts(accountID)
	require.Equal(t, 0, pending, "unleased pending_uploads row removed")
	require.Equal(t, 0, sieve, "sieve_scripts row removed")
	require.Equal(t, 0, vacation, "vacation_responses row removed")
	require.Equal(t, 1, messages, "expunged message stays until reaped")
	_, sieveOnlyCount, _, _ := dependentCounts(sieveOnlyID)
	require.Equal(t, 0, sieveOnlyCount)
	_, _, vacationOnlyCount, _ := dependentCounts(vacationOnlyID)
	require.Equal(t, 0, vacationOnlyCount)

	ids = listed()
	require.NotContains(t, ids, accountID,
		"a finished account is not listed again even while its expunged message awaits reaping")
	require.NotContains(t, ids, sieveOnlyID)
	require.NotContains(t, ids, vacationOnlyID)

	// Once the pending_uploads row is gone, CleanupFailedUploads reaps the expunged
	// non-uploaded message and the account becomes finalizable.
	runCleanupFailedUploads()
	_, _, _, messages = dependentCounts(accountID)
	require.Equal(t, 0, messages, "CleanupFailedUploads reaps the expunged non-uploaded message once its pending row is gone")

	dangling, err := db.GetDanglingAccountsForFinalDeletion(ctx, 100000, marker.Add(time.Minute))
	require.NoError(t, err)
	require.Contains(t, dangling, accountID, "account is now eligible for final deletion")

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	n, err := db.FinalizeAccountDeletions(ctx, tx, []int64{accountID})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	require.Equal(t, int64(1), n)
}

// TestHardDeleteReleasedOrExpiredUploadLeaseResumes covers an upload that held a live lease
// (PassS3WriteGate) while HardDeleteAccountStep ran to completion, so deleteAccountDependents
// spared its pending_uploads row. While the lease is live, ListSoftDeletedAccountsForHardDelete
// must not re-list the account; once the lease is released (ReleasePendingUploadLease) or
// expires (lease_until < now()), ListSoftDeletedAccountsForHardDelete must re-list the
// account so the next HardDeleteAccountStep deletes the now-unleased pending_uploads row.
func TestHardDeleteReleasedOrExpiredUploadLeaseResumes(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(db.Close)
	ctx := context.Background()

	const (
		failedUploadGrace = 24 * time.Hour
		maxAttempts       = 5
		liveness          = time.Hour
	)

	cases := []struct {
		name     string
		tag      string
		endLease func(t *testing.T, pendingID int64, owner string)
	}{
		{
			name: "released_lease",
			tag:  "released",
			endLease: func(t *testing.T, pendingID int64, owner string) {
				t.Helper()
				require.NoError(t, db.ReleasePendingUploadLease(ctx, pendingID, owner))
			},
		},
		{
			name: "expired_lease",
			tag:  "expired",
			endLease: func(t *testing.T, pendingID int64, _ string) {
				t.Helper()
				_, err := db.GetWritePool().Exec(ctx,
					`UPDATE pending_uploads SET lease_until = now() - interval '1 second' WHERE id = $1`,
					pendingID)
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marker := finalizeTestMarker(t, db)
			grace := time.Since(marker.Add(time.Minute))

			accountID, inboxID := setupSoftDeletedAccountForDependentsTest(t, db, marker, tc.tag)
			ts := time.Now().UnixNano()
			hash := fmt.Sprintf("hard_delete_%s_hash_%d", tc.tag, ts)
			instanceID := fmt.Sprintf("hard-delete-%s-instance-%d", tc.tag, ts)
			owner := fmt.Sprintf("hard-delete-%s-owner-%d", tc.tag, ts)

			insertUnuploadedMessageForDependentsTest(t, db, accountID, inboxID, hash, time.Now().Add(-25*time.Hour))

			var pendingID int64
			err := db.GetWritePool().QueryRow(ctx, `
				INSERT INTO pending_uploads (account_id, content_hash, size, instance_id, attempts, last_attempt)
				VALUES ($1, $2, 100, $3, 0, NULL)
				RETURNING id
			`, accountID, hash, instanceID).Scan(&pendingID)
			require.NoError(t, err)

			gate, err := db.PassS3WriteGate(ctx, pendingID, accountID, hash, owner, time.Minute)
			require.NoError(t, err)
			require.Equal(t, S3WriteOpen, gate)

			listed := func() []int64 {
				ids, err := db.ListSoftDeletedAccountsForHardDelete(ctx, grace, 100000)
				require.NoError(t, err)
				return ids
			}
			step := func() bool {
				tx, err := db.GetWritePool().Begin(ctx)
				require.NoError(t, err)
				defer tx.Rollback(ctx)
				done, err := db.HardDeleteAccountStep(ctx, tx, accountID, 1)
				require.NoError(t, err)
				require.NoError(t, tx.Commit(ctx))
				return done
			}
			counts := func() (pending, messages int) {
				require.NoError(t, db.GetWritePool().QueryRow(ctx, `
					SELECT (SELECT count(*) FROM pending_uploads WHERE account_id = $1),
					       (SELECT count(*) FROM messages WHERE account_id = $1)
				`, accountID).Scan(&pending, &messages))
				return
			}
			runCleanupFailedUploads := func() {
				tx, err := db.GetWritePool().Begin(ctx)
				require.NoError(t, err)
				defer tx.Rollback(ctx)
				_, err = db.CleanupFailedUploads(ctx, tx, failedUploadGrace, maxAttempts, liveness)
				require.NoError(t, err)
				require.NoError(t, tx.Commit(ctx))
			}

			for steps := 0; !step(); steps++ {
				require.Less(t, steps, 20, "hard delete must terminate")
			}

			pending, messages := counts()
			require.Equal(t, 1, pending, "leased pending_uploads row is spared while upload is in flight")
			require.Equal(t, 1, messages)
			require.NotContains(t, listed(), accountID,
				"an account whose only remaining pending upload has a live lease must not be re-polled")

			// The upload fails without finishing (releasing its lease) or stalls past lease_until.
			tc.endLease(t, pendingID, owner)

			// Without removing the now-unleased pending_uploads row, CleanupFailedUploads
			// still considers the upload live and leaves the expunged message in place.
			runCleanupFailedUploads()
			_, messages = counts()
			require.Equal(t, 1, messages, "CleanupFailedUploads spares the message while the unleased pending row remains")
			dangling, err := db.GetDanglingAccountsForFinalDeletion(ctx, 100000, marker.Add(time.Minute))
			require.NoError(t, err)
			require.NotContains(t, dangling, accountID)

			require.Contains(t, listed(), accountID,
				"once the upload lease ends, the account must be re-listed to delete the unleased pending_uploads row")

			require.True(t, step(), "HardDeleteAccountStep deletes the now-unleased pending_uploads row")
			pending, messages = counts()
			require.Equal(t, 0, pending, "unleased pending_uploads row deleted")
			require.Equal(t, 1, messages, "expunged message remains until reaped")
			require.NotContains(t, listed(), accountID,
				"once the pending_uploads row is gone, the account is not listed again")

			runCleanupFailedUploads()
			_, messages = counts()
			require.Equal(t, 0, messages, "CleanupFailedUploads now reaps the expunged non-uploaded message")

			dangling, err = db.GetDanglingAccountsForFinalDeletion(ctx, 100000, marker.Add(time.Minute))
			require.NoError(t, err)
			require.Contains(t, dangling, accountID, "account is now eligible for final deletion")

			tx, err := db.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)
			n, err := db.FinalizeAccountDeletions(ctx, tx, []int64{accountID})
			require.NoError(t, err)
			require.NoError(t, tx.Commit(ctx))
			require.Equal(t, int64(1), n)
		})
	}
}
