//go:build integration

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// TestS3Importer_ForceReimportDryRunMatchesImport: `import s3` files every object in
// INBOX. --force-reimport imports an object even when the account already holds its
// message, so a message the account keeps only in another mailbox gets a copy in
// INBOX; a message INBOX already holds leaves nothing to import. The dry run must tell
// these apart from new messages, and the import must then do what the dry run said:
// it used to report every object as "IMPORT (new message)", and the import counted
// the object INBOX already held as failed ("message already exists").
func TestS3Importer_ForceReimportDryRunMatchesImport(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()
	ctx := context.Background()

	const email = "s3import-force@example.com"
	createSimpleTestAccount(t, rdb, email, "testpassword123")
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, email)
	require.NoError(t, err)
	require.NoError(t, rdb.CreateDefaultMailboxesWithRetry(ctx, accountID))
	inbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, consts.MailboxInbox)
	require.NoError(t, err)
	archive, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, consts.MailboxArchive)
	require.NoError(t, err)

	_, s3storage := common.NewFakeS3Storage(t)
	type object struct{ key, hash string }
	put := func(name string) object {
		body := []byte("From: sender@example.org\r\n" +
			"To: " + email + "\r\n" +
			"Subject: " + name + "\r\n" +
			"Date: Mon, 02 Nov 2026 10:00:00 +0000\r\n" +
			"Message-ID: <force-" + name + "@example.org>\r\n" +
			"\r\n" +
			"Body of " + name + ".\r\n")
		hash := helpers.HashContent(body)
		key := helpers.NewS3Key("example.com", "s3import-force", hash)
		require.NoError(t, s3storage.Put(key, bytes.NewReader(body), int64(len(body))))
		return object{key, hash}
	}
	inInbox := put("in-inbox")     // imported into INBOX by an earlier run
	inArchive := put("in-archive") // the account holds it in Archive only
	fresh := put("new")            // the account does not hold it
	all := []object{inInbox, inArchive, fresh}

	newImporter := func(t *testing.T, opts S3ImporterOptions, objects ...object) *S3Importer {
		t.Helper()
		opts.Email, opts.Workers, opts.CleanupDB, opts.InstanceID = email, 1, true, "test-instance"
		si, err := NewS3Importer(ctx, rdb, s3storage, opts)
		require.NoError(t, err)
		require.NoError(t, si.lookupAccount())
		t.Cleanup(func() { si.Close() })
		for _, o := range objects {
			_, err := si.db.Exec(`INSERT INTO s3_objects (key, size, last_modified, etag, domain, local_part, content_hash)
				VALUES (?, ?, ?, ?, ?, ?, ?)`, o.key, 100, "2026-11-02T10:00:00Z", "etag",
				"example.com", "s3import-force", o.hash)
			require.NoError(t, err)
		}
		si.totalObjects = int64(len(objects))
		return si
	}

	// The earlier run: inInbox is imported into INBOX.
	first := newImporter(t, S3ImporterOptions{}, inInbox)
	require.NoError(t, first.importFromS3())
	require.EqualValues(t, 1, first.importedMessages)

	// inArchive is in the account, filed in Archive (as by a Sieve fileinto).
	_, _, err = rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
		AccountID: accountID, MailboxID: archive.ID, MailboxName: archive.Name,
		S3Domain: "example.com", S3Localpart: "s3import-force",
		ContentHash: inArchive.hash, MessageID: "<force-in-archive@example.org>",
		InternalDate: time.Now(), Size: 100, Subject: "in-archive",
	}, db.PendingUpload{InstanceID: "test-instance", ContentHash: inArchive.hash, Size: 100, AccountID: accountID})
	require.NoError(t, err)
	require.NoError(t, rdb.CompleteS3UploadWithRetry(ctx, inArchive.hash, accountID, []string{inArchive.key}))

	// dryRun returns the action the dry run reports for each object, and its output.
	dryRun := func(t *testing.T, force bool) (map[object]string, string) {
		t.Helper()
		si := newImporter(t, S3ImporterOptions{DryRun: true, ForceReimport: force}, all...)
		out, err := runCapturingStdout(t, si.performDryRun)
		require.NoError(t, err)
		actions := map[object]string{}
		for _, block := range strings.Split(out, "\n\n") {
			for _, o := range all {
				if !strings.Contains(block, o.hash[:12]) {
					continue
				}
				i := strings.Index(block, "Action: ")
				require.GreaterOrEqual(t, i, 0, "no action for %s in:\n%s", o.key, block)
				actions[o] = strings.TrimSpace(strings.SplitN(block[i+len("Action: "):], "\n", 2)[0])
			}
		}
		return actions, out
	}
	actionOf := func(reported string) string { return strings.SplitN(reported, " ", 2)[0] }

	t.Run("dry run", func(t *testing.T) {
		actions, out := dryRun(t, false)
		require.Equal(t, "SKIP", actionOf(actions[inInbox]), out)
		require.Equal(t, "SKIP", actionOf(actions[inArchive]), out)
		require.Equal(t, "IMPORT (new message)", actions[fresh], out)
		require.Contains(t, out, "Would import: 1 messages")
		require.Contains(t, out, "Would skip: 2 messages")
	})

	t.Run("dry run --force-reimport", func(t *testing.T) {
		actions, out := dryRun(t, true)
		require.Equal(t, "SKIP", actionOf(actions[inInbox]), "the message INBOX holds:\n%s", out)
		require.Equal(t, "REIMPORT", actionOf(actions[inArchive]), "the message only Archive holds:\n%s", out)
		require.Equal(t, "IMPORT (new message)", actions[fresh], out)
		require.Contains(t, out, "Would import: 2 messages")
		require.Contains(t, out, "Would skip: 1 messages")
	})

	// The import does what the dry run --force-reimport says.
	t.Run("import --force-reimport", func(t *testing.T) {
		si := newImporter(t, S3ImporterOptions{ForceReimport: true}, all...)
		require.NoError(t, si.importFromS3())
		var failures []string
		rows, err := si.db.Query(`SELECT key, COALESCE(error_message, '') FROM s3_objects WHERE NOT processed OR NOT success`)
		require.NoError(t, err)
		for rows.Next() {
			var key, msg string
			require.NoError(t, rows.Scan(&key, &msg))
			failures = append(failures, key+": "+msg)
		}
		require.NoError(t, rows.Err())
		rows.Close()
		require.Empty(t, failures, "objects not imported or skipped")
		require.Equal(t, map[string]int64{"imported": 2, "skipped": 1, "failed": 0},
			map[string]int64{"imported": si.importedMessages, "skipped": si.skippedMessages, "failed": si.failedMessages})

		for _, tc := range []struct {
			o              object
			inbox, archive int
		}{
			{inInbox, 1, 0},   // not duplicated
			{inArchive, 1, 1}, // copied into INBOX, still in Archive
			{fresh, 1, 0},
		} {
			for mailboxID, want := range map[int64]int{inbox.ID: tc.inbox, archive.ID: tc.archive} {
				var n int
				require.NoError(t, rdb.QueryRowWithRetry(ctx,
					"SELECT COUNT(*) FROM messages WHERE account_id = $1 AND mailbox_id = $2 AND content_hash = $3 AND expunged_at IS NULL",
					accountID, mailboxID, tc.o.hash).Scan(&n))
				require.Equal(t, want, n, "live copies of %s in mailbox %d", tc.o.key, mailboxID)
			}
		}
	})
}
