//go:build integration

package imap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A cross-account COPY or MOVE of a body it reads as not uploaded links the body's staging
// file into the destination owner's spool directory, for the upload re-staged under the
// owner. The file is on this node only while the body was staged here and its upload is
// still pending. These tests cover the other two cases (issue #772): the body is staged on
// another backend, and the body was uploaded (and its file removed) after the read.

// crossAccountCommands runs COPY or MOVE of message 1 of the selected mailbox to dest.
var crossAccountCommands = map[string]func(c *imapclient.Client, dest string) error{
	"COPY": func(c *imapclient.Client, dest string) error {
		_, err := c.Copy(imap.SeqSetNum(1), dest).Wait()
		return err
	},
	"MOVE": func(c *imapclient.Client, dest string) error {
		_, err := c.Move(imap.SeqSetNum(1), dest).Wait()
		return err
	},
}

// inboxBody returns the id and content hash of the only live message in the account's INBOX.
func inboxBody(t *testing.T, server *common.TestServer, accountID int64) (id int64, contentHash string) {
	t.Helper()
	err := server.ResilientDB.QueryRowWithRetry(context.Background(), `
		SELECT m.id, m.content_hash
		FROM messages m
		JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE mb.account_id = $1 AND mb.name = 'INBOX' AND m.expunged_at IS NULL
	`, accountID).Scan(&id, &contentHash)
	require.NoError(t, err, "INBOX message of account %d", accountID)
	return id, contentHash
}

// liveMessageCount returns the number of live messages in the account's mailbox.
func liveMessageCount(t *testing.T, server *common.TestServer, accountID int64, mailbox string) int {
	t.Helper()
	var n int
	err := server.ResilientDB.QueryRowWithRetry(context.Background(), `
		SELECT COUNT(*)
		FROM messages m
		JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE mb.account_id = $1 AND mb.name = $2 AND m.expunged_at IS NULL
	`, accountID, mailbox).Scan(&n)
	require.NoError(t, err)
	return n
}

// waitUploaded drains the server's upload queue until message id is uploaded. A failed
// attempt is leased again only after the worker's retry interval, so one drain may not do.
func waitUploaded(t *testing.T, server *common.TestServer, id int64) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		server.WaitForUploads(t)
		var uploaded bool
		err := server.ResilientDB.QueryRowWithRetry(context.Background(),
			`SELECT uploaded FROM messages WHERE id = $1`, id).Scan(&uploaded)
		require.NoError(t, err)
		if uploaded {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("message %d still not uploaded", id)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ownerFetchesMarker logs in as the owner and requires the single message of mailbox to
// carry marker.
func ownerFetchesMarker(t *testing.T, server *common.TestServer, ownerEmail, mailbox, marker string) {
	t.Helper()
	oc, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer oc.Logout()
	require.NoError(t, oc.Login(ownerEmail, "owner-pass-123").Wait())
	mbox, err := oc.Select(mailbox, nil).Wait()
	require.NoError(t, err)
	require.Equal(t, uint32(1), mbox.NumMessages)
	assert.Contains(t, string(fetchFullBody(t, oc, 1)), marker, "owner FETCH of the copied body")
}

// TestCrossAccountCopyMove_BodyPendingOnAnotherNode: the contributor's body was staged on
// another backend and its upload is still pending there, so it is neither in this node's
// spool nor in S3. The command must be refused as retryable (NO [UNAVAILABLE]), with no
// spool path in the response and nothing changed, and must go through once that upload
// has finished.
func TestCrossAccountCopyMove_BodyPendingOnAnotherNode(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	for _, command := range []string{"COPY", "MOVE"} {
		t.Run(command, func(t *testing.T) {
			run := crossAccountCommands[command]
			server, contributor, fake := common.SetupIMAPServerWithRealS3(t)
			defer server.Close()
			ctx := context.Background()

			ownerEmail, ownerID, shared := createOwnerWithSharedMailbox(t, server, contributor.Email, "lrswi")
			contributorID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, contributor.Email)
			require.NoError(t, err)

			cc, err := imapclient.DialInsecure(server.Address, nil)
			require.NoError(t, err)
			defer cc.Logout()
			require.NoError(t, cc.Login(contributor.Email, contributor.Password).Wait())

			fake.FailPuts(true) // the upload stalls
			marker := "pending elsewhere marker " + command
			appendTo(t, cc, "INBOX", "Pending elsewhere", marker)
			require.Equal(t, 0, fake.ObjectCount(), "the upload must still be pending")
			id, hash := inboxBody(t, server, contributorID)

			// Make it another backend's body: its staging file leaves this node's spool and
			// its pending upload belongs to that backend, so this node's worker leaves it be.
			stagingPath := filepath.Join(server.UploadPath, strconv.FormatInt(contributorID, 10), hash)
			elsewhere := filepath.Join(t.TempDir(), hash)
			require.NoError(t, os.Rename(stagingPath, elsewhere))
			_, err = server.ResilientDB.ExecWithRetry(ctx,
				`UPDATE pending_uploads SET instance_id = 'other-node' WHERE content_hash = $1 AND account_id = $2`,
				hash, contributorID)
			require.NoError(t, err)

			_, err = cc.Select("INBOX", nil).Wait()
			require.NoError(t, err)
			err = run(cc, shared)
			var imapErr *imap.Error
			require.True(t, errors.As(err, &imapErr), "%s of a body pending on another node: got %v, want NO [UNAVAILABLE]", command, err)
			assert.Equal(t, imap.StatusResponseTypeNo, imapErr.Type)
			assert.Equal(t, imap.ResponseCodeUnavailable, imapErr.Code,
				"%s of a body pending on another node must be retryable, got [%s] %q", command, imapErr.Code, imapErr.Text)
			assert.NotContains(t, imapErr.Text, server.UploadPath, "the response must not name the spool path")
			assert.Equal(t, 1, liveMessageCount(t, server, contributorID, "INBOX"), "the source message must stay")
			assert.Equal(t, 0, liveMessageCount(t, server, ownerID, shared), "nothing may reach the destination")

			// The other backend finishes the upload; the retry goes through.
			require.NoError(t, os.Rename(elsewhere, stagingPath))
			_, err = server.ResilientDB.ExecWithRetry(ctx,
				`UPDATE pending_uploads SET instance_id = 'localhost' WHERE content_hash = $1 AND account_id = $2`,
				hash, contributorID)
			require.NoError(t, err)
			fake.FailPuts(false)
			waitUploaded(t, server, id)

			require.NoError(t, run(cc, shared), "%s retried after the upload finished", command)
			ownerParts := strings.SplitN(ownerEmail, "@", 2)
			assert.NotEmpty(t, fake.Keys(helpers.NewS3Key(ownerParts[1], ownerParts[0], hash)),
				"the body must be in S3 under the owner's key")
			ownerFetchesMarker(t, server, ownerEmail, shared, marker)
		})
	}
}

// TestCrossAccountCopyMove_BodyUploadedAfterRead: the command reads the contributor's body
// as not uploaded although its upload has already finished and removed the staging file
// (a read that raced the upload, or one served by a lagging replica). The body is in S3,
// so the command must copy it there to the owner's key instead of failing on the missing
// file.
func TestCrossAccountCopyMove_BodyUploadedAfterRead(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	for _, command := range []string{"COPY", "MOVE"} {
		t.Run(command, func(t *testing.T) {
			run := crossAccountCommands[command]
			server, contributor, fake := common.SetupIMAPServerWithRealS3(t)
			defer server.Close()
			ctx := context.Background()

			ownerEmail, ownerID, shared := createOwnerWithSharedMailbox(t, server, contributor.Email, "lrswi")
			contributorID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, contributor.Email)
			require.NoError(t, err)

			cc, err := imapclient.DialInsecure(server.Address, nil)
			require.NoError(t, err)
			defer cc.Logout()
			require.NoError(t, cc.Login(contributor.Email, contributor.Password).Wait())

			marker := "uploaded after read marker " + command
			appendTo(t, cc, "INBOX", "Uploaded after read", marker)
			require.Equal(t, 1, fake.ObjectCount(), "APPEND must have uploaded the body")
			id, hash := inboxBody(t, server, contributorID)
			_, err = os.Stat(filepath.Join(server.UploadPath, strconv.FormatInt(contributorID, 10), hash))
			require.True(t, os.IsNotExist(err), "the upload must have removed the staging file, got %v", err)

			// What the command reads: the body not uploaded yet.
			_, err = server.ResilientDB.ExecWithRetry(ctx, `UPDATE messages SET uploaded = FALSE WHERE id = $1`, id)
			require.NoError(t, err)

			_, err = cc.Select("INBOX", nil).Wait()
			require.NoError(t, err)
			require.NoError(t, run(cc, shared), "%s of a body uploaded after the read", command)

			ownerParts := strings.SplitN(ownerEmail, "@", 2)
			assert.NotEmpty(t, fake.Keys(helpers.NewS3Key(ownerParts[1], ownerParts[0], hash)),
				"the body must be in S3 under the owner's key")
			assert.Equal(t, 1, liveMessageCount(t, server, ownerID, shared))

			// The command made the object exist under the owner's key and marked the owner's
			// row uploaded for it, rather than taking the source's stale flag.
			server.WaitForUploads(t)
			ownerFetchesMarker(t, server, ownerEmail, shared, marker)
		})
	}
}

// TestCrossAccountCopyMove_SpoolFaultKeepsPathOutOfResponse: the body is staged on this
// node but cannot be linked into the owner's spool directory. The command fails, but the
// response must not name files in the spool.
func TestCrossAccountCopyMove_SpoolFaultKeepsPathOutOfResponse(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	for _, command := range []string{"COPY", "MOVE"} {
		t.Run(command, func(t *testing.T) {
			run := crossAccountCommands[command]
			server, contributor, fake := common.SetupIMAPServerWithRealS3(t)
			defer server.Close()
			ctx := context.Background()

			_, ownerID, shared := createOwnerWithSharedMailbox(t, server, contributor.Email, "lrswi")
			contributorID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, contributor.Email)
			require.NoError(t, err)

			cc, err := imapclient.DialInsecure(server.Address, nil)
			require.NoError(t, err)
			defer cc.Logout()
			require.NoError(t, cc.Login(contributor.Email, contributor.Password).Wait())

			fake.FailPuts(true) // the body stays staged on this node
			appendTo(t, cc, "INBOX", "Spool fault", "spool fault marker "+command)

			ownerDir := filepath.Join(server.UploadPath, strconv.FormatInt(ownerID, 10))
			require.NoError(t, os.MkdirAll(ownerDir, 0o755))
			require.NoError(t, os.Chmod(ownerDir, 0o500))
			defer os.Chmod(ownerDir, 0o755)

			_, err = cc.Select("INBOX", nil).Wait()
			require.NoError(t, err)
			err = run(cc, shared)
			var imapErr *imap.Error
			require.True(t, errors.As(err, &imapErr), "%s with an unwritable owner spool: got %v, want NO", command, err)
			assert.Equal(t, imap.StatusResponseTypeNo, imapErr.Type)
			assert.NotContains(t, imapErr.Text, server.UploadPath, "the response must not name the spool path")
			assert.Equal(t, 1, liveMessageCount(t, server, contributorID, "INBOX"), "the source message must stay")
			assert.Equal(t, 0, liveMessageCount(t, server, ownerID, shared), "nothing may reach the destination")
		})
	}
}
