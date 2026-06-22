//go:build integration

package imap_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_FetchNotYetUploadedBody exercises the body-fetch path for a message that is
// still pending upload (uploaded=false) and whose body is NOT retrievable from this node:
// it is not on local disk (deleted to simulate cross-node staging) and not yet in S3
// (the server's S3 is an empty stub). This reproduces the production read-before-upload
// race where a client fetched a message in the same second it was created.
//
// It asserts two behaviours of the transient-vs-permanent classification:
//
//  1. While the upload is still pending, FETCH must fail with NO [UNAVAILABLE] so the
//     client retries — rather than returning an empty body that an automated consumer
//     could mistake for the real (empty) message and then delete.
//
//  2. Once the upload is no longer pending and the content is genuinely gone (no
//     pending_upload, not uploaded), FETCH must degrade gracefully to an empty body
//     (a successful command) so a permanently-broken message cannot loop the client
//     forever or break bulk webmail listings.
//
// It also confirms that a not-yet-uploaded message is NOT hidden from clients: its
// metadata is fetchable and it is visible in the mailbox.
func TestIMAP_FetchNotYetUploadedBody(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServerForUploadRace(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	msg := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Not yet uploaded\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"\r\n" +
		"This body lives only on local staging disk until the uploader runs.\r\n"

	uid := appendMessage(t, c, msg)

	// The message is uploaded=false (no worker ran), but it must still be visible:
	// a metadata-only FETCH does not need the body and must succeed, returning the row.
	// This guards against the temptation to hide uploaded=false rows. (Flags may be
	// empty on a freshly appended message — visibility is what we assert here.)
	metaMsgs, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{
		UID:   true,
		Flags: true,
	}).Collect()
	if err != nil {
		t.Fatalf("metadata FETCH of not-yet-uploaded message failed: %v", err)
	}
	if len(metaMsgs) != 1 {
		t.Fatalf("expected the not-yet-uploaded message to be visible, got %d messages (is the row hidden?)", len(metaMsgs))
	}

	// Remove the local staging file so this node can serve the body neither from disk
	// nor from S3 — exactly the cross-node read-before-upload race.
	stagedPath, contentHash := findSingleStagedFile(t, server.UploadPath)
	if err := os.Remove(stagedPath); err != nil {
		t.Fatalf("failed to remove staged file %s: %v", stagedPath, err)
	}

	bodySection := &imap.FetchItemBodySection{Peek: true}

	// 1. Upload still pending -> NO [UNAVAILABLE].
	_, err = c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{bodySection},
	}).Collect()
	if err == nil {
		t.Fatalf("expected FETCH to fail with NO [UNAVAILABLE] while upload pending, got success")
	}
	var imapErr *imap.Error
	if !errors.As(err, &imapErr) {
		t.Fatalf("expected *imap.Error, got %T: %v", err, err)
	}
	if imapErr.Code != imap.ResponseCodeUnavailable {
		t.Fatalf("expected response code %q, got %q (err: %v)", imap.ResponseCodeUnavailable, imapErr.Code, err)
	}

	// 2. Make the body permanently unrecoverable by removing only the pending_upload
	//    record (keep the message row, still uploaded=false). The body is now genuinely
	//    gone, so FETCH must degrade to an empty body rather than ask the client to retry.
	accountID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("failed to look up account id: %v", err)
	}
	deletePendingUploadOnly(t, server, contentHash, accountID)

	msgs, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{bodySection},
	}).Collect()
	if err != nil {
		t.Fatalf("expected graceful empty-body FETCH after content lost, got error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if body := msgs[0].FindBodySection(bodySection); len(body) != 0 {
		t.Fatalf("expected empty body for permanently-lost content, got %d bytes", len(body))
	}
}

// TestIMAP_FetchUploadedBodyS3Unavailable covers the uploaded-branch counterpart: a
// message that IS marked uploaded but whose body cannot be served because S3 is
// unreachable (the test S3 is an empty stub) and the local staging copy is gone. A
// transient S3 failure (anything other than 404/NoSuchKey) must yield NO [UNAVAILABLE]
// so the client retries, rather than an empty body served for what is really a
// still-present message.
func TestIMAP_FetchUploadedBodyS3Unavailable(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Standard setup uploads synchronously (uploaded=true) and keeps the staged file
	// on local disk (Noop cache). The server's S3 is an empty stub that fails on GET.
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	msg := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Uploaded but S3 down\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"\r\n" +
		"Body that lives in S3, which is currently unreachable.\r\n"
	uid := appendMessage(t, c, msg)
	server.WaitForUploads(t) // uploaded=true

	// Remove the local staging copy so the disk fallback misses; S3 (empty stub) then
	// fails with a non-404 error -> transient -> NO [UNAVAILABLE].
	stagedPath, _ := findSingleStagedFile(t, server.UploadPath)
	if err := os.Remove(stagedPath); err != nil {
		t.Fatalf("failed to remove staged file %s: %v", stagedPath, err)
	}

	_, err = c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{{Peek: true}},
	}).Collect()
	if err == nil {
		t.Fatalf("expected FETCH to fail with NO [UNAVAILABLE] while S3 unreachable, got success")
	}
	var imapErr *imap.Error
	if !errors.As(err, &imapErr) {
		t.Fatalf("expected *imap.Error, got %T: %v", err, err)
	}
	if imapErr.Code != imap.ResponseCodeUnavailable {
		t.Fatalf("expected response code %q, got %q (err: %v)", imap.ResponseCodeUnavailable, imapErr.Code, err)
	}
}

// findSingleStagedFile returns the path and base name (== content hash) of the single
// staged upload file under root. It fails if there is not exactly one.
func findSingleStagedFile(t *testing.T, root string) (path, contentHash string) {
	t.Helper()
	var found []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			found = append(found, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk upload dir %s: %v", root, err)
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly one staged file under %s, found %d: %v", root, len(found), found)
	}
	return found[0], filepath.Base(found[0])
}

// deletePendingUploadOnly removes the pending_uploads record for (contentHash, accountID)
// while leaving the message row intact (still uploaded=false), simulating a body whose
// upload was abandoned and whose content is genuinely lost.
func deletePendingUploadOnly(t *testing.T, server *common.TestServer, contentHash string, accountID int64) {
	t.Helper()
	ctx := context.Background()
	tx, err := server.ResilientDB.BeginTxWithRetry(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM pending_uploads WHERE content_hash = $1 AND account_id = $2`, contentHash, accountID); err != nil {
		t.Fatalf("delete pending_upload: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}
