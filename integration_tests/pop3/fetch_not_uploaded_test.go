//go:build integration

package pop3_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// TestPOP3_RetrNotYetUploadedBody is the POP3 counterpart to the IMAP not-yet-uploaded
// body-fetch test. It reproduces the production read-before-upload race for a message
// whose body is neither on this node's local disk (deleted to simulate cross-node
// staging) nor yet in S3 (the server's S3 is an empty stub), and asserts the
// transient-vs-permanent classification:
//
//  1. While the upload is still pending, RETR must return -ERR [SYS/TEMP] ... try again
//     later — so a well-behaved client retries and does NOT DELE — rather than the
//     permanent-sounding -ERR Message not available.
//
//  2. Once the content is genuinely gone (no pending_upload, not uploaded), RETR must
//     return -ERR Message not available.
func TestPOP3_RetrNotYetUploadedBody(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := setupPOP3RaceServer(t)
	defer server.Close()

	msg := "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Not yet uploaded\r\n\r\nBody line\r\n"
	contentHash, accountID := stageMessageNoUpload(t, server, account.Email, msg)

	// Remove the staged file so the body can be served neither from local disk nor S3 —
	// exactly the cross-node read-before-upload race.
	stagedPath := server.Uploader.FilePath(contentHash, accountID)
	if err := os.Remove(stagedPath); err != nil {
		t.Fatalf("failed to remove staged file %s: %v", stagedPath, err)
	}

	conn, err := net.Dial("tcp", server.TestServer.Address)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	reader, writer := loginClient(t, conn, account.Email, account.Password)

	// 1. Upload still pending -> transient: -ERR [SYS/TEMP] ... try again later.
	fmt.Fprintf(writer, "RETR 1\r\n")
	writer.Flush()
	resp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read RETR response: %v", err)
	}
	if !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("expected -ERR while upload pending, got: %q", resp)
	}
	if !strings.Contains(resp, "SYS/TEMP") {
		t.Fatalf("expected a transient [SYS/TEMP] try-again-later response while upload pending, got: %q", resp)
	}

	// 2. Make the content permanently unrecoverable by removing only the pending_upload
	//    record (the message row stays, uploaded=false). RETR must now report the message
	//    as not available rather than asking the client to retry forever.
	deletePendingUploadOnly(t, server.TestServer, contentHash, accountID)

	fmt.Fprintf(writer, "RETR 1\r\n")
	writer.Flush()
	resp, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read second RETR response: %v", err)
	}
	if !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("expected -ERR after content lost, got: %q", resp)
	}
	if !strings.Contains(resp, "Message not available") {
		t.Fatalf("expected permanent 'Message not available' after content lost, got: %q", resp)
	}
}

// TestPOP3_RetrUploadedBodyS3Unavailable is the POP3 uploaded-branch counterpart: a
// message marked uploaded whose body cannot be served because S3 is unreachable (empty
// stub) and the local staging copy is gone. A transient S3 failure (not 404/NoSuchKey)
// must yield -ERR [SYS/TEMP] ... try again later rather than -ERR Message not available.
func TestPOP3_RetrUploadedBodyS3Unavailable(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Sync-upload setup: the message is marked uploaded=true and its staged file is kept
	// on local disk by the Noop cache. The server's S3 is an empty stub that fails on GET.
	server, account := SetupPOP3ServerWithUploader(t)
	defer server.Close()

	msg := "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Uploaded but S3 down\r\n\r\nBody line\r\n"
	tddAppendMessage(t, server, account.Email, msg)

	// Remove the staged file so the disk fallback misses; S3 (empty stub) then fails with
	// a non-404 error -> transient -> -ERR [SYS/TEMP].
	stagedPath := findSingleStagedFile(t, server.TempDir)
	if err := os.Remove(stagedPath); err != nil {
		t.Fatalf("failed to remove staged file %s: %v", stagedPath, err)
	}

	conn, err := net.Dial("tcp", server.TestServer.Address)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	reader, writer := loginClient(t, conn, account.Email, account.Password)
	fmt.Fprintf(writer, "RETR 1\r\n")
	writer.Flush()
	resp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read RETR response: %v", err)
	}
	if !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("expected -ERR while S3 unreachable, got: %q", resp)
	}
	if !strings.Contains(resp, "SYS/TEMP") {
		t.Fatalf("expected a transient [SYS/TEMP] try-again-later response while S3 unreachable, got: %q", resp)
	}
}

// findSingleStagedFile returns the path of the single staged upload file under root.
// It fails if there is not exactly one.
func findSingleStagedFile(t *testing.T, root string) string {
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
	return found[0]
}

// setupPOP3RaceServer builds a POP3 server whose upload worker is constructed but NOT
// started and NOT in synchronous mode, so staged messages remain uploaded=false (no
// worker processes the queue). Mirrors SetupPOP3ServerWithUploader minus EnableSyncUpload/Start.
func setupPOP3RaceServer(t *testing.T) (*TDDTestServer, common.TestAccount) {
	t.Helper()
	return setupPOP3RaceServerWithS3(t, &storage.S3Storage{})
}

// setupPOP3RaceServerWithS3 is setupPOP3RaceServer with a caller-provided S3 backend, so a
// test can script GET responses (e.g. NoSuchKey then a body via a fake S3 endpoint) to
// exercise the not-yet-uploaded retry/timing path end to end.
func setupPOP3RaceServerWithS3(t *testing.T, s3Storage *storage.S3Storage) (*TDDTestServer, common.TestAccount) {
	t.Helper()

	baseServer, account := common.SetupPOP3Server(t)
	if basePOP3, ok := baseServer.Server.(*pop3.POP3Server); ok {
		basePOP3.Close()
	} else {
		t.Fatalf("baseServer.Server is not *pop3.POP3Server")
	}

	tempDir, err := os.MkdirTemp("", "sora-pop3-race-upload-*")
	if err != nil {
		baseServer.Close()
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	errCh := make(chan error, 1)
	uploadWorker, err := uploader.NewWithS3Interface(
		tempDir,
		10,
		1,
		3,
		time.Second,
		0,
		"test-instance", // must match stageMessageNoUpload's PendingUpload InstanceID
		baseServer.ResilientDB,
		&common.NoopUploaderS3{},
		&common.NoopUploaderCache{},
		errCh,
	)
	if err != nil {
		os.RemoveAll(tempDir)
		baseServer.Close()
		t.Fatalf("Failed to create upload worker: %v", err)
	}
	// Deliberately NOT EnableSyncUpload()/Start(): uploads stay pending so messages
	// remain uploaded=false with their bodies only on local staging disk.

	server, err := pop3.New(
		context.Background(),
		"test",
		"localhost",
		baseServer.Address,
		s3Storage,
		baseServer.ResilientDB,
		uploadWorker,
		nil,
		pop3.POP3ServerOptions{InsecureAuth: true},
	)
	if err != nil {
		uploadWorker.Stop()
		os.RemoveAll(tempDir)
		baseServer.Close()
		t.Fatalf("Failed to create POP3 server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		server.Start(errChan)
	}()
	time.Sleep(100 * time.Millisecond)

	baseServer.Server = server

	return &TDDTestServer{
		TestServer: baseServer,
		POP3Server: server,
		Uploader:   uploadWorker,
		TempDir:    tempDir,
	}, account
}

// stageMessageNoUpload stages a message body on local disk and inserts the message row
// plus its pending_upload, WITHOUT notifying the (unstarted) worker — so the message
// stays uploaded=false. Returns the content hash and account ID.
func stageMessageNoUpload(t *testing.T, server *TDDTestServer, email, msg string) (string, int64) {
	t.Helper()

	accountID, err := server.TestServer.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}
	inbox, err := server.TestServer.ResilientDB.GetMailboxByNameWithRetry(context.Background(), accountID, "INBOX")
	if err != nil {
		t.Fatalf("Failed to get INBOX: %v", err)
	}

	contentHash := fmt.Sprintf("%064x", time.Now().UnixNano())
	if _, err := server.Uploader.StoreLocally(contentHash, accountID, []byte(msg)); err != nil {
		t.Fatalf("Failed to store message body locally: %v", err)
	}

	_, _, err = server.TestServer.ResilientDB.InsertMessageWithRetry(context.Background(),
		&db.InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     inbox.ID,
			S3Domain:      "example.com",
			S3Localpart:   "test",
			MailboxName:   "INBOX",
			ContentHash:   contentHash,
			MessageID:     fmt.Sprintf("<%d@test.com>", time.Now().UnixNano()),
			Flags:         []imap.Flag{},
			InternalDate:  time.Now(),
			Size:          int64(len(msg)),
			Subject:       "Test",
			PlaintextBody: msg,
			SentDate:      time.Now(),
		},
		db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  "test-instance",
			Size:        int64(len(msg)),
			AccountID:   accountID,
		})
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}
	// Deliberately NOT calling NotifyUploadQueued: the message stays uploaded=false.
	return contentHash, accountID
}

// deletePendingUploadOnly removes the pending_uploads record while leaving the message
// row intact (still uploaded=false), simulating a body whose upload was abandoned and
// whose content is genuinely lost.
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
