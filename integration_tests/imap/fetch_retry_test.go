//go:build integration

package imap_test

import (
	"bytes"
	"os"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func loginSelectInbox(t *testing.T, addr, email, password string) *imapclient.Client {
	t.Helper()
	c, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	if err := c.Login(email, password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	return c
}

// TestIMAP_FetchNotYetUploaded_RetriesThenServesBody proves the not-yet-uploaded retry
// actually waits out a NoSuchKey and then serves the real body once the object lands —
// the timing/retry path the empty-stub tests can't reach.
func TestIMAP_FetchNotYetUploaded_RetriesThenServesBody(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	fake, s3 := common.NewScriptedS3(t, 1) // first GET → NoSuchKey, then the body lands
	server, account := common.SetupIMAPServerForUploadRaceWithS3(t, s3)
	defer server.Close()

	c := loginSelectInbox(t, server.Address, account.Email, account.Password)
	defer c.Logout()

	msg := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Lands on retry\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"\r\n" +
		"Body that S3 only serves on the second GET.\r\n"
	uid := appendMessage(t, c, msg)

	// The exact bytes stored on disk are what S3 would hold once uploaded; serve those,
	// then delete the staging copy so the fetch must go to S3.
	stagedPath, _ := findSingleStagedFile(t, server.UploadPath)
	body, err := os.ReadFile(stagedPath)
	if err != nil {
		t.Fatalf("read staged body: %v", err)
	}
	fake.SetBody(body)
	if err := os.Remove(stagedPath); err != nil {
		t.Fatalf("remove staged file: %v", err)
	}

	start := time.Now()
	got := fetchBodySection(t, c, uid, &imap.FetchItemBodySection{Peek: true})
	elapsed := time.Since(start)

	if !bytes.Equal(got, body) {
		t.Fatalf("expected the real body after retry, got %d bytes (want %d)", len(got), len(body))
	}
	if n := fake.GetCount(); n < 2 {
		t.Fatalf("expected at least 2 S3 GETs (NoSuchKey then body), got %d", n)
	}
	// The single retry must have waited one bodyFetchRetryDelay (~500ms). Use a slack
	// lower bound to stay non-flaky.
	if elapsed < 300*time.Millisecond {
		t.Fatalf("expected the fetch to wait out the retry delay, but it returned in %v", elapsed)
	}
}

// TestIMAP_FetchNotYetUploaded_NoPendingDoesNotRetry proves the pending-gate: a not-yet-
// uploaded message with NO pending upload (content genuinely gone) does a single S3 probe
// and degrades to an empty body instead of waiting — so a bulk fetch over abandoned
// uploads doesn't pay the retry delay per message.
func TestIMAP_FetchNotYetUploaded_NoPendingDoesNotRetry(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	fake, s3 := common.NewScriptedS3(t, 100) // always NoSuchKey
	server, account := common.SetupIMAPServerForUploadRaceWithS3(t, s3)
	defer server.Close()

	c := loginSelectInbox(t, server.Address, account.Email, account.Password)
	defer c.Logout()

	msg := "From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: Lost\r\n\r\nGone.\r\n"
	uid := appendMessage(t, c, msg)

	stagedPath, contentHash := findSingleStagedFile(t, server.UploadPath)
	if err := os.Remove(stagedPath); err != nil {
		t.Fatalf("remove staged file: %v", err)
	}
	// Drop the pending_upload so the body is no longer expected → gate closes the retries.
	accountID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(t.Context(), account.Email)
	if err != nil {
		t.Fatalf("lookup account id: %v", err)
	}
	deletePendingUploadOnly(t, server, contentHash, accountID)

	start := time.Now()
	got := fetchBodySection(t, c, uid, &imap.FetchItemBodySection{Peek: true})
	elapsed := time.Since(start)

	if len(got) != 0 {
		t.Fatalf("expected empty body for abandoned upload, got %d bytes", len(got))
	}
	if n := fake.GetCount(); n != 1 {
		t.Fatalf("expected exactly 1 S3 GET (no retry when not pending), got %d", n)
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("expected no retry delay when not pending, but fetch took %v", elapsed)
	}
}
