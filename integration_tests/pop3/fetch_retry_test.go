//go:build integration

package pop3_test

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestPOP3_RetrNotYetUploaded_RetriesThenServesBody proves the POP3 not-yet-uploaded retry
// actually waits out a real NoSuchKey and then serves the body once the object lands —
// RETR succeeds with +OK instead of -ERR. This is the timing/retry path the empty-stub
// tests can't reach.
func TestPOP3_RetrNotYetUploaded_RetriesThenServesBody(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	fake, s3 := common.NewScriptedS3(t, 1) // first GET → NoSuchKey, then the body lands
	server, account := setupPOP3RaceServerWithS3(t, s3)
	defer server.Close()

	msg := "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Lands on retry\r\n\r\nBody that S3 only serves on the second GET.\r\n"
	contentHash, accountID := stageMessageNoUpload(t, server, account.Email, msg)

	// The exact bytes staged are what S3 would hold once uploaded; serve those, then delete
	// the staging copy so RETR must go to S3.
	stagedPath := server.Uploader.FilePath(contentHash, accountID)
	body, err := os.ReadFile(stagedPath)
	if err != nil {
		t.Fatalf("read staged body: %v", err)
	}
	fake.SetBody(body)
	if err := os.Remove(stagedPath); err != nil {
		t.Fatalf("remove staged file: %v", err)
	}

	conn, err := net.Dial("tcp", server.TestServer.Address)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	reader, writer := loginClient(t, conn, account.Email, account.Password)

	start := time.Now()
	fmt.Fprintf(writer, "RETR 1\r\n")
	writer.Flush()
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read RETR status: %v", err)
	}
	if !strings.HasPrefix(statusLine, "+OK") {
		t.Fatalf("expected +OK after retry served the body, got: %q", statusLine)
	}
	content := readEntireMultilineResponse(t, reader)
	elapsed := time.Since(start)

	if !strings.Contains(content, "Body that S3 only serves on the second GET.") {
		t.Fatalf("RETR did not return the message body, got: %q", content)
	}
	if n := fake.GetCount(); n < 2 {
		t.Fatalf("expected at least 2 S3 GETs (NoSuchKey then body), got %d", n)
	}
	if elapsed < 300*time.Millisecond {
		t.Fatalf("expected RETR to wait out the retry delay, but it returned in %v", elapsed)
	}
}

// TestPOP3_RetrNotYetUploaded_NoPendingDoesNotRetry proves the pending-gate on the POP3
// path: a not-yet-uploaded message with NO pending upload does a single S3 probe and
// returns -ERR Message not available immediately, without paying the retry delay.
func TestPOP3_RetrNotYetUploaded_NoPendingDoesNotRetry(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	fake, s3 := common.NewScriptedS3(t, 100) // always NoSuchKey
	server, account := setupPOP3RaceServerWithS3(t, s3)
	defer server.Close()

	msg := "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Lost\r\n\r\nGone.\r\n"
	contentHash, accountID := stageMessageNoUpload(t, server, account.Email, msg)

	if err := os.Remove(server.Uploader.FilePath(contentHash, accountID)); err != nil {
		t.Fatalf("remove staged file: %v", err)
	}
	// Drop the pending_upload so the body is no longer expected → gate closes the retries.
	deletePendingUploadOnly(t, server.TestServer, contentHash, accountID)

	conn, err := net.Dial("tcp", server.TestServer.Address)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	reader, writer := loginClient(t, conn, account.Email, account.Password)

	start := time.Now()
	fmt.Fprintf(writer, "RETR 1\r\n")
	writer.Flush()
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read RETR status: %v", err)
	}
	elapsed := time.Since(start)

	if !strings.HasPrefix(statusLine, "-ERR") {
		t.Fatalf("expected -ERR for abandoned upload, got: %q", statusLine)
	}
	if !strings.Contains(statusLine, "Message not available") {
		t.Fatalf("expected permanent 'Message not available', got: %q", statusLine)
	}
	if n := fake.GetCount(); n != 1 {
		t.Fatalf("expected exactly 1 S3 GET (no retry when not pending), got %d", n)
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("expected no retry delay when not pending, but RETR took %v", elapsed)
	}
}
