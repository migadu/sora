//go:build integration

package lmtp_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// TestLMTP_NodeIdentitySplit pins the boundary between this node's two names as it is
// observable end to end, rather than at the resolver.
//
// uploader.instance_id is an upload-lease key: pending_uploads rows are claimable only by
// the instance named on them, because the body is a file on that node's disk. It is
// internal, and operators set it to labels like "node-1". The mail hostname is the
// opposite - it is published in the "by" clause of the Received header of every delivery
// (RFC 5321 4.4).
//
// These were once a single string, which stamped the internal label onto outbound mail.
// Splitting them is only real if both halves land in the right place, so this test runs
// one delivery with the two names set to deliberately different values and checks each
// one where it is actually consumed: the header on the stored message, and the instance_id
// on the pending_uploads row.
func TestLMTP_NodeIdentitySplit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	const (
		mailHostname = "mail-identity-split.example.com"
		leaseKey     = "node-identity-split-1"
	)

	ctx := context.Background()
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	tempDir := t.TempDir()
	uploaderInstance, err := uploader.NewWithS3Interface(
		tempDir, 10, 2, 3, time.Minute, 0, leaseKey, rdb,
		&common.NoopUploaderS3{}, &common.NoopUploaderCache{}, make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("Failed to create uploader: %v", err)
	}

	lmtpAddr := common.GetRandomAddress(t)
	lmtpSrv, err := lmtpserver.New(
		ctx, "test-lmtp", mailHostname, lmtpAddr,
		&storage.S3Storage{}, rdb, uploaderInstance,
		lmtpserver.LMTPServerOptions{InstanceID: leaseKey},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP server: %v", err)
	}
	t.Cleanup(func() { lmtpSrv.Close() })

	errChan := make(chan error, 1)
	go func() { lmtpSrv.Start(errChan) }()
	time.Sleep(200 * time.Millisecond)

	msg := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: node identity split\r\n" +
		"\r\n" +
		"body\r\n"

	resp := deliverLMTPRaw(t, lmtpAddr, "sender@example.com", account.Email, msg)
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("delivery rejected: %s", resp)
	}

	// The published name: the Received trace this hop stamped.
	stored := readStagedMessage(t, tempDir)
	receivedLine := firstReceivedHeader(stored)
	if receivedLine == "" {
		t.Fatalf("stored message has no Received header:\n%s", truncate(stored, 500))
	}
	if !strings.Contains(receivedLine, mailHostname) {
		t.Errorf("Received header does not name the mail hostname %q:\n\t%s", mailHostname, receivedLine)
	}
	if strings.Contains(receivedLine, leaseKey) {
		t.Errorf("Received header leaks the upload-lease key %q - that is an internal identifier "+
			"and belongs nowhere on the wire:\n\t%s", leaseKey, receivedLine)
	}

	// The internal name: whoever owns this body on disk.
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("resolve account: %v", err)
	}
	var instanceID string
	row := rdb.QueryRowWithRetry(ctx,
		`SELECT instance_id FROM pending_uploads WHERE account_id = $1 ORDER BY id DESC LIMIT 1`, accountID)
	if err := row.Scan(&instanceID); err != nil {
		t.Fatalf("read pending_uploads.instance_id: %v", err)
	}
	if instanceID != leaseKey {
		t.Errorf("pending_uploads.instance_id = %q, want the lease key %q - the upload worker "+
			"heartbeats under the lease key, so any other value strands this body until the "+
			"cleaner deletes it", instanceID, leaseKey)
	}
}

// readStagedMessage returns the contents of the single message file the uploader staged.
func readStagedMessage(t *testing.T, dir string) string {
	t.Helper()
	var found string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || found != "" {
			return err
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(data), "node identity split") {
			found = string(data)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk staging dir: %v", err)
	}
	if found == "" {
		t.Fatal("staged message not found in uploader directory")
	}
	return found
}

// firstReceivedHeader returns the first Received header including its folded continuation
// lines, which is where the "by" clause lives.
func firstReceivedHeader(msg string) string {
	lines := strings.Split(msg, "\n")
	var b strings.Builder
	for i, line := range lines {
		if !strings.HasPrefix(line, "Received:") {
			continue
		}
		b.WriteString(strings.TrimRight(line, "\r"))
		for _, cont := range lines[i+1:] {
			if !strings.HasPrefix(cont, " ") && !strings.HasPrefix(cont, "\t") {
				break
			}
			b.WriteString(" ")
			b.WriteString(strings.TrimSpace(cont))
		}
		return b.String()
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
