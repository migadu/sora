//go:build integration

package imap_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func TestFetchUnuploadedMessage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up server normally
	ts, account := common.SetupIMAPServer(t)
	defer ts.Close()

	ctx := context.Background()

	// Connect client
	c, err := imapclient.DialInsecure(ts.Address, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer c.Close()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	mailboxName := "INBOX/TestUnuploaded"
	if err := c.Create(mailboxName, nil).Wait(); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Append a message. The TestServer's sync upload worker will immediately
	// process it and set uploaded = true.
	content := "Subject: Unuploaded Test\r\n\r\nThis is a message that is not yet in S3."
	appendCmd := c.Append(mailboxName, int64(len(content)), nil)
	if _, err := appendCmd.Write([]byte(content)); err != nil {
		t.Fatalf("Append write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("Append close failed: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("Append Wait failed: %v", err)
	}

	accountID, err := ts.ResilientDB.GetAccountIDByEmailWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	mailbox, err := ts.ResilientDB.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
	if err != nil {
		t.Fatalf("Failed to get mailbox: %v", err)
	}

	// Simulate the race condition where a message is APPENDed but the async S3
	// upload worker hasn't processed it yet (uploaded = false).
	// In testing, the S3 Noop uploader discards the data, so if the server tries
	// to fetch it from S3, it will fail. By setting uploaded = false, we force
	// the server to use the local disk fallback, which still has the file because
	// the NoopCache doesn't delete it.
	_, err = ts.ResilientDB.GetDatabase().GetWritePool().Exec(ctx,
		"UPDATE messages SET uploaded = false WHERE mailbox_id = $1", mailbox.ID)
	if err != nil {
		t.Fatalf("Failed to simulate unuploaded state: %v", err)
	}

	// Select the mailbox
	selectData, err := c.Select(mailboxName, nil).Wait()
	if err != nil {
		t.Fatalf("Select failed: %v", err)
	}

	if selectData.NumMessages != 1 {
		t.Fatalf("Expected 1 message, got %d", selectData.NumMessages)
	}

	// Fetch envelope and body peek
	headerSection := &imap.FetchItemBodySection{
		Specifier: imap.PartSpecifierHeader,
		Peek:      true,
	}
	bodySection := &imap.FetchItemBodySection{
		Specifier: imap.PartSpecifierNone,
		Peek:      true,
	}
	fetchOptions := &imap.FetchOptions{
		Envelope:      true,
		BodyStructure: &imap.FetchItemBodyStructure{},
		BodySection: []*imap.FetchItemBodySection{
			headerSection,
			bodySection,
		},
	}

	seqSet := imap.SeqSetNum(1)
	fetchCmd := c.Fetch(seqSet, fetchOptions)

	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if len(msgs) != 1 {
		t.Fatalf("Expected 1 message in FETCH response, got %d", len(msgs))
	}

	msg := msgs[0]

	// Verify metadata (parsed from DB)
	if msg.Envelope == nil {
		t.Fatalf("Expected envelope, got nil")
	}
	if msg.Envelope.Subject != "Unuploaded Test" {
		t.Fatalf("Expected subject 'Unuploaded Test', got %q", msg.Envelope.Subject)
	}

	// Verify header content
	headerData := msg.FindBodySection(headerSection)
	if !bytes.Contains(headerData, []byte("Subject: Unuploaded Test\r\n\r\n")) {
		t.Fatalf("Expected header to contain subject and CRLF, got %q", string(headerData))
	}

	// Verify raw content (read from local disk fallback)
	bodyBytes := msg.FindBodySection(bodySection)
	if !bytes.Equal(bodyBytes, []byte(content)) {
		t.Fatalf("Expected body %q, got %q", content, string(bodyBytes))
	}
}
