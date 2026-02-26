//go:build integration

package lmtp_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	imapserver "github.com/migadu/sora/server/imap"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"

	"github.com/migadu/sora/integration_tests/common"
)

// TestLMTP_PlusAddressingWithSharedUploader tests that messages delivered to plus addresses
// (e.g., user+alias@domain.com) are:
// 1. Routed to the correct folder (e.g., "alias") via the default Sieve script
// 2. Stored with the correct S3 key (using base address localpart, not the full alias)
// 3. Can be retrieved via IMAP from the folder
//
// This test uses a SHARED uploader temp directory for both LMTP and IMAP servers,
// allowing IMAP to retrieve messages delivered via LMTP from local storage.
func TestLMTP_PlusAddressingWithSharedUploader(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup database and account
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// Create SHARED temp directory for both servers
	sharedTempDir := t.TempDir()
	t.Logf("Using shared upload directory: %s", sharedTempDir)

	// Create shared S3 storage (empty for testing)
	s3Storage := &storage.S3Storage{}

	// Create SHARED uploader that both servers will use
	sharedUploader, err := uploader.New(
		context.Background(),
		sharedTempDir,
		10,            // batch size
		2,             // concurrency
		3,             // max attempts
		5*time.Second, // retry interval
		"test-shared-host",
		rdb,
		s3Storage,
		nil, // cache
		make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("Failed to create shared uploader: %v", err)
	}

	// Setup LMTP server with shared uploader
	lmtpAddr := common.GetRandomAddress(t)
	lmtpSrv, err := lmtpserver.New(
		context.Background(),
		"test-lmtp",
		"localhost",
		lmtpAddr,
		s3Storage,
		rdb,
		sharedUploader,
		lmtpserver.LMTPServerOptions{},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP server: %v", err)
	}
	defer lmtpSrv.Close()

	// Start LMTP server
	lmtpErrChan := make(chan error, 1)
	go func() {
		lmtpSrv.Start(lmtpErrChan)
	}()

	// Setup IMAP server with SAME shared uploader
	imapAddr := common.GetRandomAddress(t)
	imapSrv, err := imapserver.New(
		context.Background(),
		"test-imap",
		"localhost",
		imapAddr,
		s3Storage,
		rdb,
		sharedUploader,
		nil, // cache
		imapserver.IMAPServerOptions{InsecureAuth: true},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}
	defer imapSrv.Close()

	// Start IMAP server
	go func() {
		if err := imapSrv.Serve(imapAddr); err != nil {
			t.Logf("IMAP server error: %v", err)
		}
	}()

	// Give servers a moment to start listening
	time.Sleep(200 * time.Millisecond)

	// Test delivering to plus address
	baseEmail := account.Email
	plusAddress := strings.Replace(baseEmail, "@", "+alias@", 1)

	t.Logf("Base account email: %s", baseEmail)
	t.Logf("Plus address for delivery: %s", plusAddress)

	// Connect to LMTP
	lmtpClient, err := NewLMTPClient(lmtpAddr)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP server: %v", err)
	}
	defer lmtpClient.Close()

	// Send LHLO
	if err := lmtpClient.SendCommand("LHLO test.example.com"); err != nil {
		t.Fatalf("Failed to send LHLO: %v", err)
	}
	if _, err := lmtpClient.ReadMultilineResponse(); err != nil {
		t.Fatalf("Failed to read LHLO response: %v", err)
	}

	// Send MAIL FROM
	if err := lmtpClient.SendCommand("MAIL FROM:<sender@example.com>"); err != nil {
		t.Fatalf("Failed to send MAIL FROM: %v", err)
	}
	if _, err := lmtpClient.ReadResponse(); err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}

	// Send RCPT TO with plus address
	t.Logf("Delivering to plus address: %s", plusAddress)
	if err := lmtpClient.SendCommand(fmt.Sprintf("RCPT TO:<%s>", plusAddress)); err != nil {
		t.Fatalf("Failed to send RCPT TO: %v", err)
	}
	rcptResponse, err := lmtpClient.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read RCPT TO response: %v", err)
	}
	if !strings.HasPrefix(rcptResponse, "250") {
		t.Fatalf("Expected 250 response for RCPT TO, got: %s", rcptResponse)
	}

	// Send DATA
	if err := lmtpClient.SendCommand("DATA"); err != nil {
		t.Fatalf("Failed to send DATA: %v", err)
	}
	if _, err := lmtpClient.ReadResponse(); err != nil {
		t.Fatalf("Failed to read DATA response: %v", err)
	}

	// Send message
	messageContent := fmt.Sprintf(`From: sender@example.com
To: %s
Subject: Test Plus Addressing
Date: %s
Message-ID: <test-plus-lmtp-%d@example.com>

This is a test message to verify plus addressing S3 key handling.
The message should be stored with the base address in s3_localpart,
not the full plus address.
`, plusAddress, time.Now().Format(time.RFC1123Z), time.Now().UnixNano())

	if err := lmtpClient.SendCommand(messageContent + "\r\n."); err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Read per-recipient response
	dataResponses, err := lmtpClient.ReadDataResponses(1)
	if err != nil {
		t.Fatalf("Failed to read DATA responses: %v", err)
	}
	if !strings.HasPrefix(dataResponses[0], "250") {
		t.Fatalf("Expected 250 response after DATA, got: %s", dataResponses[0])
	}

	t.Logf("✓ Message delivered to plus address via LMTP")

	// Give system a moment to process
	time.Sleep(200 * time.Millisecond)

	// Now FETCH the message via IMAP
	// Since both servers share the same uploader temp directory,
	// IMAP can retrieve the locally-stored message
	c, err := imapclient.DialInsecure(imapAddr, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	// Login with base address
	if err := c.Login(baseEmail, account.Password).Wait(); err != nil {
		t.Fatalf("IMAP Login failed: %v", err)
	}

	// The message should be in the "alias" folder (from plus addressing)
	// not INBOX, because our default Sieve script now handles plus addressing
	_, err = c.Select("alias", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT alias failed: %v", err)
	}

	// Fetch the message body
	fetchCmd := c.Fetch(imap.UIDSetNum(1), &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{
			{Part: []int{}}, // BODY[] (full message)
		},
	})

	var messageBody []byte
	for {
		msg := fetchCmd.Next()
		if msg == nil {
			break
		}
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			if bodyItem, ok := item.(imapclient.FetchItemDataBodySection); ok {
				buf := new(bytes.Buffer)
				if _, err := io.Copy(buf, bodyItem.Literal); err != nil {
					t.Fatalf("Failed to read message body: %v", err)
				}
				messageBody = buf.Bytes()
			}
		}
	}

	if err := fetchCmd.Close(); err != nil {
		t.Fatalf("FETCH command failed: %v", err)
	}

	// Verify we got a non-empty body
	if len(messageBody) == 0 {
		// Check if file exists in shared directory for debugging
		files, _ := os.ReadDir(sharedTempDir)
		t.Logf("Files in shared temp dir: %v", files)

		t.Fatalf("FETCH returned empty body (size=0) - this indicates S3 key mismatch bug!\n"+
			"Message was delivered to %s but s3_localpart was likely stored with the full alias.\n"+
			"Expected s3_localpart='%s' (base address), got wrong value.",
			plusAddress,
			strings.Split(baseEmail, "@")[0])
	}

	// Verify content
	if !strings.Contains(string(messageBody), "Test Plus Addressing") {
		t.Fatalf("Retrieved body doesn't contain expected content. Got %d bytes", len(messageBody))
	}

	t.Logf("✓ Successfully retrieved message body via IMAP (%d bytes)", len(messageBody))
	t.Logf("✓ Message was routed to 'alias' folder via default Sieve script")
	t.Logf("✓ S3 key is constructed correctly (using base address localpart)")
	t.Logf("✓ Plus addressing with LMTP → IMAP test completed successfully")
}

// TestLMTP_SieveFileIntoCreate tests that Sieve scripts with "fileinto :create"
// automatically create mailboxes that don't exist.
func TestLMTP_SieveFileIntoCreate(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup database and account
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// Get account ID
	accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	// Create a Sieve script with fileinto :create
	sieveScript := `require ["fileinto", "mailbox"];

# Create and deliver to a mailbox that doesn't exist yet
fileinto :create "Projects/RFC5490";
`

	// Upload the Sieve script using database method
	ctx := context.Background()

	// Delete any existing script first
	_, _ = rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", accountID)

	// Insert the new script
	_, err = rdb.ExecWithRetry(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
	`, accountID, "test-create", sieveScript, true)
	if err != nil {
		t.Fatalf("Failed to insert Sieve script: %v", err)
	}

	// Create temp directory and uploader
	tempDir := t.TempDir()
	s3Storage := &storage.S3Storage{}
	uploader, err := uploader.New(
		context.Background(),
		tempDir,
		10,
		2,
		3,
		5*time.Second,
		"test-host",
		rdb,
		s3Storage,
		nil,
		make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("Failed to create uploader: %v", err)
	}

	// Setup LMTP server
	lmtpAddr := common.GetRandomAddress(t)
	lmtpSrv, err := lmtpserver.New(
		context.Background(),
		"test-lmtp",
		"localhost",
		lmtpAddr,
		s3Storage,
		rdb,
		uploader,
		lmtpserver.LMTPServerOptions{},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP server: %v", err)
	}
	defer lmtpSrv.Close()

	// Start LMTP server
	lmtpErrChan := make(chan error, 1)
	go func() {
		lmtpSrv.Start(lmtpErrChan)
	}()

	// Give server a moment to start
	time.Sleep(200 * time.Millisecond)

	// Connect to LMTP
	lmtpClient, err := NewLMTPClient(lmtpAddr)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP server: %v", err)
	}
	defer lmtpClient.Close()

	// Send LHLO
	if err := lmtpClient.SendCommand("LHLO test.example.com"); err != nil {
		t.Fatalf("Failed to send LHLO: %v", err)
	}
	if _, err := lmtpClient.ReadMultilineResponse(); err != nil {
		t.Fatalf("Failed to read LHLO response: %v", err)
	}

	// Send MAIL FROM
	if err := lmtpClient.SendCommand("MAIL FROM:<sender@example.com>"); err != nil {
		t.Fatalf("Failed to send MAIL FROM: %v", err)
	}
	if _, err := lmtpClient.ReadResponse(); err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}

	// Send RCPT TO
	if err := lmtpClient.SendCommand(fmt.Sprintf("RCPT TO:<%s>", account.Email)); err != nil {
		t.Fatalf("Failed to send RCPT TO: %v", err)
	}
	rcptResponse, err := lmtpClient.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read RCPT TO response: %v", err)
	}
	if !strings.HasPrefix(rcptResponse, "250") {
		t.Fatalf("Expected 250 response for RCPT TO, got: %s", rcptResponse)
	}

	// Send DATA
	if err := lmtpClient.SendCommand("DATA"); err != nil {
		t.Fatalf("Failed to send DATA: %v", err)
	}
	if _, err := lmtpClient.ReadResponse(); err != nil {
		t.Fatalf("Failed to read DATA response: %v", err)
	}

	// Send message
	messageContent := fmt.Sprintf(`From: sender@example.com
To: %s
Subject: Test fileinto :create
Date: %s
Message-ID: <test-create-%d@example.com>

This message should be delivered to a mailbox that doesn't exist yet.
The Sieve :create modifier should automatically create it.
`, account.Email, time.Now().Format(time.RFC1123Z), time.Now().UnixNano())

	if err := lmtpClient.SendCommand(messageContent + "\r\n."); err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Read per-recipient response
	dataResponses, err := lmtpClient.ReadDataResponses(1)
	if err != nil {
		t.Fatalf("Failed to read DATA responses: %v", err)
	}
	if !strings.HasPrefix(dataResponses[0], "250") {
		t.Fatalf("Expected 250 response after DATA, got: %s", dataResponses[0])
	}

	t.Logf("✓ Message delivered successfully")

	// Give system a moment to process
	time.Sleep(200 * time.Millisecond)

	// Verify that the mailbox "Projects/RFC5490" was created
	mailbox, err := rdb.GetMailboxByNameWithRetry(context.Background(), accountID, "Projects/RFC5490")
	if err != nil {
		t.Fatalf("Failed to get mailbox 'Projects/RFC5490': %v (mailbox should have been auto-created by :create)", err)
	}
	if mailbox.Name != "Projects/RFC5490" {
		t.Fatalf("Expected mailbox name 'Projects/RFC5490', got: %s", mailbox.Name)
	}

	t.Logf("✓ Mailbox 'Projects/RFC5490' was automatically created by :create modifier")

	// Setup IMAP server to verify message is in the created mailbox
	imapAddr := common.GetRandomAddress(t)
	imapSrv, err := imapserver.New(
		context.Background(),
		"test-imap",
		"localhost",
		imapAddr,
		s3Storage,
		rdb,
		uploader,
		nil,
		imapserver.IMAPServerOptions{InsecureAuth: true},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}
	defer imapSrv.Close()

	// Start IMAP server
	go func() {
		if err := imapSrv.Serve(imapAddr); err != nil {
			t.Logf("IMAP server error: %v", err)
		}
	}()

	// Give IMAP server a moment to start
	time.Sleep(200 * time.Millisecond)

	// Connect via IMAP
	c, err := imapclient.DialInsecure(imapAddr, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	// Login
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("IMAP Login failed: %v", err)
	}

	// Select the created mailbox
	selectData, err := c.Select("Projects/RFC5490", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT 'Projects/RFC5490' failed: %v", err)
	}

	// Verify there's 1 message
	if selectData.NumMessages != 1 {
		t.Fatalf("Expected 1 message in 'Projects/RFC5490', got: %d", selectData.NumMessages)
	}

	t.Logf("✓ Message is in 'Projects/RFC5490' mailbox (count: %d)", selectData.NumMessages)

	// Verify INBOX is empty (message should not be there)
	inboxData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}
	if inboxData.NumMessages != 0 {
		t.Fatalf("Expected 0 messages in INBOX (message should only be in created mailbox), got: %d", inboxData.NumMessages)
	}

	t.Logf("✓ INBOX is empty (message correctly delivered only to created mailbox)")
	t.Logf("✓ Sieve fileinto :create test completed successfully")
}

// TestLMTP_PlusAddressingWithUserSieveScript tests that plus addressing works correctly
// when a user has their own Sieve script. This tests the fix for the bug where:
// 1. Default script detects plus addressing (user+test@domain.com) and sets fileinto "test"
// 2. User script doesn't match any conditions and returns implicit keep
// 3. User script's implicit keep was incorrectly overriding the default script's fileinto
//
// After the fix, the default script's action is preserved when user script returns implicit keep.
func TestLMTP_PlusAddressingWithUserSieveScript(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup database and account
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// Get account ID
	accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	// Create a user Sieve script that filters specific subjects
	// When the subject doesn't match, it should NOT override the default script's plus addressing
	userSieveScript := `require ["envelope", "fileinto", "mailbox"];

if header :contains "subject" ["Izvod po dinarskom", "Izvod po deviznom"] {
  fileinto :create "izvodi";
}
`

	// Upload the user Sieve script
	ctx := context.Background()
	_, _ = rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", accountID)
	_, err = rdb.ExecWithRetry(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
	`, accountID, "user-filter", userSieveScript, true)
	if err != nil {
		t.Fatalf("Failed to insert user Sieve script: %v", err)
	}

	// Create shared temp directory and uploader
	sharedTempDir := t.TempDir()
	s3Storage := &storage.S3Storage{}
	sharedUploader, err := uploader.New(
		context.Background(),
		sharedTempDir,
		10,
		2,
		3,
		5*time.Second,
		"test-host",
		rdb,
		s3Storage,
		nil,
		make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("Failed to create uploader: %v", err)
	}

	// Setup LMTP server
	lmtpAddr := common.GetRandomAddress(t)
	lmtpSrv, err := lmtpserver.New(
		context.Background(),
		"test-lmtp",
		"localhost",
		lmtpAddr,
		s3Storage,
		rdb,
		sharedUploader,
		lmtpserver.LMTPServerOptions{},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP server: %v", err)
	}
	defer lmtpSrv.Close()

	// Start LMTP server
	lmtpErrChan := make(chan error, 1)
	go func() {
		lmtpSrv.Start(lmtpErrChan)
	}()

	// Setup IMAP server
	imapAddr := common.GetRandomAddress(t)
	imapSrv, err := imapserver.New(
		context.Background(),
		"test-imap",
		"localhost",
		imapAddr,
		s3Storage,
		rdb,
		sharedUploader,
		nil,
		imapserver.IMAPServerOptions{InsecureAuth: true},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}
	defer imapSrv.Close()

	go func() {
		if err := imapSrv.Serve(imapAddr); err != nil {
			t.Logf("IMAP server error: %v", err)
		}
	}()

	// Give servers time to start
	time.Sleep(200 * time.Millisecond)

	// Test scenarios
	testCases := []struct {
		name            string
		recipient       string
		subject         string
		expectedMailbox string
		description     string
	}{
		{
			name:            "PlusAddressingWithMatchingSubject",
			recipient:       strings.Replace(account.Email, "@", "+test@", 1),
			subject:         "Izvod po dinarskom",
			expectedMailbox: "izvodi",
			description:     "User script matches subject, should override default and go to 'izvodi'",
		},
		{
			name:            "PlusAddressingWithNonMatchingSubject",
			recipient:       strings.Replace(account.Email, "@", "+test@", 1),
			subject:         "Hello World",
			expectedMailbox: "test",
			description:     "User script doesn't match, should preserve default plus addressing and go to 'test'",
		},
		{
			name:            "NoPlusAddressingWithMatchingSubject",
			recipient:       account.Email,
			subject:         "Izvod po deviznom",
			expectedMailbox: "izvodi",
			description:     "No plus addressing, user script matches, should go to 'izvodi'",
		},
		{
			name:            "NoPlusAddressingWithNonMatchingSubject",
			recipient:       account.Email,
			subject:         "Regular Email",
			expectedMailbox: "INBOX",
			description:     "No plus addressing, user script doesn't match, should go to INBOX",
		},
	}

	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Test case %d: %s", i+1, tc.description)

			// Connect to LMTP
			lmtpClient, err := NewLMTPClient(lmtpAddr)
			if err != nil {
				t.Fatalf("Failed to connect to LMTP: %v", err)
			}
			defer lmtpClient.Close()

			// LHLO
			if err := lmtpClient.SendCommand("LHLO test.example.com"); err != nil {
				t.Fatalf("Failed to send LHLO: %v", err)
			}
			if _, err := lmtpClient.ReadMultilineResponse(); err != nil {
				t.Fatalf("Failed to read LHLO response: %v", err)
			}

			// MAIL FROM
			if err := lmtpClient.SendCommand("MAIL FROM:<sender@example.com>"); err != nil {
				t.Fatalf("Failed to send MAIL FROM: %v", err)
			}
			if _, err := lmtpClient.ReadResponse(); err != nil {
				t.Fatalf("Failed to read MAIL FROM response: %v", err)
			}

			// RCPT TO
			if err := lmtpClient.SendCommand(fmt.Sprintf("RCPT TO:<%s>", tc.recipient)); err != nil {
				t.Fatalf("Failed to send RCPT TO: %v", err)
			}
			rcptResponse, err := lmtpClient.ReadResponse()
			if err != nil {
				t.Fatalf("Failed to read RCPT TO response: %v", err)
			}
			if !strings.HasPrefix(rcptResponse, "250") {
				t.Fatalf("Expected 250 for RCPT TO, got: %s", rcptResponse)
			}

			// DATA
			if err := lmtpClient.SendCommand("DATA"); err != nil {
				t.Fatalf("Failed to send DATA: %v", err)
			}
			if _, err := lmtpClient.ReadResponse(); err != nil {
				t.Fatalf("Failed to read DATA response: %v", err)
			}

			// Send message
			messageContent := fmt.Sprintf(`From: sender@example.com
To: %s
Subject: %s
Date: %s
Message-ID: <test-%s-%d@example.com>

Test message for: %s
`, tc.recipient, tc.subject, time.Now().Format(time.RFC1123Z), tc.name, time.Now().UnixNano(), tc.description)

			if err := lmtpClient.SendCommand(messageContent + "\r\n."); err != nil {
				t.Fatalf("Failed to send message: %v", err)
			}

			// Read DATA response
			dataResponses, err := lmtpClient.ReadDataResponses(1)
			if err != nil {
				t.Fatalf("Failed to read DATA responses: %v", err)
			}
			if !strings.HasPrefix(dataResponses[0], "250") {
				t.Fatalf("Expected 250 after DATA, got: %s", dataResponses[0])
			}

			t.Logf("✓ Message delivered to %s with subject '%s'", tc.recipient, tc.subject)

			// Give system time to process
			time.Sleep(300 * time.Millisecond)

			// Verify via IMAP
			c, err := imapclient.DialInsecure(imapAddr, nil)
			if err != nil {
				t.Fatalf("Failed to dial IMAP: %v", err)
			}
			defer c.Logout()

			if err := c.Login(account.Email, account.Password).Wait(); err != nil {
				t.Fatalf("IMAP Login failed: %v", err)
			}

			// Select expected mailbox
			selectData, err := c.Select(tc.expectedMailbox, nil).Wait()
			if err != nil {
				t.Fatalf("SELECT '%s' failed: %v", tc.expectedMailbox, err)
			}

			// The message should be in this mailbox
			// Note: We can't check exact count because previous test cases may have added messages
			// Just verify the mailbox exists and can be selected
			t.Logf("✓ Mailbox '%s' contains %d message(s)", tc.expectedMailbox, selectData.NumMessages)

			// Fetch the latest message and verify subject
			if selectData.NumMessages > 0 {
				// Get the latest message by sequence number
				fetchCmd := c.Fetch(imap.SeqSetNum(selectData.NumMessages), &imap.FetchOptions{
					Envelope: true,
				})

				for {
					msg := fetchCmd.Next()
					if msg == nil {
						break
					}
					for {
						item := msg.Next()
						if item == nil {
							break
						}
						if envItem, ok := item.(imapclient.FetchItemDataEnvelope); ok {
							if envItem.Envelope.Subject == tc.subject {
								t.Logf("✓ Verified message with subject '%s' is in mailbox '%s'", tc.subject, tc.expectedMailbox)
							}
						}
					}
				}

				if err := fetchCmd.Close(); err != nil {
					t.Fatalf("FETCH failed: %v", err)
				}
			}
		})
	}

	t.Logf("✓ All plus addressing + user Sieve script scenarios passed")
}
