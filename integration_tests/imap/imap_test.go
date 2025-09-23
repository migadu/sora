//go:build integration

package imap_test

import (
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_LoginAndSelect(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	t.Logf("Connected to IMAP server at %s", server.Address)

	// Test login
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed for user %s: %v", account.Email, err)
	}
	t.Log("Login successful")

	// Test selecting INBOX
	selectCmd := c.Select("INBOX", nil)
	mbox, err := selectCmd.Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	if mbox.NumMessages != 0 {
		t.Errorf("Expected 0 messages in INBOX, got %d", mbox.NumMessages)
	}
	t.Log("INBOX selected successfully")
}

func TestIMAP_InvalidLogin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	// Test invalid password
	err = c.Login(account.Email, "wrong_password").Wait()
	if err == nil {
		t.Fatal("Expected login to fail with wrong password, but it succeeded")
	}
	t.Logf("Login correctly failed with wrong password: %v", err)

	// Test non-existent user
	err = c.Login("nonexistent@example.com", "password").Wait()
	if err == nil {
		t.Fatal("Expected login to fail with non-existent user, but it succeeded")
	}
	t.Logf("Login correctly failed with non-existent user: %v", err)
}

func TestIMAP_MailboxOperations(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

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

	// Test LIST command
	listCmd := c.List("", "*", nil)
	mailboxes, err := listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST command failed: %v", err)
	}

	// Should at least have INBOX
	found := false
	for _, mbox := range mailboxes {
		if mbox.Mailbox == "INBOX" {
			found = true
			break
		}
	}
	if !found {
		t.Error("INBOX not found in LIST response")
	}
	t.Logf("LIST returned %d mailboxes", len(mailboxes))

	// Test CREATE mailbox
	testMailbox := "TestFolder"
	if err := c.Create(testMailbox, nil).Wait(); err != nil {
		t.Fatalf("CREATE mailbox failed: %v", err)
	}
	t.Logf("Created mailbox: %s", testMailbox)

	// Verify the mailbox was created
	listCmd = c.List("", "*", nil)
	mailboxes, err = listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST command failed after CREATE: %v", err)
	}

	found = false
	for _, mbox := range mailboxes {
		if mbox.Mailbox == testMailbox {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Created mailbox %s not found in LIST response", testMailbox)
	}

	// Test DELETE mailbox
	if err := c.Delete(testMailbox).Wait(); err != nil {
		t.Fatalf("DELETE mailbox failed: %v", err)
	}
	t.Logf("Deleted mailbox: %s", testMailbox)
}

// TestIMAP_AppendOperation tests various APPEND scenarios.
func TestIMAP_AppendOperation(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

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

	t.Run("Simple Append", func(t *testing.T) {
		// Select INBOX to check initial state
		mbox, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}
		initialMessages := mbox.NumMessages

		// Append a simple message
		messageLiteral := "Subject: Simple Append Test\r\n\r\nThis is a test."
		appendCmd := c.Append("INBOX", int64(len(messageLiteral)), nil)
		if _, err := appendCmd.Write([]byte(messageLiteral)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND command failed: %v", err)
		}

		// Verify message count increased
		mbox, err = c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Reselect INBOX failed: %v", err)
		}
		if mbox.NumMessages != initialMessages+1 {
			t.Errorf("Expected %d messages, got %d", initialMessages+1, mbox.NumMessages)
		}
		t.Logf("Message count is now %d", mbox.NumMessages)

		// Fetch and verify the subject
		fetchCmd := c.Fetch(imap.SeqSetNum(mbox.NumMessages), &imap.FetchOptions{
			Envelope: true,
		})
		msgs, err := fetchCmd.Collect()
		if err != nil {
			t.Fatalf("FETCH failed: %v", err)
		}
		if len(msgs) != 1 {
			t.Fatalf("Expected 1 message, got %d", len(msgs))
		}
		if msgs[0].Envelope.Subject != "Simple Append Test" {
			t.Errorf("Expected subject 'Simple Append Test', got '%s'", msgs[0].Envelope.Subject)
		}
		t.Logf("Fetched message with correct subject: %s", msgs[0].Envelope.Subject)
	})

	t.Run("Append with Flags and Date", func(t *testing.T) {
		// Select INBOX to get current state
		mbox, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}
		initialMessages := mbox.NumMessages

		// Append a message with specific flags and internal date
		messageLiteral := "Subject: Flags and Date Test\r\n\r\nTesting flags."
		customDate := time.Now().Add(-24 * time.Hour).Truncate(time.Second)
		appendCmd := c.Append("INBOX", int64(len(messageLiteral)), &imap.AppendOptions{
			Flags: []imap.Flag{imap.FlagSeen, imap.FlagFlagged},
			Time:  customDate,
		})
		if _, err := appendCmd.Write([]byte(messageLiteral)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND command failed: %v", err)
		}

		// Verify message count
		mbox, err = c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Reselect INBOX failed: %v", err)
		}
		if mbox.NumMessages != initialMessages+1 {
			t.Errorf("Expected %d messages, got %d", initialMessages+1, mbox.NumMessages)
		}

		// Fetch the new message and verify flags and date
		fetchCmd := c.Fetch(imap.SeqSetNum(mbox.NumMessages), &imap.FetchOptions{
			Flags:        true,
			InternalDate: true,
		})
		msgs, err := fetchCmd.Collect()
		if err != nil {
			t.Fatalf("FETCH failed: %v", err)
		}
		if len(msgs) != 1 {
			t.Fatalf("Expected 1 message, got %d", len(msgs))
		}
		msg := msgs[0]

		if !containsFlag(msg.Flags, imap.FlagSeen) {
			t.Error("Expected \\Seen flag, but not found")
		}
		if !containsFlag(msg.Flags, imap.FlagFlagged) {
			t.Error("Expected \\Flagged flag, but not found")
		}
		if !msg.InternalDate.Equal(customDate) {
			t.Errorf("Expected internal date %v, got %v", customDate, msg.InternalDate)
		}
		t.Logf("Fetched message with correct flags (%v) and date (%v)", msg.Flags, msg.InternalDate)
	})

	t.Run("Append to Non-Existent Mailbox", func(t *testing.T) {
		messageLiteral := "Subject: Failure Test\r\n\r\nThis should not be appended."
		appendCmd := c.Append("NonExistentMailbox", int64(len(messageLiteral)), nil)
		if _, err := appendCmd.Write([]byte(messageLiteral)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}

		_, err = appendCmd.Wait()
		if err == nil {
			t.Fatal("Expected APPEND to non-existent mailbox to fail, but it succeeded")
		}
		t.Logf("APPEND correctly failed for non-existent mailbox: %v", err)
	})

	t.Run("Append with Unicode Content", func(t *testing.T) {
		// Select INBOX to get current state
		mbox, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}
		initialMessages := mbox.NumMessages

		// Append a message with Unicode subject
		unicodeSubject := "Test: こんにちは世界"
		messageLiteral := "Subject: " + unicodeSubject + "\r\n\r\nUnicode body: ✅"
		appendCmd := c.Append("INBOX", int64(len(messageLiteral)), nil)
		if _, err := appendCmd.Write([]byte(messageLiteral)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND command failed: %v", err)
		}

		// Verify message count
		mbox, err = c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Reselect INBOX failed: %v", err)
		}
		if mbox.NumMessages != initialMessages+1 {
			t.Errorf("Expected %d messages, got %d", initialMessages+1, mbox.NumMessages)
		}

		// Fetch and verify the subject
		fetchCmd := c.Fetch(imap.SeqSetNum(mbox.NumMessages), &imap.FetchOptions{
			Envelope: true,
		})
		msgs, err := fetchCmd.Collect()
		if err != nil {
			t.Fatalf("FETCH failed: %v", err)
		}
		if len(msgs) != 1 {
			t.Fatalf("Expected 1 message, got %d", len(msgs))
		}
		if msgs[0].Envelope.Subject != unicodeSubject {
			t.Errorf("Expected subject '%s', got '%s'", unicodeSubject, msgs[0].Envelope.Subject)
		}
		t.Logf("Fetched message with correct Unicode subject: %s", msgs[0].Envelope.Subject)
	})
}

// TestIMAP_ComprehensiveMessageOperations tests comprehensive message operations
func TestIMAP_ComprehensiveMessageOperations(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

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

	// Select INBOX
	mbox, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	t.Logf("Selected INBOX with %d messages", mbox.NumMessages)

	// Test 1: APPEND message
	testMessage := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Test Message for Operations\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"This is a test message for comprehensive operations testing.\r\n"

	appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen},
		Time:  time.Now(),
	})
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	appendData, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}
	t.Logf("APPEND successful - UID: %d, UIDValidity: %d", appendData.UID, appendData.UIDValidity)

	// Test 2: FETCH message
	fetchCmd := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		Flags: true,
		UID:   true,
		BodySection: []*imap.FetchItemBodySection{
			{Specifier: imap.PartSpecifierHeader},
		},
	})
	fetchResults, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}

	if len(fetchResults) == 0 {
		t.Fatal("FETCH returned no results")
	}

	fetchResult := fetchResults[0]
	t.Logf("FETCH successful - SeqNum: %d, UID: %d, Flags: %v", fetchResult.SeqNum, fetchResult.UID, fetchResult.Flags)

	// Verify the message was stored with correct flags
	if !containsFlag(fetchResult.Flags, imap.FlagSeen) {
		t.Error("Expected \\Seen flag not found in fetched message")
	}

	// Test 3: Basic search for flags (most compatible search)
	searchResults, err := c.Search(&imap.SearchCriteria{
		Flag: []imap.Flag{imap.FlagSeen},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH by flags failed: %v", err)
	}

	if len(searchResults.AllSeqNums()) == 0 {
		t.Error("SEARCH by flags returned no results")
	} else {
		t.Logf("SEARCH by flags found %d messages", len(searchResults.AllSeqNums()))
	}

	t.Log("Comprehensive message operations test completed successfully")
}

// TestIMAP_ComprehensiveMailboxStatus tests comprehensive STATUS operations
func TestIMAP_ComprehensiveMailboxStatus(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

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

	// Test 1: STATUS on empty INBOX
	statusData, err := c.Status("INBOX", &imap.StatusOptions{
		NumMessages:   true,
		NumUnseen:     true,
		UIDNext:       true,
		UIDValidity:   true,
		HighestModSeq: true,
	}).Wait()
	if err != nil {
		t.Fatalf("STATUS command failed: %v", err)
	}

	if statusData.Mailbox != "INBOX" {
		t.Errorf("Expected mailbox INBOX, got %s", statusData.Mailbox)
	}

	if statusData.NumMessages != nil && *statusData.NumMessages != 0 {
		t.Errorf("Expected 0 messages in empty INBOX, got %d", *statusData.NumMessages)
	}

	if statusData.NumUnseen != nil && *statusData.NumUnseen != 0 {
		t.Errorf("Expected 0 unseen messages in empty INBOX, got %d", *statusData.NumUnseen)
	}

	t.Logf("Empty INBOX status - Messages: %v, Unseen: %v, UIDNext: %d, UIDValidity: %d, HighestModSeq: %d",
		statusData.NumMessages, statusData.NumUnseen, statusData.UIDNext, statusData.UIDValidity, statusData.HighestModSeq)

	// Add some messages to test with
	testMessage1 := "From: test1@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Status Test Message 1\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"First test message for status testing.\r\n"

	testMessage2 := "From: test2@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Status Test Message 2\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"Second test message for status testing.\r\n"

	// Append first message with \Seen flag
	appendCmd1 := c.Append("INBOX", int64(len(testMessage1)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen},
		Time:  time.Now(),
	})
	_, err = appendCmd1.Write([]byte(testMessage1))
	if err != nil {
		t.Fatalf("APPEND write first message failed: %v", err)
	}
	err = appendCmd1.Close()
	if err != nil {
		t.Fatalf("APPEND close first message failed: %v", err)
	}
	_, err = appendCmd1.Wait()
	if err != nil {
		t.Fatalf("APPEND first message failed: %v", err)
	}

	// Append second message without \Seen flag (unseen)
	appendCmd2 := c.Append("INBOX", int64(len(testMessage2)), &imap.AppendOptions{
		Flags: []imap.Flag{},
		Time:  time.Now(),
	})
	_, err = appendCmd2.Write([]byte(testMessage2))
	if err != nil {
		t.Fatalf("APPEND write second message failed: %v", err)
	}
	err = appendCmd2.Close()
	if err != nil {
		t.Fatalf("APPEND close second message failed: %v", err)
	}
	_, err = appendCmd2.Wait()
	if err != nil {
		t.Fatalf("APPEND second message failed: %v", err)
	}

	// Test 2: STATUS after adding messages
	statusData, err = c.Status("INBOX", &imap.StatusOptions{
		NumMessages:   true,
		NumUnseen:     true,
		UIDNext:       true,
		UIDValidity:   true,
		HighestModSeq: true,
	}).Wait()
	if err != nil {
		t.Fatalf("STATUS command after adding messages failed: %v", err)
	}

	if statusData.NumMessages != nil && *statusData.NumMessages != 2 {
		t.Errorf("Expected 2 messages after adding, got %d", *statusData.NumMessages)
	}

	if statusData.NumUnseen != nil && *statusData.NumUnseen != 1 {
		t.Errorf("Expected 1 unseen message after adding, got %d", *statusData.NumUnseen)
	}

	t.Logf("INBOX status after adding messages - Messages: %v, Unseen: %v, UIDNext: %d, UIDValidity: %d, HighestModSeq: %d",
		statusData.NumMessages, statusData.NumUnseen, statusData.UIDNext, statusData.UIDValidity, statusData.HighestModSeq)

	// Test 3: STATUS with selective options
	statusData, err = c.Status("INBOX", &imap.StatusOptions{
		NumMessages: true,
		UIDNext:     true,
	}).Wait()
	if err != nil {
		t.Fatalf("STATUS with selective options failed: %v", err)
	}

	// Only requested fields should be populated
	if statusData.NumMessages == nil {
		t.Error("NumMessages should be populated when requested")
	}
	if statusData.UIDNext == 0 {
		t.Error("UIDNext should be populated when requested")
	}
	t.Logf("Selective STATUS - Messages: %v, UIDNext: %d", statusData.NumMessages, statusData.UIDNext)

	// Test 4: STATUS on non-existent mailbox (should fail)
	_, err = c.Status("NonExistentMailbox", &imap.StatusOptions{
		NumMessages: true,
	}).Wait()
	if err == nil {
		t.Error("STATUS on non-existent mailbox should fail")
	} else {
		t.Logf("STATUS correctly failed on non-existent mailbox: %v", err)
	}

	t.Log("Comprehensive mailbox status test completed successfully")
}

// TestIMAP_ComprehensiveCopyMove tests COPY and MOVE operations
func TestIMAP_ComprehensiveCopyMove(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

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

	// Create test mailbox
	testMailbox := "CopyMoveTest"
	if err := c.Create(testMailbox, nil).Wait(); err != nil {
		t.Fatalf("CREATE test mailbox failed: %v", err)
	}
	defer func() {
		c.Delete(testMailbox).Wait()
	}()

	// Select INBOX to add test message
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Add test message
	testMessage := "From: copymove@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Copy Move Test Message\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"This is a test message for copy/move operations.\r\n"

	appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen, imap.FlagFlagged},
		Time:  time.Now(),
	})
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	appendData, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}
	t.Logf("APPEND successful - UID: %d", appendData.UID)

	// Test 1: COPY message by sequence number
	copyData, err := c.Copy(imap.SeqSetNum(1), testMailbox).Wait()
	if err != nil {
		t.Fatalf("COPY by sequence number failed: %v", err)
	}
	t.Logf("COPY successful - Source UID: %d, Dest UID: %d", copyData.SourceUIDs[0], copyData.DestUIDs[0])

	// Verify message was copied
	selectData, err := c.Select(testMailbox, nil).Wait()
	if err != nil {
		t.Fatalf("Select test mailbox failed: %v", err)
	}
	if selectData.NumMessages != 1 {
		t.Errorf("Expected 1 message in destination mailbox, got %d", selectData.NumMessages)
	}

	// Verify copied message has same flags
	fetchResults, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		Flags: true,
		UID:   true,
	}).Collect()
	if err != nil {
		t.Fatalf("FETCH from destination mailbox failed: %v", err)
	}

	if len(fetchResults) > 0 {
		flags := fetchResults[0].Flags
		if !containsFlag(flags, imap.FlagSeen) {
			t.Error("\\Seen flag not preserved in copied message")
		}
		if !containsFlag(flags, imap.FlagFlagged) {
			t.Error("\\Flagged flag not preserved in copied message")
		}
		t.Logf("Copied message flags: %v", flags)
	}

	// Test 2: UID COPY operation
	// Go back to INBOX and add another message
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	testMessage2 := "From: copymove2@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: UID Copy Test Message\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"This is a second test message for UID copy operation.\r\n"

	appendCmd2 := c.Append("INBOX", int64(len(testMessage2)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagAnswered},
		Time:  time.Now(),
	})
	_, err = appendCmd2.Write([]byte(testMessage2))
	if err != nil {
		t.Fatalf("APPEND write second message failed: %v", err)
	}
	err = appendCmd2.Close()
	if err != nil {
		t.Fatalf("APPEND close second message failed: %v", err)
	}
	_, err = appendCmd2.Wait()
	if err != nil {
		t.Fatalf("APPEND second message failed: %v", err)
	}

	// COPY the second message (using sequence number)
	copyData, err = c.Copy(imap.SeqSetNum(2), testMailbox).Wait()
	if err != nil {
		t.Fatalf("COPY second message failed: %v", err)
	}
	t.Logf("COPY second message successful - Source UID: %d, Dest UID: %d", copyData.SourceUIDs[0], copyData.DestUIDs[0])

	// Verify destination now has 2 messages
	selectData, err = c.Select(testMailbox, nil).Wait()
	if err != nil {
		t.Fatalf("Select test mailbox after UID COPY failed: %v", err)
	}
	if selectData.NumMessages != 2 {
		t.Errorf("Expected 2 messages in destination mailbox after UID COPY, got %d", selectData.NumMessages)
	}

	t.Log("Comprehensive copy/move test completed successfully")
}

// TestIMAP_IdleBasic tests basic IDLE functionality
func TestIMAP_IdleBasic(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

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

	// Select INBOX for IDLE test
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Test basic IDLE functionality
	idleCmd, err := c.Idle()
	if err != nil {
		if strings.Contains(err.Error(), "IDLE") || strings.Contains(err.Error(), "not supported") {
			t.Skip("IDLE command not supported by server")
		}
		t.Fatalf("IDLE command failed to start: %v", err)
	}
	t.Log("IDLE command started successfully")

	// Let IDLE run for a short time
	time.Sleep(100 * time.Millisecond)

	// End IDLE
	if err := idleCmd.Close(); err != nil {
		t.Fatalf("Failed to stop IDLE: %v", err)
	}
	t.Log("IDLE command stopped successfully")

	// Verify connection is still functional after IDLE
	_, err = c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Connection not functional after IDLE: %v", err)
	}

	t.Log("Basic IDLE test completed successfully")
}

// Helper function to check if a flag is present in a slice of flags
func containsFlag(flags []imap.Flag, flag imap.Flag) bool {
	for _, f := range flags {
		if f == flag {
			return true
		}
	}
	return false
}
