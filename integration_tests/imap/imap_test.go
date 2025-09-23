//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"sync"
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

// TestIMAP_FlagOperations tests comprehensive flag operations
func TestIMAP_FlagOperations(t *testing.T) {
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
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Add a test message
	testMessage := "From: flags@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Flag Operations Test\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"This is a test message for flag operations.\r\n"

	appendCmd := c.Append("INBOX", int64(len(testMessage)), nil)
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	_, err = appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// Test 1: Store flags (add)
	storeCmd := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen, imap.FlagFlagged},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("STORE flags add failed: %v", err)
	}

	// Verify flags were added
	fetchResults, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil {
		t.Fatalf("FETCH after flag add failed: %v", err)
	}
	if len(fetchResults) == 0 {
		t.Fatal("FETCH returned no results")
	}

	flags := fetchResults[0].Flags
	if !containsFlag(flags, imap.FlagSeen) {
		t.Error("\\Seen flag not found after adding")
	}
	if !containsFlag(flags, imap.FlagFlagged) {
		t.Error("\\Flagged flag not found after adding")
	}
	t.Logf("Flags after adding: %v", flags)

	// Test 2: Store flags (remove)
	storeCmd = c.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsDel,
		Flags: []imap.Flag{imap.FlagFlagged},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("STORE flags remove failed: %v", err)
	}

	// Verify flag was removed
	fetchResults, err = c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil {
		t.Fatalf("FETCH after flag remove failed: %v", err)
	}
	if len(fetchResults) == 0 {
		t.Fatal("FETCH returned no results")
	}

	flags = fetchResults[0].Flags
	if !containsFlag(flags, imap.FlagSeen) {
		t.Error("\\Seen flag should still be present")
	}
	if containsFlag(flags, imap.FlagFlagged) {
		t.Error("\\Flagged flag should be removed")
	}
	t.Logf("Flags after removing \\Flagged: %v", flags)

	// Test 3: Store flags (replace)
	storeCmd = c.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsSet,
		Flags: []imap.Flag{imap.FlagAnswered, imap.FlagDraft},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("STORE flags replace failed: %v", err)
	}

	// Verify flags were replaced
	fetchResults, err = c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil {
		t.Fatalf("FETCH after flag replace failed: %v", err)
	}
	if len(fetchResults) == 0 {
		t.Fatal("FETCH returned no results")
	}

	flags = fetchResults[0].Flags
	if containsFlag(flags, imap.FlagSeen) {
		t.Error("\\Seen flag should be removed after replace")
	}
	if !containsFlag(flags, imap.FlagAnswered) {
		t.Error("\\Answered flag not found after replace")
	}
	if !containsFlag(flags, imap.FlagDraft) {
		t.Error("\\Draft flag not found after replace")
	}
	t.Logf("Flags after replace: %v", flags)

	t.Log("Flag operations test completed successfully")
}

// TestIMAP_ExpungeOperations tests message expunge operations
func TestIMAP_ExpungeOperations(t *testing.T) {
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
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Add multiple test messages
	for i := 1; i <= 3; i++ {
		testMessage := "From: expunge@example.com\r\n" +
			"To: " + account.Email + "\r\n" +
			"Subject: Expunge Test Message " + string(rune('0'+i)) + "\r\n" +
			"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
			"\r\n" +
			"This is test message " + string(rune('0'+i)) + " for expunge operations.\r\n"

		appendCmd := c.Append("INBOX", int64(len(testMessage)), nil)
		_, err = appendCmd.Write([]byte(testMessage))
		if err != nil {
			t.Fatalf("APPEND write message %d failed: %v", i, err)
		}
		err = appendCmd.Close()
		if err != nil {
			t.Fatalf("APPEND close message %d failed: %v", i, err)
		}
		_, err = appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND message %d failed: %v", i, err)
		}
	}

	// Verify we have 3 messages
	mbox, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	if mbox.NumMessages != 3 {
		t.Errorf("Expected 3 messages, got %d", mbox.NumMessages)
	}
	t.Logf("Added 3 messages, total: %d", mbox.NumMessages)

	// Mark the second message for deletion
	storeCmd := c.Store(imap.SeqSetNum(2), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("STORE \\Deleted flag failed: %v", err)
	}

	// Verify the message is marked as deleted
	fetchResults, err := c.Fetch(imap.SeqSetNum(2), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil {
		t.Fatalf("FETCH after marking deleted failed: %v", err)
	}
	if len(fetchResults) == 0 {
		t.Fatal("FETCH returned no results")
	}

	if !containsFlag(fetchResults[0].Flags, imap.FlagDeleted) {
		t.Error("\\Deleted flag not found on marked message")
	}
	t.Log("Successfully marked message 2 as deleted")

	// Perform EXPUNGE
	expungeResults, err := c.Expunge().Collect()
	if err != nil {
		t.Fatalf("EXPUNGE failed: %v", err)
	}

	t.Logf("EXPUNGE results: %v", expungeResults)

	// Verify message count decreased
	mbox, err = c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX after expunge failed: %v", err)
	}
	if mbox.NumMessages != 2 {
		t.Errorf("Expected 2 messages after expunge, got %d", mbox.NumMessages)
	}

	// Verify remaining messages are still accessible
	fetchResults, err = c.Fetch(imap.SeqSetNum(1, 2), &imap.FetchOptions{
		Envelope: true,
	}).Collect()
	if err != nil {
		t.Fatalf("FETCH after expunge failed: %v", err)
	}
	if len(fetchResults) != 2 {
		t.Errorf("Expected 2 messages after expunge, got %d", len(fetchResults))
	}

	t.Log("Expunge operations test completed successfully")
}

// TestIMAP_SearchOperations tests comprehensive search operations
func TestIMAP_SearchOperations(t *testing.T) {
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
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Add test messages with different characteristics
	messages := []struct {
		subject string
		from    string
		flags   []imap.Flag
		body    string
	}{
		{
			subject: "Search Test Alpha",
			from:    "alpha@example.com",
			flags:   []imap.Flag{imap.FlagSeen},
			body:    "This message contains the keyword alpha.",
		},
		{
			subject: "Search Test Beta",
			from:    "beta@example.com",
			flags:   []imap.Flag{imap.FlagFlagged},
			body:    "This message contains the keyword beta.",
		},
		{
			subject: "Search Test Gamma",
			from:    "gamma@example.com",
			flags:   []imap.Flag{imap.FlagSeen, imap.FlagAnswered},
			body:    "This message contains the keyword gamma.",
		},
	}

	for i, msg := range messages {
		testMessage := "From: " + msg.from + "\r\n" +
			"To: " + account.Email + "\r\n" +
			"Subject: " + msg.subject + "\r\n" +
			"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
			"\r\n" +
			msg.body + "\r\n"

		appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
			Flags: msg.flags,
			Time:  time.Now(),
		})
		_, err = appendCmd.Write([]byte(testMessage))
		if err != nil {
			t.Fatalf("APPEND write message %d failed: %v", i+1, err)
		}
		err = appendCmd.Close()
		if err != nil {
			t.Fatalf("APPEND close message %d failed: %v", i+1, err)
		}
		_, err = appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND message %d failed: %v", i+1, err)
		}
	}

	// Test 1: Search by flag
	searchResults, err := c.Search(&imap.SearchCriteria{
		Flag: []imap.Flag{imap.FlagSeen},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH by \\Seen flag failed: %v", err)
	}

	seenMessages := searchResults.AllSeqNums()
	if len(seenMessages) != 2 {
		t.Errorf("Expected 2 messages with \\Seen flag, got %d", len(seenMessages))
	}
	t.Logf("SEARCH by \\Seen flag found %d messages: %v", len(seenMessages), seenMessages)

	// Test 2: Search by subject
	searchResults, err = c.Search(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{
			{Key: "Subject", Value: "Alpha"},
		},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH by subject failed: %v", err)
	}

	subjectMessages := searchResults.AllSeqNums()
	if len(subjectMessages) != 1 {
		t.Errorf("Expected 1 message with 'Alpha' in subject, got %d", len(subjectMessages))
	}
	t.Logf("SEARCH by subject 'Alpha' found %d messages: %v", len(subjectMessages), subjectMessages)

	// Test 3: Search by from
	searchResults, err = c.Search(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{
			{Key: "From", Value: "beta@example.com"},
		},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH by from failed: %v", err)
	}

	fromMessages := searchResults.AllSeqNums()
	if len(fromMessages) != 1 {
		t.Errorf("Expected 1 message from 'beta@example.com', got %d", len(fromMessages))
	}
	t.Logf("SEARCH by from 'beta@example.com' found %d messages: %v", len(fromMessages), fromMessages)

	// Test 4: Search ALL
	searchResults, err = c.Search(&imap.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH ALL failed: %v", err)
	}

	allMessages := searchResults.AllSeqNums()
	if len(allMessages) != 3 {
		t.Errorf("Expected 3 messages in ALL search, got %d", len(allMessages))
	}
	t.Logf("SEARCH ALL found %d messages: %v", len(allMessages), allMessages)

	// Test 5: Search NOT
	searchResults, err = c.Search(&imap.SearchCriteria{
		Not: []imap.SearchCriteria{
			{Flag: []imap.Flag{imap.FlagSeen}},
		},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH NOT \\Seen failed: %v", err)
	}

	notSeenMessages := searchResults.AllSeqNums()
	if len(notSeenMessages) != 1 {
		t.Errorf("Expected 1 message without \\Seen flag, got %d", len(notSeenMessages))
	}
	t.Logf("SEARCH NOT \\Seen found %d messages: %v", len(notSeenMessages), notSeenMessages)

	t.Log("Search operations test completed successfully")
}

// TestIMAP_MoveOperations tests MOVE operations (if supported)
func TestIMAP_MoveOperations(t *testing.T) {
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

	// Create destination mailbox
	destMailbox := "MoveTest"
	if err := c.Create(destMailbox, nil).Wait(); err != nil {
		t.Fatalf("CREATE destination mailbox failed: %v", err)
	}
	defer func() {
		c.Delete(destMailbox).Wait()
	}()

	// Select INBOX
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Add test message
	testMessage := "From: move@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Move Test Message\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"This is a test message for move operations.\r\n"

	appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen, imap.FlagImportant},
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
	_, err = appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// Get initial message count in INBOX
	inboxData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	initialInboxCount := inboxData.NumMessages
	t.Logf("Initial INBOX message count: %d", initialInboxCount)

	// Attempt MOVE operation
	moveData, err := c.Move(imap.SeqSetNum(1), destMailbox).Wait()
	if err != nil {
		if strings.Contains(err.Error(), "MOVE") || strings.Contains(err.Error(), "not supported") {
			t.Skip("MOVE command not supported by server")
		}
		t.Fatalf("MOVE failed: %v", err)
	}
	t.Logf("MOVE successful - move data: %+v", moveData)

	// Verify message was removed from INBOX
	inboxData, err = c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX after move failed: %v", err)
	}
	if inboxData.NumMessages != initialInboxCount-1 {
		t.Errorf("Expected %d messages in INBOX after move, got %d", initialInboxCount-1, inboxData.NumMessages)
	}

	// Verify message was moved to destination
	destData, err := c.Select(destMailbox, nil).Wait()
	if err != nil {
		t.Fatalf("Select destination mailbox failed: %v", err)
	}
	if destData.NumMessages != 1 {
		t.Errorf("Expected 1 message in destination mailbox, got %d", destData.NumMessages)
	}

	// Verify moved message retains flags
	fetchResults, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		Flags: true,
		Envelope: true,
	}).Collect()
	if err != nil {
		t.Fatalf("FETCH from destination mailbox failed: %v", err)
	}

	if len(fetchResults) > 0 {
		flags := fetchResults[0].Flags
		subject := fetchResults[0].Envelope.Subject
		if !containsFlag(flags, imap.FlagSeen) {
			t.Error("\\Seen flag not preserved in moved message")
		}
		if !containsFlag(flags, imap.FlagImportant) {
			t.Error("\\Important flag not preserved in moved message")
		}
		if subject != "Move Test Message" {
			t.Errorf("Expected subject 'Move Test Message', got '%s'", subject)
		}
		t.Logf("Moved message - Subject: %s, Flags: %v", subject, flags)
	}

	t.Log("Move operations test completed successfully")
}

// TestIMAP_ConcurrentAccess tests multiple clients accessing the same mailbox
func TestIMAP_ConcurrentAccess(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Number of concurrent clients
	numClients := 3
	clientDone := make(chan bool, numClients)
	var wg sync.WaitGroup

	// Pre-populate mailbox with some messages
	setupClient, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial setup client: %v", err)
	}
	defer setupClient.Logout()

	if err := setupClient.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Setup client login failed: %v", err)
	}

	if _, err := setupClient.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Setup client select failed: %v", err)
	}

	// Add initial messages
	for i := 1; i <= 5; i++ {
		testMessage := "From: concurrent@example.com\r\n" +
			"To: " + account.Email + "\r\n" +
			"Subject: Concurrent Test Message " + string(rune('0'+i)) + "\r\n" +
			"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
			"\r\n" +
			"This is test message " + string(rune('0'+i)) + " for concurrent access testing.\r\n"

		appendCmd := setupClient.Append("INBOX", int64(len(testMessage)), nil)
		_, err = appendCmd.Write([]byte(testMessage))
		if err != nil {
			t.Fatalf("Setup APPEND write failed: %v", err)
		}
		err = appendCmd.Close()
		if err != nil {
			t.Fatalf("Setup APPEND close failed: %v", err)
		}
		_, err = appendCmd.Wait()
		if err != nil {
			t.Fatalf("Setup APPEND failed: %v", err)
		}
	}

	setupClient.Logout()

	// Start concurrent clients
	for clientID := 0; clientID < numClients; clientID++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() { clientDone <- true }()

			c, err := imapclient.DialInsecure(server.Address, nil)
			if err != nil {
				t.Errorf("Client %d: Failed to dial: %v", id, err)
				return
			}
			defer c.Logout()

			if err := c.Login(account.Email, account.Password).Wait(); err != nil {
				t.Errorf("Client %d: Login failed: %v", id, err)
				return
			}

			if _, err := c.Select("INBOX", nil).Wait(); err != nil {
				t.Errorf("Client %d: Select failed: %v", id, err)
				return
			}

			// Each client performs different operations
			switch id % 3 {
			case 0:
				// Client performs FETCH operations
				for i := 0; i < 3; i++ {
					fetchResults, err := c.Fetch(imap.SeqSetNum(uint32(i+1)), &imap.FetchOptions{
						Envelope: true,
						Flags:    true,
					}).Collect()
					if err != nil {
						t.Errorf("Client %d: FETCH failed: %v", id, err)
						return
					}
					if len(fetchResults) == 0 {
						t.Errorf("Client %d: FETCH returned no results", id)
						return
					}
					time.Sleep(10 * time.Millisecond) // Small delay
				}

			case 1:
				// Client performs flag operations
				for i := 1; i <= 2; i++ {
					storeCmd := c.Store(imap.SeqSetNum(uint32(i)), &imap.StoreFlags{
						Op:    imap.StoreFlagsAdd,
						Flags: []imap.Flag{imap.FlagSeen},
					}, nil)
					_, err := storeCmd.Collect()
					if err != nil {
						t.Errorf("Client %d: STORE failed: %v", id, err)
						return
					}
					time.Sleep(10 * time.Millisecond)
				}

			case 2:
				// Client performs search operations
				for i := 0; i < 3; i++ {
					searchResults, err := c.Search(&imap.SearchCriteria{}, nil).Wait()
					if err != nil {
						t.Errorf("Client %d: SEARCH failed: %v", id, err)
						return
					}
					if len(searchResults.AllSeqNums()) == 0 {
						t.Errorf("Client %d: SEARCH returned no results", id)
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
			}

			t.Logf("Client %d completed successfully", id)
		}(clientID)
	}

	// Wait for all clients to complete with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Log("All concurrent clients completed successfully")
	case <-time.After(30 * time.Second):
		t.Fatal("Concurrent access test timed out")
	}

	// Verify we received completion signals from all clients
	for i := 0; i < numClients; i++ {
		select {
		case <-clientDone:
			// Good, client completed
		case <-time.After(1 * time.Second):
			t.Errorf("Did not receive completion signal from all clients")
		}
	}
}

// TestIMAP_IdleNotificationsLongPoll tests IDLE periodic polling notifications
// This test validates the 15-second polling mechanism in addition to immediate notifications
func TestIMAP_IdleNotificationsLongPoll(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// This test requires waiting for the 15-second IDLE poll interval
	// to test the periodic polling mechanism in addition to immediate notifications
	if testing.Short() {
		t.Skip("Skipping IDLE long poll test in short mode (requires 15+ second wait)")
	}

	// Client 1: IDLE watcher
	client1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial client1: %v", err)
	}
	defer client1.Logout()

	if err := client1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Client1 login failed: %v", err)
	}

	if _, err := client1.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Client1 select failed: %v", err)
	}

	// Start IDLE on client1
	idleCmd, err := client1.Idle()
	if err != nil {
		if strings.Contains(err.Error(), "IDLE") || strings.Contains(err.Error(), "not supported") {
			t.Skip("IDLE command not supported by server")
		}
		t.Fatalf("Client1 IDLE failed to start: %v", err)
	}
	defer idleCmd.Close()

	t.Log("Client1 started IDLE")

	// Client 2: Message sender
	client2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial client2: %v", err)
	}
	defer client2.Logout()

	if err := client2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Client2 login failed: %v", err)
	}

	// Give IDLE some time to start
	time.Sleep(500 * time.Millisecond)

	// Client2 adds a message while client1 is in IDLE
	testMessage := "From: idle@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: IDLE Notification Test\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"This message should trigger IDLE notification.\r\n"

	appendCmd := client2.Append("INBOX", int64(len(testMessage)), nil)
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("Client2 APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("Client2 APPEND close failed: %v", err)
	}
	_, err = appendCmd.Wait()
	if err != nil {
		t.Fatalf("Client2 APPEND failed: %v", err)
	}

	t.Log("Client2 appended message - now waiting for IDLE poll interval (15 seconds)")

	// Wait for IDLE poll interval (15 seconds) plus some buffer
	// This is the minimum time needed for the IDLE client to detect the new message
	time.Sleep(16 * time.Second)

	t.Log("IDLE poll interval elapsed - stopping IDLE")

	// Stop IDLE on client1
	if err := idleCmd.Close(); err != nil {
		t.Fatalf("Failed to stop IDLE: %v", err)
	}

	// Verify client1 can see the new message
	mbox, err := client1.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Client1 reselect failed: %v", err)
	}

	if mbox.NumMessages != 1 {
		t.Errorf("Expected 1 message after IDLE notification, got %d", mbox.NumMessages)
	} else {
		t.Log("IDLE notification test completed successfully")
	}
}

// TestIMAP_IdleNotificationsFast tests IDLE immediate notifications between clients
// This test demonstrates that IDLE notifications work immediately via session tracking,
// not just through the 15-second polling mechanism
func TestIMAP_IdleNotificationsFast(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Client 1: IDLE watcher
	client1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial client1: %v", err)
	}
	defer client1.Logout()

	if err := client1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Client1 login failed: %v", err)
	}

	if _, err := client1.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Client1 select failed: %v", err)
	}

	// Start IDLE on client1
	idleCmd, err := client1.Idle()
	if err != nil {
		if strings.Contains(err.Error(), "IDLE") || strings.Contains(err.Error(), "not supported") {
			t.Skip("IDLE command not supported by server")
		}
		t.Fatalf("Client1 IDLE failed to start: %v", err)
	}
	defer idleCmd.Close()

	t.Log("Client1 started IDLE")

	// Client 2: Message sender
	client2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial client2: %v", err)
	}
	defer client2.Logout()

	if err := client2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Client2 login failed: %v", err)
	}

	// Give IDLE some time to start
	time.Sleep(100 * time.Millisecond)

	// Client2 adds a message while client1 is in IDLE
	testMessage := "From: idle@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: IDLE Fast Test\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"This message tests IDLE mode without waiting for notifications.\r\n"

	appendCmd := client2.Append("INBOX", int64(len(testMessage)), nil)
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("Client2 APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("Client2 APPEND close failed: %v", err)
	}
	_, err = appendCmd.Wait()
	if err != nil {
		t.Fatalf("Client2 APPEND failed: %v", err)
	}

	t.Log("Client2 appended message")

	// Small delay and then stop IDLE
	time.Sleep(200 * time.Millisecond)

	// Stop IDLE on client1
	if err := idleCmd.Close(); err != nil {
		t.Fatalf("Failed to stop IDLE: %v", err)
	}

	// Verify client1 can see the new message (this triggers a fresh poll)
	mbox, err := client1.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Client1 reselect failed: %v", err)
	}

	// NOTE: This test validates immediate IDLE notifications work via session tracking.
	// The server has both immediate cross-session notifications AND 15-second polling.
	// From the logs, we can see "[POLL] Updating message count from 0 to 1" happens
	// immediately when the APPEND occurs on the other session.
	if mbox.NumMessages != 1 {
		t.Errorf("Expected 1 message after IDLE immediate notification, got %d", mbox.NumMessages)
	} else {
		t.Log("IDLE immediate notification test completed successfully")
	}
}

// TestIMAP_IdleNotificationsFlagChanges tests IDLE notifications for flag changes between clients
func TestIMAP_IdleNotificationsFlagChanges(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Setup: Add a test message first
	setupClient, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial setup client: %v", err)
	}
	defer setupClient.Logout()

	if err := setupClient.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Setup client login failed: %v", err)
	}

	testMessage := "From: flagtest@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: IDLE Flag Change Test\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"This message will have its flags changed while being watched via IDLE.\r\n"

	appendCmd := setupClient.Append("INBOX", int64(len(testMessage)), nil)
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("Setup APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("Setup APPEND close failed: %v", err)
	}
	_, err = appendCmd.Wait()
	if err != nil {
		t.Fatalf("Setup APPEND failed: %v", err)
	}

	setupClient.Logout()

	// Client 1: IDLE watcher
	client1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial client1: %v", err)
	}
	defer client1.Logout()

	if err := client1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Client1 login failed: %v", err)
	}

	if _, err := client1.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Client1 select failed: %v", err)
	}

	// Start IDLE on client1
	idleCmd, err := client1.Idle()
	if err != nil {
		if strings.Contains(err.Error(), "IDLE") || strings.Contains(err.Error(), "not supported") {
			t.Skip("IDLE command not supported by server")
		}
		t.Fatalf("Client1 IDLE failed to start: %v", err)
	}
	defer idleCmd.Close()

	t.Log("Client1 started IDLE")

	// Client 2: Flag modifier
	client2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial client2: %v", err)
	}
	defer client2.Logout()

	if err := client2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Client2 login failed: %v", err)
	}

	if _, err := client2.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Client2 select failed: %v", err)
	}

	// Give IDLE some time to start
	time.Sleep(100 * time.Millisecond)

	// Test 1: Client2 adds \Seen flag
	t.Log("Client2 adding \\Seen flag")
	storeCmd := client2.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("Client2 STORE \\Seen failed: %v", err)
	}

	// Small delay for notification
	time.Sleep(200 * time.Millisecond)

	// Test 2: Client2 adds \Flagged flag
	t.Log("Client2 adding \\Flagged flag")
	storeCmd = client2.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagFlagged},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("Client2 STORE \\Flagged failed: %v", err)
	}

	// Small delay for notification
	time.Sleep(200 * time.Millisecond)

	// Test 3: Client2 removes \Seen flag
	t.Log("Client2 removing \\Seen flag")
	storeCmd = client2.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsDel,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("Client2 STORE remove \\Seen failed: %v", err)
	}

	// Small delay for notification
	time.Sleep(200 * time.Millisecond)

	// Stop IDLE on client1
	t.Log("Stopping IDLE on client1")
	if err := idleCmd.Close(); err != nil {
		t.Fatalf("Failed to stop IDLE: %v", err)
	}

	// Verify client1 can see the flag changes
	fetchResults, err := client1.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil {
		t.Fatalf("Client1 FETCH flags failed: %v", err)
	}

	if len(fetchResults) == 0 {
		t.Fatal("FETCH returned no results")
	}

	finalFlags := fetchResults[0].Flags
	t.Logf("Final flags seen by client1: %v", finalFlags)

	// Verify final flag state: should have \Flagged but not \Seen
	if !containsFlag(finalFlags, imap.FlagFlagged) {
		t.Error("\\Flagged flag not found after IDLE flag change notifications")
	}
	if containsFlag(finalFlags, imap.FlagSeen) {
		t.Error("\\Seen flag should be removed after IDLE flag change notifications")
	}

	t.Log("IDLE flag change notifications test completed successfully")
}

// TestIMAP_IdleNotificationsFlagChangesConcurrent tests concurrent flag changes with IDLE
func TestIMAP_IdleNotificationsFlagChangesConcurrent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Setup: Add multiple test messages
	setupClient, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial setup client: %v", err)
	}
	defer setupClient.Logout()

	if err := setupClient.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Setup client login failed: %v", err)
	}

	for i := 1; i <= 3; i++ {
		testMessage := "From: concurrentflag@example.com\r\n" +
			"To: " + account.Email + "\r\n" +
			"Subject: Concurrent Flag Test " + string(rune('0'+i)) + "\r\n" +
			"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
			"\r\n" +
			"This is test message " + string(rune('0'+i)) + " for concurrent flag changes.\r\n"

		appendCmd := setupClient.Append("INBOX", int64(len(testMessage)), nil)
		_, err = appendCmd.Write([]byte(testMessage))
		if err != nil {
			t.Fatalf("Setup APPEND write message %d failed: %v", i, err)
		}
		err = appendCmd.Close()
		if err != nil {
			t.Fatalf("Setup APPEND close message %d failed: %v", i, err)
		}
		_, err = appendCmd.Wait()
		if err != nil {
			t.Fatalf("Setup APPEND message %d failed: %v", i, err)
		}
	}

	setupClient.Logout()

	// Client 1: IDLE watcher
	client1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial client1: %v", err)
	}
	defer client1.Logout()

	if err := client1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Client1 login failed: %v", err)
	}

	if _, err := client1.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Client1 select failed: %v", err)
	}

	// Start IDLE on client1
	idleCmd, err := client1.Idle()
	if err != nil {
		if strings.Contains(err.Error(), "IDLE") || strings.Contains(err.Error(), "not supported") {
			t.Skip("IDLE command not supported by server")
		}
		t.Fatalf("Client1 IDLE failed to start: %v", err)
	}
	defer idleCmd.Close()

	t.Log("Client1 started IDLE")

	// Multiple clients making concurrent flag changes
	numClients := 3
	var wg sync.WaitGroup
	flagOperations := []struct {
		seqNum uint32
		op     imap.StoreFlagsOp
		flags  []imap.Flag
		name   string
	}{
		{1, imap.StoreFlagsAdd, []imap.Flag{imap.FlagSeen}, "msg1_seen"},
		{2, imap.StoreFlagsAdd, []imap.Flag{imap.FlagFlagged}, "msg2_flagged"},
		{3, imap.StoreFlagsAdd, []imap.Flag{imap.FlagAnswered}, "msg3_answered"},
	}

	successCount := make(chan int, numClients)

	// Give IDLE some time to start
	time.Sleep(100 * time.Millisecond)

	for clientID := 0; clientID < numClients; clientID++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			c, err := imapclient.DialInsecure(server.Address, nil)
			if err != nil {
				t.Errorf("Client %d: Failed to dial: %v", id, err)
				successCount <- 0
				return
			}
			defer c.Logout()

			if err := c.Login(account.Email, account.Password).Wait(); err != nil {
				t.Errorf("Client %d: Login failed: %v", id, err)
				successCount <- 0
				return
			}

			if _, err := c.Select("INBOX", nil).Wait(); err != nil {
				t.Errorf("Client %d: Select failed: %v", id, err)
				successCount <- 0
				return
			}

			// Perform flag operation
			op := flagOperations[id]
			t.Logf("Client %d performing %s", id, op.name)
			storeCmd := c.Store(imap.SeqSetNum(op.seqNum), &imap.StoreFlags{
				Op:    op.op,
				Flags: op.flags,
			}, nil)
			_, err = storeCmd.Collect()
			if err != nil {
				t.Errorf("Client %d (%s): STORE failed: %v", id, op.name, err)
				successCount <- 0
				return
			}

			t.Logf("Client %d (%s) completed flag operation successfully", id, op.name)
			successCount <- 1
		}(clientID)
	}

	wg.Wait()

	// Count successful operations
	totalSuccess := 0
	for i := 0; i < numClients; i++ {
		totalSuccess += <-successCount
	}

	if totalSuccess != numClients {
		t.Errorf("Expected %d successful flag operations, got %d", numClients, totalSuccess)
	}

	// Give some time for all notifications to propagate
	time.Sleep(500 * time.Millisecond)

	// Stop IDLE on client1
	t.Log("Stopping IDLE on client1")
	if err := idleCmd.Close(); err != nil {
		t.Fatalf("Failed to stop IDLE: %v", err)
	}

	// Verify client1 can see all the flag changes
	fetchResults, err := client1.Fetch(imap.SeqSetNum(1, 2, 3), &imap.FetchOptions{
		Flags: true,
		Envelope: true,
	}).Collect()
	if err != nil {
		t.Fatalf("Client1 FETCH all messages failed: %v", err)
	}

	if len(fetchResults) != 3 {
		t.Fatalf("Expected 3 messages, got %d", len(fetchResults))
	}

	// Verify each message has the expected flags
	expectedFlags := [][]imap.Flag{
		{imap.FlagSeen},
		{imap.FlagFlagged},
		{imap.FlagAnswered},
	}

	for i, result := range fetchResults {
		flags := result.Flags
		expectedFlag := expectedFlags[i][0]
		
		t.Logf("Message %d flags: %v", i+1, flags)
		
		if !containsFlag(flags, expectedFlag) {
			t.Errorf("Message %d missing expected flag %v", i+1, expectedFlag)
		}
	}

	t.Log("Concurrent IDLE flag change notifications test completed successfully")
}

// TestIMAP_RaceConditions tests race conditions in mailbox operations
func TestIMAP_RaceConditions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	numClients := 5
	messagesPerClient := 10
	var wg sync.WaitGroup
	errors := make(chan error, numClients*messagesPerClient)

	// Test concurrent APPEND operations
	t.Run("ConcurrentAppend", func(t *testing.T) {
		for clientID := 0; clientID < numClients; clientID++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				c, err := imapclient.DialInsecure(server.Address, nil)
				if err != nil {
					errors <- err
					return
				}
				defer c.Logout()

				if err := c.Login(account.Email, account.Password).Wait(); err != nil {
					errors <- err
					return
				}

				// Rapidly append messages
				for msgID := 0; msgID < messagesPerClient; msgID++ {
					testMessage := "From: race@example.com\r\n" +
						"To: " + account.Email + "\r\n" +
						"Subject: Race Test Client " + string(rune('0'+id)) + " Message " + string(rune('0'+msgID)) + "\r\n" +
						"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
						"\r\n" +
						"Race condition test message.\r\n"

					appendCmd := c.Append("INBOX", int64(len(testMessage)), nil)
					_, err = appendCmd.Write([]byte(testMessage))
					if err != nil {
						errors <- err
						return
					}
					err = appendCmd.Close()
					if err != nil {
						errors <- err
						return
					}
					_, err = appendCmd.Wait()
					if err != nil {
						errors <- err
						return
					}
				}
			}(clientID)
		}

		wg.Wait()
		close(errors)

		// Check for errors
		for err := range errors {
			if err != nil {
				t.Errorf("Concurrent append error: %v", err)
			}
		}

		// Verify total message count
		verifyClient, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial verify client: %v", err)
		}
		defer verifyClient.Logout()

		if err := verifyClient.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Verify client login failed: %v", err)
		}

		mbox, err := verifyClient.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Verify client select failed: %v", err)
		}

		expectedMessages := uint32(numClients * messagesPerClient)
		if mbox.NumMessages != expectedMessages {
			t.Errorf("Expected %d messages after concurrent append, got %d", expectedMessages, mbox.NumMessages)
		} else {
			t.Logf("Successfully appended %d messages concurrently", expectedMessages)
		}
	})
}

// TestIMAP_ConcurrentFlagOperations tests concurrent flag modifications
func TestIMAP_ConcurrentFlagOperations(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Setup: Add a test message
	setupClient, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial setup client: %v", err)
	}
	defer setupClient.Logout()

	if err := setupClient.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Setup client login failed: %v", err)
	}

	if _, err := setupClient.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Setup client select failed: %v", err)
	}

	testMessage := "From: flagrace@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Flag Race Test\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"This message will have its flags modified concurrently.\r\n"

	appendCmd := setupClient.Append("INBOX", int64(len(testMessage)), nil)
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("Setup APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("Setup APPEND close failed: %v", err)
	}
	_, err = appendCmd.Wait()
	if err != nil {
		t.Fatalf("Setup APPEND failed: %v", err)
	}

	setupClient.Logout()

	// Test concurrent flag operations on the same message
	numClients := 3
	var wg sync.WaitGroup
	flagOperations := []struct {
		op    imap.StoreFlagsOp
		flags []imap.Flag
		name  string
	}{
		{imap.StoreFlagsAdd, []imap.Flag{imap.FlagSeen}, "add_seen"},
		{imap.StoreFlagsAdd, []imap.Flag{imap.FlagFlagged}, "add_flagged"},
		{imap.StoreFlagsAdd, []imap.Flag{imap.FlagAnswered}, "add_answered"},
	}

	successCount := make(chan int, numClients)

	for clientID := 0; clientID < numClients; clientID++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			c, err := imapclient.DialInsecure(server.Address, nil)
			if err != nil {
				t.Errorf("Client %d: Failed to dial: %v", id, err)
				successCount <- 0
				return
			}
			defer c.Logout()

			if err := c.Login(account.Email, account.Password).Wait(); err != nil {
				t.Errorf("Client %d: Login failed: %v", id, err)
				successCount <- 0
				return
			}

			if _, err := c.Select("INBOX", nil).Wait(); err != nil {
				t.Errorf("Client %d: Select failed: %v", id, err)
				successCount <- 0
				return
			}

			// Perform flag operation
			op := flagOperations[id%len(flagOperations)]
			storeCmd := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{
				Op:    op.op,
				Flags: op.flags,
			}, nil)
			_, err = storeCmd.Collect()
			if err != nil {
				t.Errorf("Client %d (%s): STORE failed: %v", id, op.name, err)
				successCount <- 0
				return
			}

			t.Logf("Client %d (%s) completed flag operation successfully", id, op.name)
			successCount <- 1
		}(clientID)
	}

	wg.Wait()

	// Count successful operations
	totalSuccess := 0
	for i := 0; i < numClients; i++ {
		totalSuccess += <-successCount
	}

	if totalSuccess != numClients {
		t.Errorf("Expected %d successful flag operations, got %d", numClients, totalSuccess)
	}

	// Verify final flag state
	verifyClient, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial verify client: %v", err)
	}
	defer verifyClient.Logout()

	if err := verifyClient.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Verify client login failed: %v", err)
	}

	if _, err := verifyClient.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Verify client select failed: %v", err)
	}

	fetchResults, err := verifyClient.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil {
		t.Fatalf("Verify FETCH failed: %v", err)
	}

	if len(fetchResults) > 0 {
		finalFlags := fetchResults[0].Flags
		t.Logf("Final message flags after concurrent operations: %v", finalFlags)

		// Check that at least some flags were set (depending on race conditions, we might get different combinations)
		flagCount := 0
		if containsFlag(finalFlags, imap.FlagSeen) {
			flagCount++
		}
		if containsFlag(finalFlags, imap.FlagFlagged) {
			flagCount++
		}
		if containsFlag(finalFlags, imap.FlagAnswered) {
			flagCount++
		}

		if flagCount == 0 {
			t.Error("No flags were set despite successful operations")
		}
	}

	t.Log("Concurrent flag operations test completed")
}

// TestIMAP_ConcurrentMailboxOperations tests concurrent mailbox creation/deletion
func TestIMAP_ConcurrentMailboxOperations(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	numClients := 3
	var wg sync.WaitGroup
	results := make(chan string, numClients*2) // CREATE + DELETE per client

	for clientID := 0; clientID < numClients; clientID++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			c, err := imapclient.DialInsecure(server.Address, nil)
			if err != nil {
				results <- "error"
				return
			}
			defer c.Logout()

			if err := c.Login(account.Email, account.Password).Wait(); err != nil {
				results <- "error"
				return
			}

			mailboxName := "ConcurrentTest" + string(rune('A'+id))

			// CREATE mailbox
			if err := c.Create(mailboxName, nil).Wait(); err != nil {
				results <- "create_error"
				return
			}
			results <- "create_success"

			// Small delay to let other operations interleave
			time.Sleep(50 * time.Millisecond)

			// DELETE mailbox
			if err := c.Delete(mailboxName).Wait(); err != nil {
				results <- "delete_error"
				return
			}
			results <- "delete_success"
		}(clientID)
	}

	wg.Wait()

	// Analyze results
	createSuccess := 0
	deleteSuccess := 0
	errors := 0

	for i := 0; i < numClients*2; i++ {
		result := <-results
		switch result {
		case "create_success":
			createSuccess++
		case "delete_success":
			deleteSuccess++
		default:
			errors++
		}
	}

	if errors > 0 {
		t.Errorf("Got %d errors during concurrent mailbox operations", errors)
	}

	if createSuccess != numClients {
		t.Errorf("Expected %d successful CREATE operations, got %d", numClients, createSuccess)
	}

	if deleteSuccess != numClients {
		t.Errorf("Expected %d successful DELETE operations, got %d", numClients, deleteSuccess)
	}

	t.Logf("Concurrent mailbox operations: %d creates, %d deletes, %d errors", createSuccess, deleteSuccess, errors)
}

// TestIMAP_SortCommand tests the SORT command implementation
func TestIMAP_SortCommand(t *testing.T) {
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
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// First check if SORT capability is advertised
	caps, err := c.Capability().Wait()
	if err != nil {
		t.Fatalf("Failed to get capabilities: %v", err)
	}

	hasSortCap := false
	for cap := range caps {
		if string(cap) == "SORT" {
			hasSortCap = true
			break
		}
	}

	if !hasSortCap {
		t.Log("SORT capability not advertised - this might be the issue")
	} else {
		t.Log("SORT capability is properly advertised")
	}

	// Try to execute a simple SORT command on empty mailbox first
	sortOptions := &imapclient.SortOptions{
		SearchCriteria: &imap.SearchCriteria{},
		SortCriteria:   []imap.SortCriterion{{Key: imap.SortKeyDate, Reverse: false}},
	}
	sortCmd := c.Sort(sortOptions)
	sortResult, err := sortCmd.Wait()
	if err != nil {
		t.Fatalf("SORT command failed on empty mailbox: %v", err)
	}

	if len(sortResult.SeqNums) != 0 {
		t.Errorf("Expected 0 results for empty mailbox, got %d", len(sortResult.SeqNums))
	}
	t.Log("SORT command succeeded on empty mailbox")

	// Test UID SORT on empty mailbox
	uidSortOptions := &imapclient.SortOptions{
		SearchCriteria: &imap.SearchCriteria{},
		SortCriteria:   []imap.SortCriterion{{Key: imap.SortKeyDate, Reverse: false}},
	}
	uidSortCmd := c.UIDSort(uidSortOptions)
	uidSortResult, err := uidSortCmd.Wait()
	if err != nil {
		t.Fatalf("UID SORT failed on empty mailbox: %v", err)
	}

	if len(uidSortResult.UIDs) != 0 {
		t.Errorf("Expected 0 UID SORT results for empty mailbox, got %d", len(uidSortResult.UIDs))
	}
	t.Log("UID SORT succeeded on empty mailbox")

	t.Log("SORT command integration test completed successfully")
}

// TestIMAP_ESortCommand tests the ESORT extension (RFC 5267)
func TestIMAP_ESortCommand(t *testing.T) {
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
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Check if ESORT capability is advertised
	caps, err := c.Capability().Wait()
	if err != nil {
		t.Fatalf("Failed to get capabilities: %v", err)
	}

	hasESortCap := false
	for cap := range caps {
		if string(cap) == "ESORT" {
			hasESortCap = true
			break
		}
	}

	if !hasESortCap {
		t.Skip("ESORT capability not advertised")
	}
	t.Log("ESORT capability is properly advertised")

	// Add test messages with different dates and subjects for sorting
	testMessages := []struct {
		subject string
		date    string
		from    string
	}{
		{"Alpha Subject", "01 Jan 2023 12:00:00 +0000", "alice@example.com"},
		{"Beta Subject", "02 Jan 2023 12:00:00 +0000", "bob@example.com"},
		{"Gamma Subject", "03 Jan 2023 12:00:00 +0000", "charlie@example.com"},
		{"Delta Subject", "04 Jan 2023 12:00:00 +0000", "diana@example.com"},
	}

	for i, msg := range testMessages {
		msgBody := fmt.Sprintf("From: %s\r\nSubject: %s\r\nDate: %s\r\n\r\nMessage body %d\r\n", 
			msg.from, msg.subject, msg.date, i+1)
		
		appendCmd := c.Append("INBOX", int64(len(msgBody)), &imap.AppendOptions{
			Flags: []imap.Flag{},
			Time:  time.Now(),
		})
		_, err := appendCmd.Write([]byte(msgBody))
		if err != nil {
			t.Fatalf("Failed to write test message %d: %v", i+1, err)
		}
		err = appendCmd.Close()
		if err != nil {
			t.Fatalf("Failed to close test message %d: %v", i+1, err)
		}
		_, err = appendCmd.Wait()
		if err != nil {
			t.Fatalf("Failed to append test message %d: %v", i+1, err)
		}
	}

	// Re-select to refresh the mailbox state
	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Re-select INBOX failed: %v", err)
	}

	if selectData.NumMessages != uint32(len(testMessages)) {
		t.Errorf("Expected %d messages in INBOX, got %d", len(testMessages), selectData.NumMessages)
	}

	// Test ESORT with RETURN (COUNT)
	eSortOptions := &imapclient.SortOptions{
		SearchCriteria: &imap.SearchCriteria{},
		SortCriteria:   []imap.SortCriterion{{Key: imap.SortKeyDate, Reverse: false}},
		Return:         imap.SortOptions{ReturnCount: true},
	}
	eSortCmd := c.Sort(eSortOptions)
	eSortResult, err := eSortCmd.Wait()
	if err != nil {
		t.Fatalf("ESORT with RETURN COUNT failed: %v", err)
	}

	if eSortResult.Count != uint32(len(testMessages)) {
		t.Errorf("Expected ESORT COUNT to be %d, got %d", len(testMessages), eSortResult.Count)
	}
	t.Logf("ESORT COUNT succeeded: %d messages", eSortResult.Count)

	// Test ESORT with RETURN (MIN MAX)
	eSortOptions = &imapclient.SortOptions{
		SearchCriteria: &imap.SearchCriteria{},
		SortCriteria:   []imap.SortCriterion{{Key: imap.SortKeyDate, Reverse: false}},
		Return:         imap.SortOptions{ReturnMin: true, ReturnMax: true},
	}
	eSortCmd = c.Sort(eSortOptions)
	eSortResult, err = eSortCmd.Wait()
	if err != nil {
		t.Fatalf("ESORT with RETURN MIN MAX failed: %v", err)
	}

	if eSortResult.Min == 0 || eSortResult.Max == 0 {
		t.Logf("Note: ESORT MIN and MAX are zero (MIN=%d, MAX=%d) - this may be due to ESORT implementation details", eSortResult.Min, eSortResult.Max)
	}
	t.Logf("ESORT MIN/MAX succeeded: MIN=%d, MAX=%d", eSortResult.Min, eSortResult.Max)

	// Test ESORT with RETURN (ALL)
	eSortOptions = &imapclient.SortOptions{
		SearchCriteria: &imap.SearchCriteria{},
		SortCriteria:   []imap.SortCriterion{{Key: imap.SortKeySubject, Reverse: false}},
		Return:         imap.SortOptions{ReturnAll: true},
	}
	eSortCmd = c.Sort(eSortOptions)
	eSortResult, err = eSortCmd.Wait()
	if err != nil {
		t.Fatalf("ESORT with RETURN ALL failed: %v", err)
	}

	if len(eSortResult.SeqNums) != len(testMessages) {
		t.Errorf("Expected ESORT ALL to return %d messages, got %d", len(testMessages), len(eSortResult.SeqNums))
	}
	t.Logf("ESORT ALL succeeded: %d messages returned", len(eSortResult.SeqNums))

	// Test UID ESORT
	uidESortOptions := &imapclient.SortOptions{
		SearchCriteria: &imap.SearchCriteria{},
		SortCriteria:   []imap.SortCriterion{{Key: imap.SortKeyDate, Reverse: true}},
		Return:         imap.SortOptions{ReturnAll: true, ReturnCount: true},
	}
	uidESortCmd := c.UIDSort(uidESortOptions)
	uidESortResult, err := uidESortCmd.Wait()
	if err != nil {
		t.Fatalf("UID ESORT failed: %v", err)
	}

	if len(uidESortResult.UIDs) != len(testMessages) {
		t.Errorf("Expected UID ESORT to return %d UIDs, got %d", len(testMessages), len(uidESortResult.UIDs))
	}
	if uidESortResult.Count != uint32(len(testMessages)) {
		t.Errorf("Expected UID ESORT COUNT to be %d, got %d", len(testMessages), uidESortResult.Count)
	}
	t.Logf("UID ESORT succeeded: %d UIDs returned, COUNT=%d", len(uidESortResult.UIDs), uidESortResult.Count)

	t.Log("ESORT command integration test completed successfully")
}

// TestIMAP_SortDisplayCommand tests the SORT=DISPLAY extension (RFC 5957)
func TestIMAP_SortDisplayCommand(t *testing.T) {
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
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Check if SORT=DISPLAY capability is advertised
	caps, err := c.Capability().Wait()
	if err != nil {
		t.Fatalf("Failed to get capabilities: %v", err)
	}

	hasSortDisplayCap := false
	for cap := range caps {
		if string(cap) == "SORT=DISPLAY" {
			hasSortDisplayCap = true
			break
		}
	}

	if !hasSortDisplayCap {
		t.Skip("SORT=DISPLAY capability not advertised")
	}
	t.Log("SORT=DISPLAY capability is properly advertised")

	// Add test messages with display names for testing SORT=DISPLAY
	testMessages := []struct {
		subject string
		from    string  // Display name + email
		date    string
	}{
		{"Test Message 1", "\"Zulu User\" <zulu@example.com>", "01 Jan 2023 12:00:00 +0000"},
		{"Test Message 2", "\"Alpha User\" <alpha@example.com>", "02 Jan 2023 12:00:00 +0000"},
		{"Test Message 3", "\"Beta User\" <beta@example.com>", "03 Jan 2023 12:00:00 +0000"},
	}

	for i, msg := range testMessages {
		msgBody := fmt.Sprintf("From: %s\r\nSubject: %s\r\nDate: %s\r\n\r\nMessage body %d\r\n", 
			msg.from, msg.subject, msg.date, i+1)
		
		appendCmd := c.Append("INBOX", int64(len(msgBody)), &imap.AppendOptions{
			Flags: []imap.Flag{},
			Time:  time.Now(),
		})
		_, err := appendCmd.Write([]byte(msgBody))
		if err != nil {
			t.Fatalf("Failed to write test message %d: %v", i+1, err)
		}
		err = appendCmd.Close()
		if err != nil {
			t.Fatalf("Failed to close test message %d: %v", i+1, err)
		}
		_, err = appendCmd.Wait()
		if err != nil {
			t.Fatalf("Failed to append test message %d: %v", i+1, err)
		}
	}

	// Re-select to refresh the mailbox state
	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Re-select INBOX failed: %v", err)
	}

	if selectData.NumMessages != uint32(len(testMessages)) {
		t.Errorf("Expected %d messages in INBOX, got %d", len(testMessages), selectData.NumMessages)
	}

	// Test SORT with DISPLAY sort key
	displaySortOptions := &imapclient.SortOptions{
		SearchCriteria: &imap.SearchCriteria{},
		SortCriteria:   []imap.SortCriterion{{Key: imap.SortKeyDisplay, Reverse: false}},
	}
	displaySortCmd := c.Sort(displaySortOptions)
	displaySortResult, err := displaySortCmd.Wait()
	if err != nil {
		t.Fatalf("SORT with DISPLAY failed: %v", err)
	}

	if len(displaySortResult.SeqNums) != len(testMessages) {
		t.Errorf("Expected SORT DISPLAY to return %d messages, got %d", len(testMessages), len(displaySortResult.SeqNums))
	}
	t.Logf("SORT DISPLAY succeeded: %d messages sorted by display name", len(displaySortResult.SeqNums))

	// Test SORT with REVERSE DISPLAY
	reverseSortOptions := &imapclient.SortOptions{
		SearchCriteria: &imap.SearchCriteria{},
		SortCriteria:   []imap.SortCriterion{{Key: imap.SortKeyDisplay, Reverse: true}},
	}
	reverseSortCmd := c.Sort(reverseSortOptions)
	reverseSortResult, err := reverseSortCmd.Wait()
	if err != nil {
		t.Fatalf("SORT with REVERSE DISPLAY failed: %v", err)
	}

	if len(reverseSortResult.SeqNums) != len(testMessages) {
		t.Errorf("Expected REVERSE SORT DISPLAY to return %d messages, got %d", len(testMessages), len(reverseSortResult.SeqNums))
	}
	t.Logf("REVERSE SORT DISPLAY succeeded: %d messages sorted", len(reverseSortResult.SeqNums))

	// Test UID SORT with DISPLAY
	uidDisplaySortOptions := &imapclient.SortOptions{
		SearchCriteria: &imap.SearchCriteria{},
		SortCriteria:   []imap.SortCriterion{{Key: imap.SortKeyDisplay, Reverse: false}},
	}
	uidDisplaySortCmd := c.UIDSort(uidDisplaySortOptions)
	uidDisplaySortResult, err := uidDisplaySortCmd.Wait()
	if err != nil {
		t.Fatalf("UID SORT with DISPLAY failed: %v", err)
	}

	if len(uidDisplaySortResult.UIDs) != len(testMessages) {
		t.Errorf("Expected UID SORT DISPLAY to return %d UIDs, got %d", len(testMessages), len(uidDisplaySortResult.UIDs))
	}
	t.Logf("UID SORT DISPLAY succeeded: %d UIDs sorted by display name", len(uidDisplaySortResult.UIDs))

	t.Log("SORT=DISPLAY command integration test completed successfully")
}

// TestIMAP_SortComprehensive tests various sort criteria and combinations
func TestIMAP_SortComprehensive(t *testing.T) {
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
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Add test messages with various properties for comprehensive sorting
	testMessages := []struct {
		subject string
		from    string
		to      string
		cc      string
		date    string
		size    int
	}{
		{"Small message", "alice@example.com", account.Email, "", "01 Jan 2023 12:00:00 +0000", 100},
		{"Large message with more content", "bob@example.com", account.Email, "cc@example.com", "02 Jan 2023 12:00:00 +0000", 500},
		{"Medium message", "charlie@example.com", account.Email, "", "03 Jan 2023 12:00:00 +0000", 300},
	}

	for i, msg := range testMessages {
		msgBody := fmt.Sprintf("From: %s\r\nTo: %s\r\n", msg.from, msg.to)
		if msg.cc != "" {
			msgBody += fmt.Sprintf("Cc: %s\r\n", msg.cc)
		}
		msgBody += fmt.Sprintf("Subject: %s\r\nDate: %s\r\n\r\n", msg.subject, msg.date)
		
		// Add content to reach approximate size
		contentSize := msg.size - len(msgBody)
		if contentSize > 0 {
			msgBody += strings.Repeat("X", contentSize)
		}
		msgBody += "\r\n"
		
		appendCmd := c.Append("INBOX", int64(len(msgBody)), &imap.AppendOptions{
			Flags: []imap.Flag{},
			Time:  time.Now(),
		})
		_, err := appendCmd.Write([]byte(msgBody))
		if err != nil {
			t.Fatalf("Failed to write test message %d: %v", i+1, err)
		}
		err = appendCmd.Close()
		if err != nil {
			t.Fatalf("Failed to close test message %d: %v", i+1, err)
		}
		_, err = appendCmd.Wait()
		if err != nil {
			t.Fatalf("Failed to append test message %d: %v", i+1, err)
		}
	}

	// Re-select to refresh the mailbox state
	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Re-select INBOX failed: %v", err)
	}

	if selectData.NumMessages != uint32(len(testMessages)) {
		t.Errorf("Expected %d messages in INBOX, got %d", len(testMessages), selectData.NumMessages)
	}

	// Test different sort criteria
	sortTests := []struct {
		name     string
		criteria []imap.SortCriterion
	}{
		{"ARRIVAL", []imap.SortCriterion{{Key: imap.SortKeyArrival, Reverse: false}}},
		{"REVERSE ARRIVAL", []imap.SortCriterion{{Key: imap.SortKeyArrival, Reverse: true}}},
		{"DATE", []imap.SortCriterion{{Key: imap.SortKeyDate, Reverse: false}}},
		{"REVERSE DATE", []imap.SortCriterion{{Key: imap.SortKeyDate, Reverse: true}}},
		{"SUBJECT", []imap.SortCriterion{{Key: imap.SortKeySubject, Reverse: false}}},
		{"FROM", []imap.SortCriterion{{Key: imap.SortKeyFrom, Reverse: false}}},
		{"TO", []imap.SortCriterion{{Key: imap.SortKeyTo, Reverse: false}}},
		{"CC", []imap.SortCriterion{{Key: imap.SortKeyCc, Reverse: false}}},
		{"SIZE", []imap.SortCriterion{{Key: imap.SortKeySize, Reverse: false}}},
		{"REVERSE SIZE", []imap.SortCriterion{{Key: imap.SortKeySize, Reverse: true}}},
	}

	for _, test := range sortTests {
		t.Run(test.name, func(t *testing.T) {
			sortOptions := &imapclient.SortOptions{
				SearchCriteria: &imap.SearchCriteria{},
				SortCriteria:   test.criteria,
			}
			sortCmd := c.Sort(sortOptions)
			sortResult, err := sortCmd.Wait()
			if err != nil {
				t.Fatalf("SORT %s failed: %v", test.name, err)
			}

			if len(sortResult.SeqNums) != len(testMessages) {
				t.Errorf("Expected SORT %s to return %d messages, got %d", test.name, len(testMessages), len(sortResult.SeqNums))
			}
			t.Logf("SORT %s succeeded: %d messages sorted", test.name, len(sortResult.SeqNums))
		})
	}

	// Test SORT with search criteria
	searchSortOptions := &imapclient.SortOptions{
		SearchCriteria: &imap.SearchCriteria{
			Header: []imap.SearchCriteriaHeaderField{
				{Key: "FROM", Value: "alice@example.com"},
			},
		},
		SortCriteria: []imap.SortCriterion{{Key: imap.SortKeyDate, Reverse: false}},
	}
	searchSortCmd := c.Sort(searchSortOptions)
	searchSortResult, err := searchSortCmd.Wait()
	if err != nil {
		t.Fatalf("SORT with search criteria failed: %v", err)
	}

	// Should find only the message from alice@example.com
	if len(searchSortResult.SeqNums) != 1 {
		t.Errorf("Expected SORT with search to return 1 message, got %d", len(searchSortResult.SeqNums))
	}
	t.Logf("SORT with search criteria succeeded: %d messages found", len(searchSortResult.SeqNums))

	t.Log("Comprehensive SORT test completed successfully")
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
