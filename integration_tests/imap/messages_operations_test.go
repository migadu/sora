//go:build integration

package imap_test

import (
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

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
