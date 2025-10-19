//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// Helper function to create a second user
func createSecondUser(t *testing.T, server *common.TestServer, domain string, suffix string) (string, string) {
	t.Helper()
	email := fmt.Sprintf("user2-%s-%d@%s", suffix, common.GetTimestamp(), domain)
	password := "password2"

	req := db.CreateAccountRequest{
		Email:     email,
		Password:  password,
		HashType:  "bcrypt",
		IsPrimary: true,
	}
	if err := server.ResilientDB.CreateAccountWithRetry(context.Background(), req); err != nil {
		t.Fatalf("Failed to create second account: %v", err)
	}
	return email, password
}

// TestACL_APPEND_Permission tests that APPEND requires 'i' (insert) right
func TestACL_APPEND_Permission(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	email1 := account1.Email
	password1 := account1.Password
	email2, password2 := createSecondUser(t, server, "example.com", "append")

	// Connect as owner (user1)
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(email1, password1).Wait(); err != nil {
		t.Fatalf("Failed to login as owner: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/TestAppend-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}

	// Grant accessor only 'l' (lookup) right - NOT 'i' (insert)
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("l")).Wait(); err != nil {
		t.Fatalf("Failed to set ACL: %v", err)
	}

	// Connect as accessor (user2)
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("Failed to login as accessor: %v", err)
	}

	// Accessor tries to APPEND - should fail without 'i' right
	testMsg1 := []byte("Subject: Test\r\n\r\nTest message")
	appendCmd := c2.Append(sharedMailbox, int64(len(testMsg1)), &imap.AppendOptions{
		Time: time.Now(),
	})
	_, writeErr := appendCmd.Write(testMsg1)
	closeErr := appendCmd.Close()
	// The APPEND command execution happens asynchronously, so we need to check the result
	// by verifying the mailbox is still empty
	if writeErr != nil {
		t.Logf("APPEND failed as expected (during write): %v", writeErr)
	} else if closeErr != nil {
		t.Logf("APPEND failed as expected (during close): %v", closeErr)
	} else {
		// Write and Close succeeded, but the APPEND should have been rejected by server
		// Verify by checking the mailbox has no messages (owner can check)
		statusData, err := c1.Status(sharedMailbox, &imap.StatusOptions{NumMessages: true}).Wait()
		if err != nil {
			t.Fatalf("Failed to get STATUS: %v", err)
		}
		if statusData.NumMessages != nil && *statusData.NumMessages > 0 {
			t.Fatalf("APPEND should have been rejected without 'i' right, but mailbox has %d messages", *statusData.NumMessages)
		}
		t.Log("APPEND was rejected by server (verified mailbox is empty)")
	}

	// Owner grants 'i' right to accessor
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationAdd, imap.RightSet("i")).Wait(); err != nil {
		t.Fatalf("Failed to add 'i' right: %v", err)
	}

	// Accessor tries APPEND again - should succeed now
	testMsg2 := []byte("Subject: Test Success\r\n\r\nTest message with permission")
	appendCmd = c2.Append(sharedMailbox, int64(len(testMsg2)), &imap.AppendOptions{
		Time: time.Now(),
	})
	_, err = appendCmd.Write(testMsg2)
	if err != nil {
		t.Fatalf("Failed to write APPEND data: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND should succeed with 'i' right, got error: %v", err)
	}
	t.Log("APPEND succeeded with 'i' right")
}

// TestACL_STORE_Permission tests that STORE requires 'w', 's', or 't' based on flags
func TestACL_STORE_Permission(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	email1 := account1.Email
	password1 := account1.Password
	email2, password2 := createSecondUser(t, server, "example.com", "store")

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(email1, password1).Wait(); err != nil {
		t.Fatalf("Failed to login as owner: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/TestStore-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}

	// Add messages
	for i := 0; i < 5; i++ {
		msgBody := []byte(fmt.Sprintf("Subject: Message %d\r\n\r\nTest message %d", i, i))
		appendCmd := c1.Append(sharedMailbox, int64(len(msgBody)), nil)
		_, err = appendCmd.Write(msgBody)
		if err != nil {
			t.Fatalf("Failed to write APPEND data: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("Failed to APPEND: %v", err)
		}
	}

	// Grant accessor only 'lr' - no flag modification rights
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lr")).Wait(); err != nil {
		t.Fatalf("Failed to set ACL: %v", err)
	}

	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("Failed to login as accessor: %v", err)
	}

	_, err = c2.Select(sharedMailbox, nil).Wait()
	if err != nil {
		t.Fatalf("Failed to SELECT: %v", err)
	}

	// Try to set \Seen flag - should fail without 's' right
	storeCmd := c2.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil)
	_, err = storeCmd.Collect()
	if err == nil {
		t.Fatal("STORE \\Seen should fail without 's' right")
	}
	t.Logf("STORE \\Seen failed as expected: %v", err)

	// Grant 's' right - \Seen should now work
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationAdd, imap.RightSet("s")).Wait(); err != nil {
		t.Fatalf("Failed to add 's' right: %v", err)
	}

	storeCmd = c2.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("STORE \\Seen should succeed with 's' right, got error: %v", err)
	}
	t.Log("STORE \\Seen succeeded with 's' right")

	// Try to set \Deleted flag - should fail without 't' right
	storeCmd = c2.Store(imap.SeqSetNum(2), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil)
	_, err = storeCmd.Collect()
	if err == nil {
		t.Fatal("STORE \\Deleted should fail without 't' right")
	}
	t.Logf("STORE \\Deleted failed as expected: %v", err)

	// Grant 't' right
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationAdd, imap.RightSet("t")).Wait(); err != nil {
		t.Fatalf("Failed to add 't' right: %v", err)
	}

	storeCmd = c2.Store(imap.SeqSetNum(2), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("STORE \\Deleted should succeed with 't' right, got error: %v", err)
	}
	t.Log("STORE \\Deleted succeeded with 't' right")
}

// TestACL_EXPUNGE_Permission tests that EXPUNGE requires 'e' (expunge) right
func TestACL_EXPUNGE_Permission(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	email1 := account1.Email
	password1 := account1.Password
	email2, password2 := createSecondUser(t, server, "example.com", "expunge")

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(email1, password1).Wait(); err != nil {
		t.Fatalf("Failed to login as owner: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/TestExpunge-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}

	// Add messages
	for i := 0; i < 3; i++ {
		msgBody := []byte(fmt.Sprintf("Subject: Message %d\r\n\r\nTest message %d", i, i))
		appendCmd := c1.Append(sharedMailbox, int64(len(msgBody)), nil)
		_, err = appendCmd.Write(msgBody)
		if err != nil {
			t.Fatalf("Failed to write APPEND data: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("Failed to APPEND: %v", err)
		}
	}

	// Grant accessor 'lrst' (has 't' for delete-msg but not 'e' for expunge)
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lrst")).Wait(); err != nil {
		t.Fatalf("Failed to set ACL: %v", err)
	}

	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("Failed to login as accessor: %v", err)
	}

	_, err = c2.Select(sharedMailbox, nil).Wait()
	if err != nil {
		t.Fatalf("Failed to SELECT: %v", err)
	}

	// Mark message as deleted
	storeCmd := c2.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("Failed to mark message as deleted: %v", err)
	}

	// Try to EXPUNGE - should fail without 'e' right
	expungeCmd := c2.Expunge()
	_, err = expungeCmd.Collect()
	if err == nil {
		t.Fatal("EXPUNGE should fail without 'e' right")
	}
	t.Logf("EXPUNGE failed as expected: %v", err)

	// Owner grants 'e' right
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationAdd, imap.RightSet("e")).Wait(); err != nil {
		t.Fatalf("Failed to add 'e' right: %v", err)
	}

	// Mark another message as deleted for next expunge
	storeCmd = c2.Store(imap.SeqSetNum(2), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("Failed to mark message as deleted: %v", err)
	}

	// Try EXPUNGE again - should succeed now
	expungeCmd = c2.Expunge()
	_, err = expungeCmd.Collect()
	if err != nil {
		t.Fatalf("EXPUNGE should succeed with 'e' right, got error: %v", err)
	}
	t.Log("EXPUNGE succeeded with 'e' right")
}

// TestACL_DELETE_Permission tests that DELETE requires 'x' (delete) right
func TestACL_DELETE_Permission(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	email1 := account1.Email
	password1 := account1.Password
	email2, password2 := createSecondUser(t, server, "example.com", "delete")

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(email1, password1).Wait(); err != nil {
		t.Fatalf("Failed to login as owner: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/TestDelete-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}

	// Grant accessor 'lrswi' (all except 'x', 'k', 't', 'e', 'a')
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lrswi")).Wait(); err != nil {
		t.Fatalf("Failed to set ACL: %v", err)
	}

	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("Failed to login as accessor: %v", err)
	}

	// Try to DELETE - should fail without 'x' right
	err = c2.Delete(sharedMailbox).Wait()
	if err == nil {
		t.Fatal("DELETE should fail without 'x' right")
	}
	t.Logf("DELETE failed as expected: %v", err)

	// Owner grants 'x' right
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationAdd, imap.RightSet("x")).Wait(); err != nil {
		t.Fatalf("Failed to add 'x' right: %v", err)
	}

	// Verify the mailbox still exists before trying to delete
	listData := c1.List("", sharedMailbox, nil)
	mailboxes, err := listData.Collect()
	if err != nil {
		t.Fatalf("Failed to list mailbox before second DELETE: %v", err)
	}
	if len(mailboxes) == 0 {
		t.Fatal("Mailbox disappeared after first DELETE attempt (should have been rejected)")
	}
	t.Logf("Verified mailbox still exists: %s", mailboxes[0].Mailbox)

	// Try DELETE again - should succeed now
	if err := c2.Delete(sharedMailbox).Wait(); err != nil {
		t.Fatalf("DELETE should succeed with 'x' right, got error: %v", err)
	}
	t.Log("DELETE succeeded with 'x' right")
}

// TestACL_STATUS_Permission tests that STATUS requires 'r' (read) right
func TestACL_STATUS_Permission(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	email1 := account1.Email
	password1 := account1.Password
	email2, password2 := createSecondUser(t, server, "example.com", "status")

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(email1, password1).Wait(); err != nil {
		t.Fatalf("Failed to login as owner: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/TestStatus-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}

	// Add messages
	for i := 0; i < 3; i++ {
		msgBody := []byte(fmt.Sprintf("Subject: Message %d\r\n\r\nTest message %d", i, i))
		appendCmd := c1.Append(sharedMailbox, int64(len(msgBody)), nil)
		_, err = appendCmd.Write(msgBody)
		if err != nil {
			t.Fatalf("Failed to write APPEND data: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("Failed to APPEND: %v", err)
		}
	}

	// Grant accessor only 'l' (lookup) - NOT 'r' (read)
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("l")).Wait(); err != nil {
		t.Fatalf("Failed to set ACL: %v", err)
	}

	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("Failed to login as accessor: %v", err)
	}

	// Try STATUS - should fail without 'r' right
	_, err = c2.Status(sharedMailbox, &imap.StatusOptions{
		NumMessages: true,
		UIDNext:     true,
	}).Wait()
	if err == nil {
		t.Fatal("STATUS should fail without 'r' right")
	}
	t.Logf("STATUS failed as expected: %v", err)

	// Owner grants 'r' right
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationAdd, imap.RightSet("r")).Wait(); err != nil {
		t.Fatalf("Failed to add 'r' right: %v", err)
	}

	// Try STATUS again - should succeed now
	statusData, err := c2.Status(sharedMailbox, &imap.StatusOptions{
		NumMessages: true,
		UIDNext:     true,
	}).Wait()
	if err != nil {
		t.Fatalf("STATUS should succeed with 'r' right, got error: %v", err)
	}
	if statusData.NumMessages == nil || *statusData.NumMessages != 3 {
		t.Fatalf("Expected 3 messages, got %v", statusData.NumMessages)
	}
	t.Log("STATUS succeeded with 'r' right")
}
