//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
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
	if _, err := server.ResilientDB.CreateAccountWithRetry(context.Background(), req); err != nil {
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

// TestACL_SetACL_RejectsUnrecognizedRights verifies RFC 4314 §3.1: an unrecognized
// right MUST cause a BAD response and MUST NOT be silently ignored. Critically, a
// rejected SETACL must not destroy an existing grant (the old behavior let "ZZ"
// collapse to an empty rights set and silently revoke the entry).
func TestACL_SetACL_RejectsUnrecognizedRights(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	email2, _ := createSecondUser(t, server, "example.com", "badrights")

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()
	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/TestBadRights-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	// Establish a valid baseline grant.
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lr")).Wait(); err != nil {
		t.Fatalf("Baseline SETACL failed: %v", err)
	}

	// Each of these contains an unrecognized right and MUST be rejected.
	// "ZZ" is the dangerous case: it must not collapse to empty and revoke the entry.
	for _, bad := range []imap.RightSet{imap.RightSet("lrZ"), imap.RightSet("q"), imap.RightSet("ZZ")} {
		err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, bad).Wait()
		if err == nil {
			t.Errorf("SETACL with unrecognized rights %q should fail (BAD)", bad.String())
		} else {
			t.Logf("✓ SETACL %q rejected: %v", bad.String(), err)
		}
	}

	// The rejected SETACLs must have left the baseline grant intact.
	getACLData, err := c1.GetACL(sharedMailbox).Wait()
	if err != nil {
		t.Fatalf("GETACL failed: %v", err)
	}
	rights, ok := getACLData.Rights[imap.RightsIdentifier(email2)]
	if !ok {
		t.Fatalf("baseline ACL entry was destroyed by a rejected SETACL (silent-revoke regression)")
	}
	if !strings.ContainsRune(rights.String(), 'l') || !strings.ContainsRune(rights.String(), 'r') {
		t.Errorf("baseline rights changed by rejected SETACL: got %q, want at least 'lr'", rights.String())
	}
	t.Logf("✓ baseline grant preserved after rejected SETACLs: %s", rights.String())
}

// TestACL_FetchDoesNotImplicitlySetSeenWithoutSeenRight verifies RFC 4314 §5.1.1:
// a non-PEEK BODY[] FETCH must NOT implicitly set \Seen when the user lacks the 's'
// right, and MUST set it once the 's' right is granted.
func TestACL_FetchDoesNotImplicitlySetSeenWithoutSeenRight(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	email2, password2 := createSecondUser(t, server, "example.com", "fetchseen")

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()
	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/TestFetchSeen-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	msgBody := []byte("Subject: Seen test\r\n\r\nbody")
	appendCmd := c1.Append(sharedMailbox, int64(len(msgBody)), nil)
	if _, err := appendCmd.Write(msgBody); err != nil {
		t.Fatalf("Failed to write APPEND data: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("Failed to APPEND: %v", err)
	}

	// Grant read but NOT 's'.
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lr")).Wait(); err != nil {
		t.Fatalf("SETACL lr failed: %v", err)
	}

	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server for user2: %v", err)
	}
	defer c2.Logout()
	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("Accessor login failed: %v", err)
	}
	if _, err := c2.Select(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Accessor SELECT failed: %v", err)
	}

	// Non-PEEK BODY[] fetch would implicitly set \Seen; without 's' it MUST NOT.
	bodyFetch := &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{}}}
	if _, err := c2.Fetch(imap.SeqSetNum(1), bodyFetch).Collect(); err != nil {
		t.Fatalf("Accessor FETCH BODY[] failed: %v", err)
	}

	if fetchSeenAsOwner(t, c1, sharedMailbox) {
		t.Errorf("message marked \\Seen by a user lacking the 's' right (RFC 4314 §5.1.1 violation)")
	} else {
		t.Logf("✓ \\Seen not set for FETCH by user without 's' right")
	}

	// Grant 's' and confirm the implicit \Seen now happens.
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationAdd, imap.RightSet("s")).Wait(); err != nil {
		t.Fatalf("SETACL +s failed: %v", err)
	}
	if _, err := c2.Fetch(imap.SeqSetNum(1), bodyFetch).Collect(); err != nil {
		t.Fatalf("Accessor FETCH BODY[] (2) failed: %v", err)
	}
	if !fetchSeenAsOwner(t, c1, sharedMailbox) {
		t.Errorf("message should be \\Seen after FETCH by a user WITH the 's' right")
	} else {
		t.Logf("✓ \\Seen set after FETCH by user with 's' right")
	}
}

// fetchSeenAsOwner re-selects the mailbox as the owner and reports whether message 1
// carries \Seen. It fetches FLAGS only (no body section) so it does not itself set \Seen.
func fetchSeenAsOwner(t *testing.T, c *imapclient.Client, mailbox string) bool {
	t.Helper()
	if _, err := c.Select(mailbox, nil).Wait(); err != nil {
		t.Fatalf("owner SELECT for flag check failed: %v", err)
	}
	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil {
		t.Fatalf("owner FETCH FLAGS failed: %v", err)
	}
	if len(msgs) == 0 {
		t.Fatalf("no message found for flag check")
	}
	return containsFlag(msgs[0].Flags, imap.FlagSeen)
}

// TestACL_CloseWithoutExpungeRight verifies RFC 4314 §4: if the user lacks the
// 'e' right, CLOSE must ignore the expunge, close the mailbox, and return tagged
// OK (not fail) — and must not actually expunge \Deleted messages.
func TestACL_CloseWithoutExpungeRight(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	email2, password2 := createSecondUser(t, server, "example.com", "closenoe")

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()
	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/TestCloseNoE-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	for i := 0; i < 2; i++ {
		msgBody := []byte(fmt.Sprintf("Subject: msg %d\r\n\r\nbody %d", i, i))
		appendCmd := c1.Append(sharedMailbox, int64(len(msgBody)), nil)
		if _, err := appendCmd.Write(msgBody); err != nil {
			t.Fatalf("Failed to write APPEND data: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("Failed to APPEND: %v", err)
		}
	}

	// Grant read + delete-message ('t'), but NOT expunge ('e').
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lrt")).Wait(); err != nil {
		t.Fatalf("SETACL lrt failed: %v", err)
	}

	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server for user2: %v", err)
	}
	defer c2.Logout()
	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}
	if _, err := c2.Select(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("User2 SELECT failed: %v", err)
	}

	// Mark message 1 \Deleted (user2 has 't').
	if _, err := c2.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Collect(); err != nil {
		t.Fatalf("STORE \\Deleted failed: %v", err)
	}

	// CLOSE must succeed even though user2 lacks 'e'.
	if err := c2.UnselectAndExpunge().Wait(); err != nil {
		t.Fatalf("CLOSE without 'e' right should return OK (RFC 4314 §4), got: %v", err)
	}
	t.Logf("✓ CLOSE returned OK despite missing 'e' right")

	// The expunge must have been IGNORED: both messages still present.
	statusData, err := c1.Status(sharedMailbox, &imap.StatusOptions{NumMessages: true}).Wait()
	if err != nil {
		t.Fatalf("STATUS failed: %v", err)
	}
	if statusData.NumMessages == nil || *statusData.NumMessages != 2 {
		t.Errorf("expected 2 messages to remain (expunge ignored), got %v", statusData.NumMessages)
	} else {
		t.Logf("✓ \\Deleted message was not expunged (both messages remain)")
	}
}

// TestACL_ListRightsIndividualGroups verifies RFC 4314 §3.7: because Sora grants
// every right independently, LISTRIGHTS must return each right as its own
// single-character (untied) group rather than one bundled all-or-none string, and
// must not list any right more than once.
func TestACL_ListRightsIndividualGroups(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	email2, _ := createSecondUser(t, server, "example.com", "listrights")

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()
	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	data, err := c1.ListRights("INBOX", imap.RightsIdentifier(email2)).Wait()
	if err != nil {
		t.Fatalf("LISTRIGHTS failed: %v", err)
	}

	seen := map[rune]int{}
	for _, grp := range data.OptionalRights {
		// Each grantable right must be its own group (no false "tied" bundle).
		if len(grp.String()) != 1 {
			t.Errorf("optional rights must be individual single-char groups, got tied group %q", grp.String())
		}
		for _, r := range grp.String() {
			seen[r]++
		}
	}

	// Every standard right plus the obsolete compat rights c/d must appear exactly once.
	for _, r := range "lrswipkxteacd" {
		if seen[r] == 0 {
			t.Errorf("LISTRIGHTS missing right %q", string(r))
		} else if seen[r] > 1 {
			t.Errorf("LISTRIGHTS lists right %q %d times (must be at most once)", string(r), seen[r])
		}
	}
	t.Logf("✓ LISTRIGHTS returns %d individual untied groups incl. standalone c/d", len(data.OptionalRights))
}

// TestACL_SetACL_RejectsEmptyIdentifier verifies RFC 4314 §3: an empty/invalid
// identifier MUST be refused with a BAD response.
func TestACL_SetACL_RejectsEmptyIdentifier(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()
	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/TestEmptyId-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	for _, id := range []string{"", "   "} {
		err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(id), imap.RightModificationReplace, imap.RightSet("lr")).Wait()
		if err == nil {
			t.Errorf("SETACL with empty/whitespace identifier %q should be rejected", id)
		} else {
			t.Logf("✓ SETACL identifier %q rejected: %v", id, err)
		}
	}
}

// TestACL_RenameRequiresCreateOnNewParent verifies RFC 4314 §4: moving a mailbox
// to a different parent requires the 'k' right on the new parent.
func TestACL_RenameRequiresCreateOnNewParent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	email2, password2 := createSecondUser(t, server, "example.com", "renamek")

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()
	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	ts := common.GetTimestamp()
	movable := fmt.Sprintf("Shared/Movable-%d", ts)
	destParent := fmt.Sprintf("Shared/DestParent-%d", ts)
	for _, mb := range []string{movable, destParent} {
		if err := c1.Create(mb, nil).Wait(); err != nil {
			t.Fatalf("CREATE %s failed: %v", mb, err)
		}
		defer func(m string) { c1.Delete(m).Wait() }(mb)
	}

	// user2 may delete (rename) the movable mailbox, but has NO rights on destParent.
	if err := c1.SetACL(movable, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lrx")).Wait(); err != nil {
		t.Fatalf("SETACL on movable failed: %v", err)
	}

	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial for user2: %v", err)
	}
	defer c2.Logout()
	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}

	target := fmt.Sprintf("%s/Movable-%d", destParent, ts)

	// Without 'k' on destParent, the move must be denied.
	if err := c2.Rename(movable, target, nil).Wait(); err == nil {
		t.Errorf("RENAME into a parent without 'k' right should be denied")
	} else {
		t.Logf("✓ RENAME denied without 'k' on new parent: %v", err)
	}

	// Grant 'k' on destParent; the move should now succeed.
	if err := c1.SetACL(destParent, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lrk")).Wait(); err != nil {
		t.Fatalf("SETACL k on destParent failed: %v", err)
	}
	if err := c2.Rename(movable, target, nil).Wait(); err != nil {
		t.Errorf("RENAME into a parent WITH 'k' right should succeed, got: %v", err)
	} else {
		t.Logf("✓ RENAME succeeded once 'k' granted on new parent")
		c1.Delete(target).Wait()
	}

	// Auto-create guard: renaming into a NON-existent nested parent must also
	// require 'k' on the nearest existing ancestor ("Shared", which user2 lacks).
	// Otherwise a grantee could auto-create mailboxes in the owner's namespace.
	movable2 := fmt.Sprintf("Shared/Movable2-%d", ts)
	if err := c1.Create(movable2, nil).Wait(); err != nil {
		t.Fatalf("CREATE movable2 failed: %v", err)
	}
	defer func() { c1.Delete(movable2).Wait() }()
	if err := c1.SetACL(movable2, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lrx")).Wait(); err != nil {
		t.Fatalf("SETACL movable2 failed: %v", err)
	}
	brandNewTarget := fmt.Sprintf("Shared/BrandNew-%d/Movable2-%d", ts, ts)
	if err := c2.Rename(movable2, brandNewTarget, nil).Wait(); err == nil {
		t.Errorf("RENAME auto-creating a parent without 'k' on the nearest ancestor should be denied")
		c1.Delete(brandNewTarget).Wait()
		c1.Delete(fmt.Sprintf("Shared/BrandNew-%d", ts)).Wait()
	} else {
		t.Logf("✓ RENAME into an auto-created parent denied without 'k' on the ancestor: %v", err)
	}
}

// TestACL_StoreAppliesPermittedFlagSubset verifies RFC 4314 §4: a +FLAGS STORE
// applies the flags the user may change and silently drops the rest (SHOULD NOT
// fail when at least one flag is modifiable), but fails when none are modifiable.
func TestACL_StoreAppliesPermittedFlagSubset(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	email2, password2 := createSecondUser(t, server, "example.com", "storesubset")

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()
	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/TestStoreSubset-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	msgBody := []byte("Subject: subset\r\n\r\nbody")
	appendCmd := c1.Append(sharedMailbox, int64(len(msgBody)), nil)
	if _, err := appendCmd.Write(msgBody); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// user2 may change \Seen ('s') and read, but not other flags ('w') or \Deleted ('t').
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lrs")).Wait(); err != nil {
		t.Fatalf("SETACL lrs failed: %v", err)
	}

	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial for user2: %v", err)
	}
	defer c2.Logout()
	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}
	if _, err := c2.Select(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("User2 SELECT failed: %v", err)
	}

	// +FLAGS (\Seen \Flagged): \Seen permitted (s), \Flagged dropped (no w) — must NOT fail.
	if _, err := c2.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen, imap.FlagFlagged},
	}, nil).Collect(); err != nil {
		t.Fatalf("partial STORE should not fail (\\Seen modifiable): %v", err)
	}
	c2.Unselect().Wait()

	// Owner verifies \Seen was applied and \Flagged was not.
	if _, err := c1.Select(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Owner SELECT failed: %v", err)
	}
	msgs, err := c1.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil || len(msgs) == 0 {
		t.Fatalf("owner FETCH flags failed: %v", err)
	}
	if !containsFlag(msgs[0].Flags, imap.FlagSeen) {
		t.Errorf("expected \\Seen to be applied, flags=%v", msgs[0].Flags)
	}
	if containsFlag(msgs[0].Flags, imap.FlagFlagged) {
		t.Errorf("expected \\Flagged to be dropped (no 'w' right), flags=%v", msgs[0].Flags)
	}
	c1.Unselect().Wait()
	t.Logf("✓ partial STORE applied \\Seen and dropped \\Flagged without failing")

	// +FLAGS (\Flagged) alone: user can modify none → must fail.
	if _, err := c2.Select(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("User2 re-SELECT failed: %v", err)
	}
	if _, err := c2.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagFlagged},
	}, nil).Collect(); err == nil {
		t.Errorf("STORE of only-unmodifiable flags should fail")
	} else {
		t.Logf("✓ STORE failed when no requested flag is modifiable: %v", err)
	}
}

// TestACL_CopyFiltersFlagsByRights verifies RFC 4314 §4: copied messages keep only
// the flags the user may set on the destination (\Deleted needs 't', others 'w'),
// without failing the COPY — mirroring the RFC §4 COPY example.
func TestACL_CopyFiltersFlagsByRights(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	email2, password2 := createSecondUser(t, server, "example.com", "copyfilter")

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()
	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	ts := common.GetTimestamp()
	src := fmt.Sprintf("Shared/CopySrc-%d", ts)
	dst := fmt.Sprintf("Shared/CopyDst-%d", ts)
	for _, mb := range []string{src, dst} {
		if err := c1.Create(mb, nil).Wait(); err != nil {
			t.Fatalf("CREATE %s failed: %v", mb, err)
		}
		defer func(m string) { c1.Delete(m).Wait() }(mb)
	}

	// Owner appends a message to src carrying \Deleted and \Flagged.
	msgBody := []byte("Subject: copyflags\r\n\r\nbody")
	appendCmd := c1.Append(src, int64(len(msgBody)), &imap.AppendOptions{Flags: []imap.Flag{imap.FlagDeleted, imap.FlagFlagged}})
	if _, err := appendCmd.Write(msgBody); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// user2: read on src, insert-only on dst (no 't'/'w').
	if err := c1.SetACL(src, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lr")).Wait(); err != nil {
		t.Fatalf("SETACL src failed: %v", err)
	}
	if err := c1.SetACL(dst, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lri")).Wait(); err != nil {
		t.Fatalf("SETACL dst failed: %v", err)
	}

	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial for user2: %v", err)
	}
	defer c2.Logout()
	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}
	if _, err := c2.Select(src, nil).Wait(); err != nil {
		t.Fatalf("User2 SELECT src failed: %v", err)
	}

	// COPY must succeed (i held) but strip \Deleted and \Flagged on the destination.
	if _, err := c2.Copy(imap.SeqSetNum(1), dst).Wait(); err != nil {
		t.Fatalf("COPY should succeed with 'i' right, got: %v", err)
	}
	c2.Unselect().Wait()

	if _, err := c1.Select(dst, nil).Wait(); err != nil {
		t.Fatalf("Owner SELECT dst failed: %v", err)
	}
	msgs, err := c1.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil || len(msgs) == 0 {
		t.Fatalf("owner FETCH dst flags failed: %v", err)
	}
	if containsFlag(msgs[0].Flags, imap.FlagDeleted) {
		t.Errorf("copied message should have lost \\Deleted (no 't' right), flags=%v", msgs[0].Flags)
	}
	if containsFlag(msgs[0].Flags, imap.FlagFlagged) {
		t.Errorf("copied message should have lost \\Flagged (no 'w' right), flags=%v", msgs[0].Flags)
	}
	c1.Unselect().Wait()
	t.Logf("✓ COPY stripped \\Deleted and \\Flagged the user could not set on the destination")
}

// TestACL_StoreReplacePreservesUnmodifiableFlags verifies RFC 4314 §4: a STORE
// FLAGS (replace) must NOT clear flags the user lacks the right to modify. A user
// with only 's' replacing the flag set leaves \Deleted ('t') and \Flagged ('w')
// untouched while still updating \Seen.
func TestACL_StoreReplacePreservesUnmodifiableFlags(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	email2, password2 := createSecondUser(t, server, "example.com", "storereplace")

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()
	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/TestStoreReplace-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	// Owner appends a message already carrying \Seen, \Deleted and \Flagged.
	msgBody := []byte("Subject: replace\r\n\r\nbody")
	appendCmd := c1.Append(sharedMailbox, int64(len(msgBody)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen, imap.FlagDeleted, imap.FlagFlagged},
	})
	if _, err := appendCmd.Write(msgBody); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// user2 may change \Seen ('s') only.
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lrs")).Wait(); err != nil {
		t.Fatalf("SETACL lrs failed: %v", err)
	}

	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial for user2: %v", err)
	}
	defer c2.Logout()
	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}
	if _, err := c2.Select(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("User2 SELECT failed: %v", err)
	}

	// Replace the flag set with the empty set. \Seen is modifiable → cleared;
	// \Deleted and \Flagged are NOT modifiable → must be preserved.
	if _, err := c2.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsSet,
		Flags: []imap.Flag{},
	}, nil).Collect(); err != nil {
		t.Fatalf("STORE FLAGS () replace failed: %v", err)
	}
	c2.Unselect().Wait()

	if _, err := c1.Select(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Owner SELECT failed: %v", err)
	}
	msgs, err := c1.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil || len(msgs) == 0 {
		t.Fatalf("owner FETCH flags failed: %v", err)
	}
	flags := msgs[0].Flags
	if containsFlag(flags, imap.FlagSeen) {
		t.Errorf("\\Seen should have been cleared by the replace (user holds 's'), flags=%v", flags)
	}
	if !containsFlag(flags, imap.FlagDeleted) {
		t.Errorf("\\Deleted must be preserved (user lacks 't'), flags=%v", flags)
	}
	if !containsFlag(flags, imap.FlagFlagged) {
		t.Errorf("\\Flagged must be preserved (user lacks 'w'), flags=%v", flags)
	}
	c1.Unselect().Wait()
	t.Logf("✓ replace cleared \\Seen but preserved \\Deleted and \\Flagged the user could not modify")
}

// TestACL_GetACLIncludesOwnerOnPersonalMailbox verifies that GETACL lists the
// mailbox owner with full rights even on a personal (non-shared) mailbox, where
// no owner ACL row is materialized (RFC 4314 §3.3 example shows the owner listed).
func TestACL_GetACLIncludesOwnerOnPersonalMailbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()
	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	getACLData, err := c1.GetACL("INBOX").Wait()
	if err != nil {
		t.Fatalf("GETACL INBOX failed: %v", err)
	}
	ownerRights, found := getACLData.Rights[imap.RightsIdentifier(account1.Email)]
	if !found {
		t.Fatalf("GETACL on personal INBOX must list the owner %s, got %+v", account1.Email, getACLData.Rights)
	}
	for _, r := range "lrswipkxtea" {
		if !strings.ContainsRune(ownerRights.String(), r) {
			t.Errorf("owner should have full rights, missing %c in %q", r, ownerRights.String())
		}
	}
	t.Logf("✓ GETACL lists the owner with full rights on a personal mailbox: %s", ownerRights.String())
}

// TestACL_MyRightsUnionsAnyone verifies RFC 4314 §2 consistency: MYRIGHTS reports
// the UNION of a user's specific rights and applicable "anyone" rights, matching
// what the server actually enforces.
func TestACL_MyRightsUnionsAnyone(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	email2, password2 := createSecondUser(t, server, "example.com", "unionrights")

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()
	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/TestUnion-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	// "anyone" grants 'i'; user2 has an explicit 'lr' entry that omits 'i'.
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier("anyone"), imap.RightModificationReplace, imap.RightSet("i")).Wait(); err != nil {
		t.Fatalf("SETACL anyone failed: %v", err)
	}
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lr")).Wait(); err != nil {
		t.Fatalf("SETACL user2 failed: %v", err)
	}

	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial for user2: %v", err)
	}
	defer c2.Logout()
	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}

	myRights, err := c2.MyRights(sharedMailbox).Wait()
	if err != nil {
		t.Fatalf("MYRIGHTS failed: %v", err)
	}
	got := myRights.Rights.String()
	for _, r := range "lri" {
		if !strings.ContainsRune(got, r) {
			t.Errorf("MYRIGHTS should union user 'lr' with anyone 'i' → include %c, got %q", r, got)
		}
	}
	t.Logf("✓ MYRIGHTS reports the union of specific and 'anyone' rights: %s", got)
}

// TestACL_ListRightsAcceptsAnyone verifies LISTRIGHTS works for the special
// "anyone" identifier rather than failing with "user does not exist".
func TestACL_ListRightsAcceptsAnyone(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()
	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/TestLRAnyone-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	data, err := c1.ListRights(sharedMailbox, imap.RightsIdentifier("anyone")).Wait()
	if err != nil {
		t.Fatalf("LISTRIGHTS for 'anyone' should succeed, got: %v", err)
	}
	if len(data.OptionalRights) == 0 {
		t.Errorf("LISTRIGHTS for 'anyone' returned no optional rights")
	}
	t.Logf("✓ LISTRIGHTS accepts the 'anyone' identifier (%d optional groups)", len(data.OptionalRights))
}

// TestACL_RejectsNegativeIdentifier verifies RFC 4314 §2: identifiers starting with
// "-" (negative rights) are refused, since this server does not implement them.
func TestACL_RejectsNegativeIdentifier(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()
	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/TestNegId-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier("-someone@example.com"), imap.RightModificationReplace, imap.RightSet("lr")).Wait(); err == nil {
		t.Errorf("SETACL with a negative-right identifier should be rejected")
	} else {
		t.Logf("✓ SETACL rejected negative-right identifier: %v", err)
	}
	if _, err := c1.ListRights(sharedMailbox, imap.RightsIdentifier("-someone@example.com")).Wait(); err == nil {
		t.Errorf("LISTRIGHTS with a negative-right identifier should be rejected")
	} else {
		t.Logf("✓ LISTRIGHTS rejected negative-right identifier: %v", err)
	}
}
