//go:build integration

package imap_test

import (
	"fmt"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestAppendExistsNotification tests that other clients can see messages after APPEND
// This reproduces imaptest "append command" test 3/20 and 6/20
//
// According to RFC 3501:
//   - When a message is added to the mailbox, the server SHOULD send an untagged EXISTS
//     response to all clients with the mailbox selected
//
// Note: We test this by verifying conn2 can see new messages via STATUS/NOOP.
func TestAppendExistsNotification(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	conn1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial conn1: %v", err)
	}
	defer conn1.Logout()

	conn2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial conn2: %v", err)
	}
	defer conn2.Logout()

	if err := conn1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("conn1 login failed: %v", err)
	}

	if err := conn2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("conn2 login failed: %v", err)
	}

	mbox1, err := conn1.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("conn1 select failed: %v", err)
	}
	t.Logf("conn1: INBOX selected, %d messages", mbox1.NumMessages)

	mbox2, err := conn2.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("conn2 select failed: %v", err)
	}
	t.Logf("conn2: INBOX selected, %d messages", mbox2.NumMessages)
	initialCount := mbox2.NumMessages

	// APPEND on conn1
	msg := "Subject: test\r\n\r\ntest body"
	appendCmd := conn1.Append("INBOX", int64(len(msg)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen, imap.FlagFlagged},
	})
	if _, err := appendCmd.Write([]byte(msg)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	t.Log("conn1: APPEND completed")
	time.Sleep(100 * time.Millisecond)

	// conn2: Verify message is visible via STATUS
	statusData, err := conn2.Status("INBOX", &imap.StatusOptions{
		NumMessages: true,
	}).Wait()
	if err != nil {
		t.Fatalf("conn2: STATUS failed: %v", err)
	}

	expectedCount := initialCount + 1
	actualCount := statusData.NumMessages

	t.Logf("conn2: STATUS shows %d messages (expected %d)", *actualCount, expectedCount)

	if *actualCount != expectedCount {
		t.Errorf("conn2: Expected %d messages after APPEND, got %d", expectedCount, *actualCount)
	}

	t.Log("✓ APPEND EXISTS notification test passed")
}

// TestAppendExistsThenFetch tests APPEND then FETCH to verify flags
func TestAppendExistsThenFetch(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	conn1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial conn1: %v", err)
	}
	defer conn1.Logout()

	conn2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial conn2: %v", err)
	}
	defer conn2.Logout()

	if err := conn1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("conn1 login failed: %v", err)
	}

	if err := conn2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("conn2 login failed: %v", err)
	}

	if _, err := conn1.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("conn1 select failed: %v", err)
	}

	if _, err := conn2.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("conn2 select failed: %v", err)
	}

	// APPEND with specific flags
	msg := "Subject: test\r\n\r\nbody"
	appendCmd := conn1.Append("INBOX", int64(len(msg)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen, imap.FlagFlagged},
	})
	if _, err := appendCmd.Write([]byte(msg)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	appendData, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	t.Logf("conn1: APPEND completed, UID=%d", appendData.UID)
	time.Sleep(100 * time.Millisecond)

	// conn2: Reselect to get updated message count
	mbox2, err := conn2.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("conn2: Reselect failed: %v", err)
	}

	t.Logf("conn2: INBOX has %d messages", mbox2.NumMessages)

	// FETCH the message to verify flags
	fetchCmd := conn2.Fetch(imap.SeqSetNum(mbox2.NumMessages), &imap.FetchOptions{
		UID:   true,
		Flags: true,
	})

	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("conn2: FETCH failed: %v", err)
	}

	if len(msgs) != 1 {
		t.Fatalf("conn2: Expected 1 message from FETCH, got %d", len(msgs))
	}

	fetchedMsg := msgs[0]
	t.Logf("conn2: FETCH returned UID=%d, Flags=%v", fetchedMsg.UID, fetchedMsg.Flags)

	// Verify flags
	hasSeen := containsFlag(fetchedMsg.Flags, imap.FlagSeen)
	hasFlagged := containsFlag(fetchedMsg.Flags, imap.FlagFlagged)

	if !hasSeen {
		t.Error("conn2: FETCH missing \\Seen flag (was set during APPEND)")
	}
	if !hasFlagged {
		t.Error("conn2: FETCH missing \\Flagged flag (was set during APPEND)")
	}

	if hasSeen && hasFlagged {
		t.Log("conn2: ✓ FETCH returned correct flags")
	}

	t.Log("✓ APPEND EXISTS then FETCH test passed")
}

// TestAppendExistsSequential tests sequential APPENDs from different clients
func TestAppendExistsSequential(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	conn1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial conn1: %v", err)
	}
	defer conn1.Logout()

	conn2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial conn2: %v", err)
	}
	defer conn2.Logout()

	if err := conn1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("conn1 login failed: %v", err)
	}
	if err := conn2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("conn2 login failed: %v", err)
	}

	mbox1, err := conn1.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("conn1 select failed: %v", err)
	}
	initialCount := mbox1.NumMessages

	if _, err := conn2.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("conn2 select failed: %v", err)
	}

	// Append 3 messages sequentially from conn1
	for i := 1; i <= 3; i++ {
		msg := fmt.Sprintf("Subject: msg%d\r\n\r\nbody%d", i, i)
		appendCmd := conn1.Append("INBOX", int64(len(msg)), nil)
		if _, err := appendCmd.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND %d write failed: %v", i, err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND %d close failed: %v", i, err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND %d failed: %v", i, err)
		}

		t.Logf("conn1: APPEND %d completed", i)
		time.Sleep(50 * time.Millisecond)

		// Check conn2 can see the new message via STATUS
		statusData, err := conn2.Status("INBOX", &imap.StatusOptions{
			NumMessages: true,
		}).Wait()
		if err != nil {
			t.Fatalf("conn2: STATUS failed: %v", err)
		}

		expectedCount := initialCount + uint32(i)
		actualCount := statusData.NumMessages

		t.Logf("conn2: STATUS #%d: %d messages (expected %d)",
			i, *actualCount, expectedCount)

		if *actualCount != expectedCount {
			t.Errorf("conn2: After APPEND #%d, expected %d messages, got %d",
				i, expectedCount, *actualCount)
		}
	}

	t.Log("✓ Sequential APPEND EXISTS test passed")
}
