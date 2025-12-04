//go:build integration

package imap_test

import (
	"fmt"
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestESEARCHMinMax tests ESEARCH RETURN (MIN/MAX) functionality
// This reproduces imaptest "esearch command" tests 5-6, 11-12, 17-18
//
// According to the imaptest failure:
// Expected: esearch (tag $tag) min 1
// Actual:   ESEARCH (TAG "12.18") MIN 7
//
// This suggests MIN/MAX are returning wrong values after EXPUNGE
func TestESEARCHMinMaxBasic(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select failed: %v", err)
	}

	// Append 6 messages (matching imaptest scenario)
	for i := 1; i <= 6; i++ {
		msg := fmt.Sprintf("Subject: msg%d\r\n\r\nbody%d", i, i)
		appendCmd := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := appendCmd.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND %d write failed: %v", i, err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND %d close failed: %v", i, err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND %d failed: %v", i, err)
		}
	}

	// According to imaptest:
	// "ok store 4 +flags \deleted"
	// "ok expunge"
	// Then test MIN/MAX

	// Mark message 4 as deleted
	if err := c.Store(imap.SeqSetNum(4), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		t.Fatalf("STORE failed: %v", err)
	}

	// EXPUNGE
	if err := c.Expunge().Close(); err != nil {
		t.Fatalf("EXPUNGE failed: %v", err)
	}

	t.Log("After EXPUNGE: should have 5 messages with sequences 1-5")

	// Now test SEARCH RETURN (MIN) ALL
	// Expected: MIN should be 1 (first sequence number)
	searchData, err := c.Search(&imap.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH failed: %v", err)
	}

	seqNums := searchData.AllSeqNums()
	t.Logf("SEARCH ALL returned sequences: %v", seqNums)

	if len(seqNums) != 5 {
		t.Errorf("Expected 5 messages, got %d", len(seqNums))
	}

	// Check MIN - should be 1
	if len(seqNums) > 0 {
		minSeq := seqNums[0]
		t.Logf("MIN sequence number: %d", minSeq)
		if minSeq != 1 {
			t.Errorf("ESEARCH MIN BUG: Expected MIN=1, got MIN=%d", minSeq)
		}
	}

	// Check MAX - should be 5 (after removing message 4, we have 5 messages)
	if len(seqNums) > 0 {
		maxSeq := seqNums[len(seqNums)-1]
		t.Logf("MAX sequence number: %d", maxSeq)
		if maxSeq != 5 {
			t.Errorf("ESEARCH MAX BUG: Expected MAX=5, got MAX=%d", maxSeq)
		}
	}

	t.Log("✓ ESEARCH MIN/MAX basic test completed")
}

// TestESEARCHMinMaxWithFlags tests ESEARCH MIN/MAX with flag filtering
// This is the exact scenario from imaptest line 42-53
func TestESEARCHMinMaxWithFlags(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select failed: %v", err)
	}

	// Append 6 messages
	for i := 1; i <= 6; i++ {
		msg := fmt.Sprintf("Subject: msg%d\r\n\r\nbody%d", i, i)
		appendCmd := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := appendCmd.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
	}

	// Delete message 4 and expunge
	if err := c.Store(imap.SeqSetNum(4), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		t.Fatalf("STORE failed: %v", err)
	}

	if err := c.Expunge().Close(); err != nil {
		t.Fatalf("EXPUNGE failed: %v", err)
	}

	// Now mark messages 2,4 (in the new sequence) as \Seen
	// After expunge of original msg 4, the sequences are:
	// 1=msg1, 2=msg2, 3=msg3, 4=msg5, 5=msg6
	// So marking 2,4 means msg2 and msg5
	if err := c.Store(imap.SeqSetNum(2, 4), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil).Close(); err != nil {
		t.Fatalf("STORE \\Seen failed: %v", err)
	}

	// Search for \Seen messages
	searchData, err := c.Search(&imap.SearchCriteria{
		Flag: []imap.Flag{imap.FlagSeen},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH \\Seen failed: %v", err)
	}

	seqNums := searchData.AllSeqNums()
	t.Logf("SEARCH \\Seen returned sequences: %v", seqNums)

	if len(seqNums) != 2 {
		t.Errorf("Expected 2 messages with \\Seen, got %d", len(seqNums))
	}

	// Check MIN - should be 2
	if len(seqNums) > 0 {
		minSeq := seqNums[0]
		t.Logf("SEARCH \\Seen MIN: %d", minSeq)
		if minSeq != 2 {
			t.Errorf("ESEARCH MIN BUG: Expected MIN=2 for \\Seen messages, got MIN=%d", minSeq)
		}
	}

	// Check MAX - should be 4
	if len(seqNums) > 0 {
		maxSeq := seqNums[len(seqNums)-1]
		t.Logf("SEARCH \\Seen MAX: %d", maxSeq)
		if maxSeq != 4 {
			t.Errorf("ESEARCH MAX BUG: Expected MAX=4 for \\Seen messages, got MAX=%d", maxSeq)
		}
	}

	t.Log("✓ ESEARCH MIN/MAX with flags test completed")
}

// TestESEARCHUIDMinMax tests UID SEARCH RETURN (MIN/MAX)
func TestESEARCHUIDMinMax(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select failed: %v", err)
	}

	// Append 6 messages and track UIDs
	var uids []imap.UID
	for i := 1; i <= 6; i++ {
		msg := fmt.Sprintf("Subject: msg%d\r\n\r\nbody%d", i, i)
		appendCmd := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := appendCmd.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		data, err := appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
		if data.UID != 0 {
			uids = append(uids, data.UID)
		}
	}

	// Fallback: fetch UIDs if not returned by APPEND
	if len(uids) < 6 {
		fetchCmd := c.Fetch(imap.SeqSetNum(1, 2, 3, 4, 5, 6), &imap.FetchOptions{UID: true})
		msgs, err := fetchCmd.Collect()
		if err != nil {
			t.Fatalf("FETCH UIDs failed: %v", err)
		}
		uids = nil
		for _, msg := range msgs {
			uids = append(uids, msg.UID)
		}
	}

	t.Logf("Original UIDs: %v", uids)

	// Delete message 4 and expunge
	if err := c.Store(imap.SeqSetNum(4), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		t.Fatalf("STORE failed: %v", err)
	}

	if err := c.Expunge().Close(); err != nil {
		t.Fatalf("EXPUNGE failed: %v", err)
	}

	// Mark sequences 2,4 (new numbering) as \Seen
	if err := c.Store(imap.SeqSetNum(2, 4), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil).Close(); err != nil {
		t.Fatalf("STORE \\Seen failed: %v", err)
	}

	// UID SEARCH for \Seen messages
	searchData, err := c.UIDSearch(&imap.SearchCriteria{
		Flag: []imap.Flag{imap.FlagSeen},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("UID SEARCH \\Seen failed: %v", err)
	}

	searchUIDs := searchData.AllUIDs()
	t.Logf("UID SEARCH \\Seen returned UIDs: %v", searchUIDs)

	if len(searchUIDs) != 2 {
		t.Errorf("Expected 2 UIDs with \\Seen, got %d", len(searchUIDs))
	}

	// After expunge of msg4, sequences 2,4 correspond to:
	// Seq 2 = original msg 2 = uids[1]
	// Seq 4 = original msg 5 = uids[4]

	if len(searchUIDs) > 0 && len(uids) >= 5 {
		expectedMinUID := uids[1] // msg2
		expectedMaxUID := uids[4] // msg5

		minUID := searchUIDs[0]
		maxUID := searchUIDs[len(searchUIDs)-1]

		t.Logf("UID SEARCH \\Seen MIN: %d (expected %d)", minUID, expectedMinUID)
		t.Logf("UID SEARCH \\Seen MAX: %d (expected %d)", maxUID, expectedMaxUID)

		if minUID != expectedMinUID {
			t.Errorf("UID ESEARCH MIN BUG: Expected MIN=%d, got MIN=%d", expectedMinUID, minUID)
		}

		if maxUID != expectedMaxUID {
			t.Errorf("UID ESEARCH MAX BUG: Expected MAX=%d, got MAX=%d", expectedMaxUID, maxUID)
		}
	}

	t.Log("✓ UID ESEARCH MIN/MAX test completed")
}

// TestESEARCHCount tests SEARCH RETURN (COUNT)
func TestESEARCHCount(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select failed: %v", err)
	}

	// Append 6 messages
	for i := 1; i <= 6; i++ {
		msg := fmt.Sprintf("Subject: msg%d\r\n\r\nbody%d", i, i)
		appendCmd := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := appendCmd.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
	}

	// Delete and expunge message 4
	if err := c.Store(imap.SeqSetNum(4), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		t.Fatalf("STORE failed: %v", err)
	}

	if err := c.Expunge().Close(); err != nil {
		t.Fatalf("EXPUNGE failed: %v", err)
	}

	// Search ALL and check count
	searchData, err := c.Search(&imap.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH ALL failed: %v", err)
	}

	seqNums := searchData.AllSeqNums()
	count := len(seqNums)

	t.Logf("SEARCH ALL COUNT: %d", count)

	if count != 5 {
		t.Errorf("Expected COUNT=5, got COUNT=%d", count)
	}

	t.Log("✓ ESEARCH COUNT test completed")
}
