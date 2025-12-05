//go:build integration

package imap_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_SearchOrderDESC verifies that ESEARCH MIN/MAX work correctly
// regardless of the database ORDER BY direction (DESC or ASC).
// Regression test for bug fixed in commit b9010c8 where changing to ASC order
// broke iOS Mail because the MIN/MAX logic assumed ASC order.
func TestIMAP_SearchOrderDESC(t *testing.T) {
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

	// Append 5 messages with known UIDs
	var uids []imap.UID
	for i := 1; i <= 5; i++ {
		msg := fmt.Sprintf("From: test@example.com\r\nSubject: Message %d\r\nDate: %s\r\n\r\nBody %d\r\n",
			i, time.Now().Add(time.Duration(i)*time.Second).Format(time.RFC1123Z), i)
		appendCmd := c.Append("INBOX", int64(len(msg)), nil)
		appendCmd.Write([]byte(msg))
		appendCmd.Close()
		appendData, err := appendCmd.Wait()
		if err != nil {
			t.Fatalf("Failed to append message %d: %v", i, err)
		}
		uids = append(uids, appendData.UID)
		t.Logf("Appended message %d with UID %d", i, appendData.UID)
	}

	// SELECT INBOX
	_, err = c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Failed to SELECT: %v", err)
	}

	// UIDs should be sequential: 1, 2, 3, 4, 5
	minUID := uids[0]           // First appended = smallest UID
	maxUID := uids[len(uids)-1] // Last appended = largest UID

	// Test ESEARCH MIN/MAX correctness
	// This is the critical test that broke in commit ad7a0f9 when ORDER BY changed to ASC
	// The MIN/MAX logic was updated to work with DESC order in commit b9010c8
	t.Run("ESEARCH_MIN_MAX_correct", func(t *testing.T) {
		searchData, err := c.UIDSearch(&imap.SearchCriteria{}, &imap.SearchOptions{
			ReturnMin: true,
			ReturnMax: true,
		}).Wait()
		if err != nil {
			t.Fatalf("ESEARCH MIN/MAX failed: %v", err)
		}

		t.Logf("ESEARCH returned MIN=%d, MAX=%d (expected MIN=%d, MAX=%d)",
			searchData.Min, searchData.Max, minUID, maxUID)

		// MIN must be the smallest UID
		if searchData.Min != uint32(minUID) {
			t.Errorf("ESEARCH MIN should be %d, got %d", minUID, searchData.Min)
			t.Error("MIN/MAX logic broken - likely ORDER BY changed without updating MIN/MAX calculation")
		}

		// MAX must be the largest UID
		if searchData.Max != uint32(maxUID) {
			t.Errorf("ESEARCH MAX should be %d, got %d", maxUID, searchData.Max)
			t.Error("MIN/MAX logic broken - likely ORDER BY changed without updating MIN/MAX calculation")
		}

		// Critical invariant: MIN <= MAX
		if searchData.Min > searchData.Max {
			t.Fatalf("ESEARCH MIN (%d) > MAX (%d) - INVALID! This breaks iOS Mail and other clients",
				searchData.Min, searchData.Max)
		}

		t.Logf("✓ ESEARCH MIN/MAX are correct and MIN <= MAX")
	})

	// Test ESEARCH MIN/MAX with a UID range (simulates iOS Mail searching for new messages)
	t.Run("ESEARCH_MIN_MAX_with_UID_range", func(t *testing.T) {
		// Search for UIDs 3 and higher (last 3 messages)
		var uidSet imap.UIDSet
		uidSet.AddRange(uids[2], 0) // 3:*

		searchData, err := c.UIDSearch(&imap.SearchCriteria{
			UID: []imap.UIDSet{uidSet},
		}, &imap.SearchOptions{
			ReturnMin: true,
			ReturnMax: true,
		}).Wait()
		if err != nil {
			t.Fatalf("ESEARCH with UID range failed: %v", err)
		}

		// For range 3:*, MIN should be 3, MAX should be 5
		expectedMin := uids[2]
		expectedMax := uids[4]

		t.Logf("ESEARCH for UID %d:* returned MIN=%d, MAX=%d (expected MIN=%d, MAX=%d)",
			uids[2], searchData.Min, searchData.Max, expectedMin, expectedMax)

		if searchData.Min != uint32(expectedMin) {
			t.Errorf("ESEARCH MIN should be %d, got %d", expectedMin, searchData.Min)
		}

		if searchData.Max != uint32(expectedMax) {
			t.Errorf("ESEARCH MAX should be %d, got %d", expectedMax, searchData.Max)
		}

		if searchData.Min > searchData.Max {
			t.Fatalf("ESEARCH MIN (%d) > MAX (%d) - INVALID!", searchData.Min, searchData.Max)
		}

		t.Logf("✓ ESEARCH MIN/MAX correct for UID range search")
	})
}
