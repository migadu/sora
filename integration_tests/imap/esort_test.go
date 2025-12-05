//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_ESORT verifies that SORT with RETURN options generates ESEARCH responses
// RFC 5267 (ESORT): SORT command with RETURN (MIN/MAX/ALL/COUNT) should return ESEARCH
func TestIMAP_ESORT(t *testing.T) {
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
		t.Fatalf("SELECT failed: %v", err)
	}

	// Append 5 messages with different subjects to sort
	subjects := []string{"AAA", "BBB", "CCC", "DDD", "EEE"}
	for _, subj := range subjects {
		msg := "From: test@example.com\r\nTo: user@example.com\r\nSubject: " + subj + "\r\n\r\nBody\r\n"
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

	// Test 1: SORT RETURN (MIN)
	t.Run("RETURN MIN", func(t *testing.T) {
		sortData, err := c.Sort(&imapclient.SortOptions{
			SortCriteria: []imap.SortCriterion{{Key: imap.SortKeyArrival}},
			SearchCriteria: &imap.SearchCriteria{
				SeqNum: []imap.SeqSet{imap.SeqSetNum(1, 2, 3, 4, 5)},
			},
			Return: imap.SortOptions{
				ReturnMin: true,
			},
		}).Wait()
		if err != nil {
			t.Fatalf("SORT RETURN (MIN) failed: %v", err)
		}

		t.Logf("SORT RETURN (MIN) result: Min=%d, Max=%d, Count=%d", sortData.Min, sortData.Max, sortData.Count)

		if sortData.Min == 0 {
			t.Error("Expected Min to be set, got 0")
		}
	})

	// Test 2: SORT RETURN (MAX)
	t.Run("RETURN MAX", func(t *testing.T) {
		sortData, err := c.Sort(&imapclient.SortOptions{
			SortCriteria: []imap.SortCriterion{{Key: imap.SortKeyArrival}},
			SearchCriteria: &imap.SearchCriteria{
				SeqNum: []imap.SeqSet{imap.SeqSetNum(1, 2, 3, 4, 5)},
			},
			Return: imap.SortOptions{
				ReturnMax: true,
			},
		}).Wait()
		if err != nil {
			t.Fatalf("SORT RETURN (MAX) failed: %v", err)
		}

		t.Logf("SORT RETURN (MAX) result: Min=%d, Max=%d, Count=%d", sortData.Min, sortData.Max, sortData.Count)

		if sortData.Max == 0 {
			t.Error("Expected Max to be set, got 0")
		}
	})

	// Test 3: SORT RETURN (COUNT)
	t.Run("RETURN COUNT", func(t *testing.T) {
		sortData, err := c.Sort(&imapclient.SortOptions{
			SortCriteria: []imap.SortCriterion{{Key: imap.SortKeyArrival}},
			SearchCriteria: &imap.SearchCriteria{
				SeqNum: []imap.SeqSet{imap.SeqSetNum(1, 2, 3, 4, 5)},
			},
			Return: imap.SortOptions{
				ReturnCount: true,
			},
		}).Wait()
		if err != nil {
			t.Fatalf("SORT RETURN (COUNT) failed: %v", err)
		}

		t.Logf("SORT RETURN (COUNT) result: Min=%d, Max=%d, Count=%d", sortData.Min, sortData.Max, sortData.Count)

		if sortData.Count == 0 {
			t.Error("Expected Count to be set, got 0")
		}

		expectedCount := uint32(5)
		if sortData.Count != expectedCount {
			t.Errorf("Expected Count=%d, got %d", expectedCount, sortData.Count)
		}
	})

	// Test 4: SORT RETURN (MIN MAX)
	t.Run("RETURN MIN MAX", func(t *testing.T) {
		sortData, err := c.Sort(&imapclient.SortOptions{
			SortCriteria: []imap.SortCriterion{{Key: imap.SortKeyArrival}},
			SearchCriteria: &imap.SearchCriteria{
				SeqNum: []imap.SeqSet{imap.SeqSetNum(1, 2, 3, 4, 5)},
			},
			Return: imap.SortOptions{
				ReturnMin: true,
				ReturnMax: true,
			},
		}).Wait()
		if err != nil {
			t.Fatalf("SORT RETURN (MIN MAX) failed: %v", err)
		}

		t.Logf("SORT RETURN (MIN MAX) result: Min=%d, Max=%d, Count=%d", sortData.Min, sortData.Max, sortData.Count)

		if sortData.Min == 0 {
			t.Error("Expected Min to be set, got 0")
		}

		if sortData.Max == 0 {
			t.Error("Expected Max to be set, got 0")
		}

		// Min should be less than or equal to Max
		if sortData.Min > sortData.Max {
			t.Errorf("Min (%d) should be <= Max (%d)", sortData.Min, sortData.Max)
		}
	})

	// Test 5: Regular SORT (no RETURN)
	t.Run("Regular SORT", func(t *testing.T) {
		sortData, err := c.Sort(&imapclient.SortOptions{
			SortCriteria: []imap.SortCriterion{{Key: imap.SortKeyArrival}},
			SearchCriteria: &imap.SearchCriteria{
				SeqNum: []imap.SeqSet{imap.SeqSetNum(1, 2, 3, 4, 5)},
			},
		}).Wait()
		if err != nil {
			t.Fatalf("Regular SORT failed: %v", err)
		}

		t.Logf("Regular SORT result: SeqNums=%v", sortData.SeqNums)

		if len(sortData.SeqNums) == 0 {
			t.Error("Expected SeqNums to contain sequence numbers for regular SORT, got empty")
		}

		expectedCount := 5
		if len(sortData.SeqNums) != expectedCount {
			t.Errorf("Expected %d messages, got %d", expectedCount, len(sortData.SeqNums))
		}
	})
}
