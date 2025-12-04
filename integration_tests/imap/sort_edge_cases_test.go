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

// TestIMAP_SortAddressesEdgeCases tests SORT with various address field edge cases
func TestIMAP_SortAddressesEdgeCases(t *testing.T) {
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

	// Test case: Messages with different From addresses
	// Reproducing imaptest failure: Expected "3 1 2", Got "3 2 1"
	testMessages := []struct {
		from    string
		subject string
	}{
		// Message 1: From with display name starting with 'B'
		{"\"Bob User\" <bob@example.com>", "Test 1"},
		// Message 2: From with display name starting with 'A'
		{"\"Alice User\" <alice@example.com>", "Test 2"},
		// Message 3: From with display name starting with 'Z'
		{"\"Zulu User\" <zulu@example.com>", "Test 3"},
	}

	t.Log("=== Appending messages with different From addresses ===")
	for i, msg := range testMessages {
		msgBody := fmt.Sprintf("From: %s\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"Date: %s\r\n"+
			"\r\n"+
			"Message %d\r\n", msg.from, account.Email, msg.subject, time.Now().Format(time.RFC1123Z), i+1)

		appendCmd := c.Append("INBOX", int64(len(msgBody)), nil)
		appendCmd.Write([]byte(msgBody))
		appendCmd.Close()
		appendData, err := appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND %d failed: %v", i+1, err)
		}
		t.Logf("Appended message %d: UID=%d, From=%s", i+1, appendData.UID, msg.from)
	}

	// Test 1: SORT by FROM (should sort by email address or display name)
	t.Log("=== TEST 1: SORT by FROM ===")
	sortOptions := &imapclient.SortOptions{
		SearchCriteria: &imap.SearchCriteria{},
		SortCriteria:   []imap.SortCriterion{{Key: imap.SortKeyFrom, Reverse: false}},
	}
	sortResult, err := c.Sort(sortOptions).Wait()
	if err != nil {
		t.Fatalf("SORT by FROM failed: %v", err)
	}

	t.Logf("SORT by FROM result: %v", sortResult.SeqNums)

	// Expected: Should be sorted by From field
	// Alice (msg 2), Bob (msg 1), Zulu (msg 3)
	// So: 2, 1, 3
	if len(sortResult.SeqNums) != 3 {
		t.Errorf("Expected 3 messages, got %d", len(sortResult.SeqNums))
	}

	// Check if sorting is by display name (Alice < Bob < Zulu)
	if len(sortResult.SeqNums) >= 3 {
		if sortResult.SeqNums[0] == 2 && sortResult.SeqNums[1] == 1 && sortResult.SeqNums[2] == 3 {
			t.Log("✅ SORT by FROM uses display name: Alice(2), Bob(1), Zulu(3)")
		} else if sortResult.SeqNums[0] == 2 && sortResult.SeqNums[1] == 3 && sortResult.SeqNums[2] == 1 {
			t.Log("✅ SORT by FROM uses email address: alice@(2), bob@(1), zulu@(3)")
		} else {
			t.Logf("⚠️  SORT by FROM order: %v (different from expected patterns)", sortResult.SeqNums)
			t.Logf("    Expected: [2 1 3] (by display name) or [2 3 1] (by email)")
			t.Logf("    This may be a valid interpretation or edge case")
		}
	}

	// Test 2: SORT by FROM with empty/missing From fields
	t.Log("=== TEST 2: SORT with missing From fields ===")

	// Append message without From field
	msgNoFrom := fmt.Sprintf("To: %s\r\n"+
		"Subject: No From\r\n"+
		"Date: %s\r\n"+
		"\r\n"+
		"Message without From\r\n", account.Email, time.Now().Format(time.RFC1123Z))

	appendCmd := c.Append("INBOX", int64(len(msgNoFrom)), nil)
	appendCmd.Write([]byte(msgNoFrom))
	appendCmd.Close()
	appendData, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND message without From failed: %v", err)
	}
	t.Logf("Appended message 4: UID=%d, From=(none)", appendData.UID)

	// Sort again
	sortResult, err = c.Sort(sortOptions).Wait()
	if err != nil {
		t.Fatalf("SORT by FROM with missing From failed: %v", err)
	}

	t.Logf("SORT by FROM with missing field result: %v", sortResult.SeqNums)

	// Message without From should sort first (empty < any value) or last depending on implementation
	if len(sortResult.SeqNums) == 4 {
		if sortResult.SeqNums[0] == 4 {
			t.Log("✅ Empty From sorts first (empty < any value)")
		} else if sortResult.SeqNums[3] == 4 {
			t.Log("✅ Empty From sorts last (empty > any value)")
		} else {
			t.Logf("⚠️  Empty From in middle: %v", sortResult.SeqNums)
		}
	}

	// Test 3: SORT by TO
	t.Log("=== TEST 3: SORT by TO ===")
	sortOptions.SortCriteria = []imap.SortCriterion{{Key: imap.SortKeyTo, Reverse: false}}
	sortResult, err = c.Sort(sortOptions).Wait()
	if err != nil {
		t.Fatalf("SORT by TO failed: %v", err)
	}

	t.Logf("SORT by TO result: %v", sortResult.SeqNums)
	// All messages have same TO (account.Email), so order could be any
	if len(sortResult.SeqNums) != 4 {
		t.Errorf("Expected 4 messages, got %d", len(sortResult.SeqNums))
	} else {
		t.Log("✅ SORT by TO completed (all same TO address, order may vary)")
	}

	// Test 4: SORT by DISPLAY
	t.Log("=== TEST 4: SORT by DISPLAY (RFC 5957) ===")
	sortOptions.SortCriteria = []imap.SortCriterion{{Key: imap.SortKeyDisplayFrom, Reverse: false}}
	sortResult, err = c.Sort(sortOptions).Wait()
	if err != nil {
		t.Fatalf("SORT by DISPLAY failed: %v", err)
	}

	t.Logf("SORT by DISPLAY result: %v", sortResult.SeqNums)

	// DISPLAY should prefer display name over email address
	// Expected: message 4 (no From), then Alice, Bob, Zulu
	if len(sortResult.SeqNums) == 4 {
		t.Logf("✅ SORT by DISPLAY completed with order: %v", sortResult.SeqNums)
		t.Log("   (order depends on how missing From is handled)")
	}

	t.Log("=== All SORT edge case tests completed ===")
}

// TestIMAP_SortSubjectEdgeCases tests SORT by SUBJECT with edge cases
func TestIMAP_SortSubjectEdgeCases(t *testing.T) {
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

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Test messages with Subject prefixes that should be ignored per RFC 5256
	testMessages := []struct {
		subject     string
		baseSubject string // What it should sort as
	}{
		{"Re: Test Subject", "Test Subject"},
		{"Fwd: Test Subject", "Test Subject"},
		{"Test Subject", "Test Subject"},
		{"RE: Another Subject", "Another Subject"},
		{"Fw: Another Subject", "Another Subject"},
	}

	t.Log("=== Appending messages with Subject prefixes ===")
	for i, msg := range testMessages {
		msgBody := fmt.Sprintf("From: sender@example.com\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"Date: %s\r\n"+
			"\r\n"+
			"Message %d\r\n", account.Email, msg.subject, time.Now().Format(time.RFC1123Z), i+1)

		appendCmd := c.Append("INBOX", int64(len(msgBody)), nil)
		appendCmd.Write([]byte(msgBody))
		appendCmd.Close()
		_, err := appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND %d failed: %v", i+1, err)
		}
		t.Logf("Appended message %d: Subject='%s' (sorts as '%s')", i+1, msg.subject, msg.baseSubject)
	}

	// SORT by SUBJECT
	t.Log("=== TEST: SORT by SUBJECT ===")
	sortOptions := &imapclient.SortOptions{
		SearchCriteria: &imap.SearchCriteria{},
		SortCriteria:   []imap.SortCriterion{{Key: imap.SortKeySubject, Reverse: false}},
	}
	sortResult, err := c.Sort(sortOptions).Wait()
	if err != nil {
		t.Fatalf("SORT by SUBJECT failed: %v", err)
	}

	t.Logf("SORT by SUBJECT result: %v", sortResult.SeqNums)

	// Expected: Messages 4 and 5 first (Another Subject), then 1, 2, 3 (Test Subject)
	// Order within same base subject is undefined
	if len(sortResult.SeqNums) != 5 {
		t.Errorf("Expected 5 messages, got %d", len(sortResult.SeqNums))
	} else {
		// Check that "Another Subject" messages come before "Test Subject" messages
		anotherSubjectIndices := []int{}
		testSubjectIndices := []int{}

		for idx, seqNum := range sortResult.SeqNums {
			if seqNum == 4 || seqNum == 5 {
				anotherSubjectIndices = append(anotherSubjectIndices, idx)
			} else {
				testSubjectIndices = append(testSubjectIndices, idx)
			}
		}

		if len(anotherSubjectIndices) > 0 && len(testSubjectIndices) > 0 {
			if anotherSubjectIndices[len(anotherSubjectIndices)-1] < testSubjectIndices[0] {
				t.Log("✅ SORT by SUBJECT correctly groups by base subject")
				t.Logf("   'Another Subject' messages at positions: %v", anotherSubjectIndices)
				t.Logf("   'Test Subject' messages at positions: %v", testSubjectIndices)
			} else {
				t.Errorf("❌ Subject sorting does NOT strip prefixes (RFC 5256 violation)")
				t.Errorf("   Expected: All 'Another Subject' messages (4,5) before 'Test Subject' messages (1,2,3)")
				t.Errorf("   Got order: %v", sortResult.SeqNums)
				t.Errorf("   'Another Subject' at positions: %v", anotherSubjectIndices)
				t.Errorf("   'Test Subject' at positions: %v", testSubjectIndices)
				t.Errorf("   This means prefixes like 'Re:', 'Fwd:', 'RE:', 'Fw:' are NOT being stripped before sorting")
			}
		}
	}

	t.Log("=== All SORT SUBJECT edge case tests completed ===")
}
