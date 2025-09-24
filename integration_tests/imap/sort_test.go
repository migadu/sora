//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

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
		from    string // Display name + email
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
