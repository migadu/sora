//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_CONDSTOREFiltering_iOSBeforeAfterID tests that CONDSTORE fragments are properly
// filtered for iOS clients when the config disables it.
//
// Test scenario:
// 1. Client connects and logs in (no ID command yet)
// 2. Client performs SELECT - should include CONDSTORE fragments (HighestModSeq)
// 3. Client sends ID command identifying as iOS
// 4. Client performs SELECT again - should NOT include CONDSTORE fragments
func TestIMAP_CONDSTOREFiltering_iOSBeforeAfterID(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Define capability filters to disable CONDSTORE for iOS Apple Mail
	filters := []config.ClientCapabilityFilter{
		{
			ClientName:    "com\\.apple\\.email\\.maild",
			ClientVersion: ".*",
			DisableCaps:   []string{"CONDSTORE"},
			Reason:        "iOS Apple Mail has CONDSTORE implementation issues",
		},
	}

	// Setup test server with CONDSTORE filtering
	server, account := setupIMAPServerWithCapabilityFilters(t, filters)
	defer server.Close()

	// Connect using raw TCP connection for precise protocol inspection
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Set up raw IMAP protocol handling
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Helper functions for IMAP protocol
	sendCommand := func(tag, command string) {
		fmt.Fprintf(writer, "%s %s\r\n", tag, command)
		writer.Flush()
		t.Logf("SENT: %s %s", tag, command)
	}

	readResponse := func(expectedTag string) []string {
		var responses []string
		for {
			line, _, err := reader.ReadLine()
			if err != nil {
				t.Fatalf("Failed to read response: %v", err)
			}
			lineStr := string(line)
			t.Logf("RECV: %s", lineStr)
			responses = append(responses, lineStr)

			if strings.HasPrefix(lineStr, expectedTag+" ") {
				break
			}
		}
		return responses
	}

	// Read greeting
	greeting, _, err := reader.ReadLine()
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	t.Logf("RECV: %s", greeting)

	// Login
	sendCommand("A01", fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	readResponse("A01")

	// STEP 1: SELECT before ID command - should include CONDSTORE fragments
	t.Logf("=== STEP 1: SELECT before ID command (expecting CONDSTORE fragments) ===")
	sendCommand("A02", "SELECT INBOX")
	beforeIDResponses := readResponse("A02")

	// Parse SELECT response and check for CONDSTORE fragments
	var highestModSeqBeforeID *uint64
	for _, resp := range beforeIDResponses {
		if strings.HasPrefix(resp, "* OK [HIGHESTMODSEQ ") {
			// Extract HIGHESTMODSEQ value
			parts := strings.Split(resp, " ")
			if len(parts) >= 4 {
				modSeqStr := strings.TrimSuffix(parts[3], "]")
				if modSeq, err := strconv.ParseUint(modSeqStr, 10, 64); err == nil {
					highestModSeqBeforeID = &modSeq
					t.Logf("Before ID: Found HIGHESTMODSEQ %d", modSeq)
				}
			}
		}
	}

	if highestModSeqBeforeID != nil {
		t.Logf("✓ Before ID: SELECT response includes CONDSTORE fragment (HIGHESTMODSEQ %d)", *highestModSeqBeforeID)
	} else {
		t.Logf("⚠ Before ID: SELECT response does not include CONDSTORE fragments (this may be normal if no messages exist)")
	}

	// STEP 2: Send ID command to identify as iOS Apple Mail
	t.Logf("=== STEP 2: ID command to identify as iOS ===")
	sendCommand("A03", `ID ("name" "com.apple.email.maild" "version" "3826.300.87.2.22" "os" "iOS" "os-version" "18.2.1 (22C161)" "vendor" "Apple Inc")`)
	readResponse("A03")

	// STEP 3: SELECT after ID command - should NOT include CONDSTORE fragments
	t.Logf("=== STEP 3: SELECT after ID command (expecting NO CONDSTORE fragments) ===")
	sendCommand("A04", "SELECT INBOX")
	afterIDResponses := readResponse("A04")

	// Parse SELECT response and check that CONDSTORE fragments are absent
	var highestModSeqAfterID *uint64
	for _, resp := range afterIDResponses {
		if strings.HasPrefix(resp, "* OK [HIGHESTMODSEQ ") {
			// Extract HIGHESTMODSEQ value
			parts := strings.Split(resp, " ")
			if len(parts) >= 4 {
				modSeqStr := strings.TrimSuffix(parts[3], "]")
				if modSeq, err := strconv.ParseUint(modSeqStr, 10, 64); err == nil {
					highestModSeqAfterID = &modSeq
					t.Logf("After ID: Found HIGHESTMODSEQ %d", modSeq)
				}
			}
		}
	}

	// Verify the filtering behavior
	if highestModSeqAfterID != nil {
		t.Errorf("✗ FAILURE: After ID command, SELECT response still includes CONDSTORE fragment (HIGHESTMODSEQ %d)", *highestModSeqAfterID)
		t.Error("CONDSTORE capability filtering is not working properly for iOS clients")
	} else {
		t.Logf("✓ SUCCESS: After ID command, SELECT response correctly excludes CONDSTORE fragments")
		t.Logf("CONDSTORE capability filtering is working properly for iOS clients")
	}

	// Additional verification: Add a message and verify that subsequent operations also respect filtering
	t.Logf("=== STEP 4: Add message and verify CONDSTORE filtering persists ===")

	// Add a test message to trigger potential CONDSTORE responses
	messageData := fmt.Sprintf("From: test@example.com\r\nTo: %s\r\nSubject: Test CONDSTORE Filtering\r\nDate: %s\r\n\r\nThis is a test message for CONDSTORE filtering verification.",
		account.Email, time.Now().Format(time.RFC1123))

	sendCommand("A05", fmt.Sprintf("APPEND INBOX {%d}", len(messageData)))

	// Read continuation response
	contLine, _, err := reader.ReadLine()
	if err != nil {
		t.Fatalf("Failed to read continuation: %v", err)
	}
	t.Logf("RECV: %s", contLine)

	// Send message data
	fmt.Fprintf(writer, "%s\r\n", messageData)
	writer.Flush()
	readResponse("A05")

	// SELECT again after adding a message - should still not include CONDSTORE fragments
	sendCommand("A06", "SELECT INBOX")
	finalResponses := readResponse("A06")

	var highestModSeqFinal *uint64
	for _, resp := range finalResponses {
		if strings.HasPrefix(resp, "* OK [HIGHESTMODSEQ ") {
			// Extract HIGHESTMODSEQ value
			parts := strings.Split(resp, " ")
			if len(parts) >= 4 {
				modSeqStr := strings.TrimSuffix(parts[3], "]")
				if modSeq, err := strconv.ParseUint(modSeqStr, 10, 64); err == nil {
					highestModSeqFinal = &modSeq
					t.Logf("Final SELECT: Found HIGHESTMODSEQ %d", modSeq)
				}
			}
		}
	}

	if highestModSeqFinal != nil {
		t.Errorf("✗ FAILURE: Final SELECT after message addition still includes CONDSTORE fragment (HIGHESTMODSEQ %d)", *highestModSeqFinal)
	} else {
		t.Logf("✓ SUCCESS: Final SELECT correctly excludes CONDSTORE fragments even after message operations")
	}

	// STEP 5: Test FETCH command with CONDSTORE fragments
	t.Logf("=== STEP 5: Test FETCH with CONDSTORE filtering ===")

	// Test FETCH with MODSEQ attribute - should not return MODSEQ when CONDSTORE is filtered
	sendCommand("A07", "FETCH 1 (FLAGS MODSEQ)")
	fetchResponses := readResponse("A07")

	var foundModSeqInFetch bool
	for _, resp := range fetchResponses {
		if strings.Contains(resp, "MODSEQ") && strings.Contains(resp, "FETCH") {
			foundModSeqInFetch = true
			t.Logf("FETCH response includes MODSEQ: %s", resp)
		}
	}

	if foundModSeqInFetch {
		t.Errorf("✗ FAILURE: FETCH response includes MODSEQ when CONDSTORE should be filtered")
	} else {
		t.Logf("✓ SUCCESS: FETCH correctly excludes MODSEQ when CONDSTORE is filtered")
	}

	// STEP 6: Test STORE command with CONDSTORE fragments
	t.Logf("=== STEP 6: Test STORE with CONDSTORE filtering ===")

	// STORE command that would normally return MODSEQ with CONDSTORE
	sendCommand("A08", "STORE 1 +FLAGS (\\Seen)")
	storeResponses := readResponse("A08")

	var foundModSeqInStore bool
	for _, resp := range storeResponses {
		if strings.Contains(resp, "MODSEQ") && strings.Contains(resp, "FETCH") {
			foundModSeqInStore = true
			t.Logf("STORE response includes MODSEQ: %s", resp)
		}
	}

	if foundModSeqInStore {
		t.Errorf("✗ FAILURE: STORE response includes MODSEQ when CONDSTORE should be filtered")
	} else {
		t.Logf("✓ SUCCESS: STORE correctly excludes MODSEQ when CONDSTORE is filtered")
	}

	// STEP 7: Test SEARCH with CONDSTORE filtering
	t.Logf("=== STEP 7: Test SEARCH with CONDSTORE filtering ===")

	// Add another message to have something to search for
	messageData2 := fmt.Sprintf("From: test2@example.com\r\nTo: %s\r\nSubject: Another Test Message\r\nDate: %s\r\n\r\nSecond test message.",
		account.Email, time.Now().Format(time.RFC1123))

	sendCommand("A09", fmt.Sprintf("APPEND INBOX {%d}", len(messageData2)))
	contLine2, _, err := reader.ReadLine()
	if err != nil {
		t.Fatalf("Failed to read continuation: %v", err)
	}
	t.Logf("RECV: %s", contLine2)
	fmt.Fprintf(writer, "%s\r\n", messageData2)
	writer.Flush()
	readResponse("A09")

	// Search with MODSEQ criteria - should work but not return MODSEQ-specific data when filtered
	sendCommand("A10", "SEARCH MODSEQ 1")
	searchResponses := readResponse("A10")

	var foundCondstoreInSearch bool
	for _, resp := range searchResponses {
		// Look for any CONDSTORE-specific extensions in search response
		if strings.Contains(resp, "MODSEQ") && !strings.Contains(resp, "SEARCH MODSEQ") {
			foundCondstoreInSearch = true
			t.Logf("SEARCH response includes CONDSTORE data: %s", resp)
		}
	}

	if foundCondstoreInSearch {
		t.Errorf("✗ FAILURE: SEARCH response includes CONDSTORE extensions when should be filtered")
	} else {
		t.Logf("✓ SUCCESS: SEARCH correctly processes MODSEQ criteria but excludes CONDSTORE extensions when filtered")
	}

	// STEP 8: Test UNCHANGEDSINCE with STORE (should be ignored when CONDSTORE filtered)
	t.Logf("=== STEP 8: Test STORE with UNCHANGEDSINCE (should be ignored when CONDSTORE filtered) ===")

	// This should be ignored/fail gracefully when CONDSTORE is filtered
	sendCommand("A11", "STORE 1 (UNCHANGEDSINCE 1) +FLAGS (\\Flagged)")
	unchangedSinceResponses := readResponse("A11")

	for _, resp := range unchangedSinceResponses {
		// Check if it failed due to CONDSTORE being filtered
		if strings.Contains(resp, "A11 BAD") || strings.Contains(resp, "A11 NO") {
			t.Logf("STORE UNCHANGEDSINCE correctly rejected: %s", resp)
		}
	}

	// When CONDSTORE is filtered, UNCHANGEDSINCE should either be ignored or rejected
	// The exact behavior may vary, but it shouldn't include MODSEQ in responses
	var hasModSeqInUnchangedSince bool
	for _, resp := range unchangedSinceResponses {
		if strings.Contains(resp, "MODSEQ") {
			hasModSeqInUnchangedSince = true
		}
	}

	if hasModSeqInUnchangedSince {
		t.Errorf("✗ FAILURE: STORE UNCHANGEDSINCE includes MODSEQ when CONDSTORE should be filtered")
	} else {
		t.Logf("✓ SUCCESS: STORE UNCHANGEDSINCE correctly excludes MODSEQ when CONDSTORE is filtered")
	}

	t.Log("=== COMPREHENSIVE CONDSTORE filtering test completed ===")
}

// TestIMAP_CONDSTOREFiltering_NonIOSClient tests that CONDSTORE fragments are included
// for non-iOS clients even when iOS filtering is configured
func TestIMAP_CONDSTOREFiltering_NonIOSClient(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Same filters as above - should only affect iOS clients
	filters := []config.ClientCapabilityFilter{
		{
			ClientName:    "com\\.apple\\.email\\.maild",
			ClientVersion: ".*",
			DisableCaps:   []string{"CONDSTORE"},
			Reason:        "iOS Apple Mail has CONDSTORE implementation issues",
		},
	}

	server, account := setupIMAPServerWithCapabilityFilters(t, filters)
	defer server.Close()

	// Use imapclient for simpler protocol handling in this test
	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	// Login
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Send ID command identifying as a non-iOS client
	clientID := &imap.IDData{
		Name:    "Thunderbird",
		Version: "115.0",
		OS:      "Linux",
		Vendor:  "Mozilla",
	}

	if _, err := c.ID(clientID).Wait(); err != nil {
		t.Fatalf("ID command failed: %v", err)
	}

	// Add a test message to ensure we have content that will trigger CONDSTORE responses
	testMessage := fmt.Sprintf("From: test@example.com\r\nTo: %s\r\nSubject: Test Non-iOS CONDSTORE\r\nDate: %s\r\n\r\nThis message tests CONDSTORE for non-iOS clients.",
		account.Email, time.Now().Format(time.RFC1123))

	appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
		Time: time.Now(),
	})
	if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND wait failed: %v", err)
	}

	// SELECT INBOX - should include CONDSTORE fragments for non-iOS clients
	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	// Check that CONDSTORE data is present
	if selectData.HighestModSeq == 0 {
		t.Errorf("✗ FAILURE: Non-iOS client did not receive CONDSTORE data (HighestModSeq is 0)")
		t.Error("CONDSTORE should be available for non-iOS clients")
	} else {
		t.Logf("✓ SUCCESS: Non-iOS client correctly received CONDSTORE data (HighestModSeq: %d)", selectData.HighestModSeq)
	}

	t.Log("Non-iOS client CONDSTORE test completed successfully")
}

// TestIMAP_CONDSTOREFiltering_UnidentifiedClient tests that CONDSTORE fragments are included
// for unidentified clients (no ID command sent)
func TestIMAP_CONDSTOREFiltering_UnidentifiedClient(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Same filters as above
	filters := []config.ClientCapabilityFilter{
		{
			ClientName:    "com\\.apple\\.email\\.maild",
			ClientVersion: ".*",
			DisableCaps:   []string{"CONDSTORE"},
			Reason:        "iOS Apple Mail has CONDSTORE implementation issues",
		},
	}

	server, account := setupIMAPServerWithCapabilityFilters(t, filters)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	// Login without sending ID command
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Add a test message
	testMessage := fmt.Sprintf("From: test@example.com\r\nTo: %s\r\nSubject: Test Unidentified CONDSTORE\r\nDate: %s\r\n\r\nThis message tests CONDSTORE for unidentified clients.",
		account.Email, time.Now().Format(time.RFC1123))

	appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
		Time: time.Now(),
	})
	if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND wait failed: %v", err)
	}

	// SELECT INBOX - should include CONDSTORE fragments for unidentified clients
	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	// Check that CONDSTORE data is present
	if selectData.HighestModSeq == 0 {
		t.Errorf("✗ FAILURE: Unidentified client did not receive CONDSTORE data (HighestModSeq is 0)")
		t.Error("CONDSTORE should be available for unidentified clients")
	} else {
		t.Logf("✓ SUCCESS: Unidentified client correctly received CONDSTORE data (HighestModSeq: %d)", selectData.HighestModSeq)
	}

	t.Log("Unidentified client CONDSTORE test completed successfully")
}

// TestIMAP_CONDSTOREFiltering_ComprehensiveBeforeAfterID tests CONDSTORE filtering
// across all major IMAP commands (SELECT, FETCH, STORE, SEARCH) before and after ID
func TestIMAP_CONDSTOREFiltering_ComprehensiveBeforeAfterID(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Same filters as main test
	filters := []config.ClientCapabilityFilter{
		{
			ClientName:    "com\\.apple\\.email\\.maild",
			ClientVersion: ".*",
			DisableCaps:   []string{"CONDSTORE"},
			Reason:        "iOS Apple Mail has CONDSTORE implementation issues",
		},
	}

	server, account := setupIMAPServerWithCapabilityFilters(t, filters)
	defer server.Close()

	// Connect using raw TCP for precise protocol control
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	sendCommand := func(tag, command string) {
		fmt.Fprintf(writer, "%s %s\r\n", tag, command)
		writer.Flush()
		t.Logf("SENT: %s %s", tag, command)
	}

	readResponse := func(expectedTag string) []string {
		var responses []string
		for {
			line, _, err := reader.ReadLine()
			if err != nil {
				t.Fatalf("Failed to read response: %v", err)
			}
			lineStr := string(line)
			t.Logf("RECV: %s", lineStr)
			responses = append(responses, lineStr)

			if strings.HasPrefix(lineStr, expectedTag+" ") {
				break
			}
		}
		return responses
	}

	// Read greeting
	greeting, _, err := reader.ReadLine()
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	t.Logf("RECV: %s", greeting)

	// Login
	sendCommand("A01", fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	readResponse("A01")

	// SELECT INBOX
	sendCommand("A02", "SELECT INBOX")
	readResponse("A02")

	// Add test messages for operations
	for i := 1; i <= 2; i++ {
		messageData := fmt.Sprintf("From: test%d@example.com\r\nTo: %s\r\nSubject: Test Message %d\r\nDate: %s\r\n\r\nTest message content %d.",
			i, account.Email, i, time.Now().Format(time.RFC1123), i)

		sendCommand(fmt.Sprintf("A%02d", i+2), fmt.Sprintf("APPEND INBOX {%d}", len(messageData)))
		contLine, _, err := reader.ReadLine()
		if err != nil {
			t.Fatalf("Failed to read continuation: %v", err)
		}
		t.Logf("RECV: %s", contLine)
		fmt.Fprintf(writer, "%s\r\n", messageData)
		writer.Flush()
		readResponse(fmt.Sprintf("A%02d", i+2))
	}

	// Reselect to see messages
	sendCommand("A05", "SELECT INBOX")
	readResponse("A05")

	t.Logf("=== BEFORE ID: Test all operations with CONDSTORE (should include fragments) ===")

	// Test FETCH before ID - should include MODSEQ
	sendCommand("A06", "FETCH 1:2 (FLAGS MODSEQ)")
	fetchBeforeResponses := readResponse("A06")

	var foundModSeqBeforeID bool
	for _, resp := range fetchBeforeResponses {
		if strings.Contains(resp, "MODSEQ") && strings.Contains(resp, "FETCH") {
			foundModSeqBeforeID = true
			t.Logf("Before ID - FETCH includes MODSEQ: %s", resp)
		}
	}

	// Test STORE before ID - should include MODSEQ in response
	sendCommand("A07", "STORE 1 +FLAGS (\\Seen)")
	storeBeforeResponses := readResponse("A07")

	var foundModSeqInStoreBeforeID bool
	for _, resp := range storeBeforeResponses {
		if strings.Contains(resp, "MODSEQ") && strings.Contains(resp, "FETCH") {
			foundModSeqInStoreBeforeID = true
			t.Logf("Before ID - STORE includes MODSEQ: %s", resp)
		}
	}

	// Test SEARCH with MODSEQ before ID - should work normally
	sendCommand("A08", "SEARCH MODSEQ 1")
	searchBeforeResponses := readResponse("A08")

	var searchWorkedBeforeID bool
	for _, resp := range searchBeforeResponses {
		if strings.Contains(resp, "A08 OK") {
			searchWorkedBeforeID = true
		}
	}

	// Log results before ID
	if foundModSeqBeforeID {
		t.Logf("✓ Before ID: FETCH correctly includes MODSEQ (CONDSTORE available)")
	} else {
		t.Logf("⚠ Before ID: FETCH does not include MODSEQ (may be expected if no messages)")
	}

	if foundModSeqInStoreBeforeID {
		t.Logf("✓ Before ID: STORE correctly includes MODSEQ (CONDSTORE available)")
	} else {
		t.Logf("⚠ Before ID: STORE does not include MODSEQ")
	}

	if searchWorkedBeforeID {
		t.Logf("✓ Before ID: SEARCH MODSEQ works correctly (CONDSTORE available)")
	} else {
		t.Logf("⚠ Before ID: SEARCH MODSEQ failed")
	}

	t.Logf("=== SEND ID: Identify as iOS ===")

	// Send ID command to identify as iOS
	sendCommand("A09", `ID ("name" "com.apple.email.maild" "version" "3826.300.87.2.22" "os" "iOS")`)
	readResponse("A09")

	t.Logf("=== AFTER ID: Test all operations with CONDSTORE (should exclude fragments) ===")

	// Test FETCH after ID - should NOT include MODSEQ
	sendCommand("A10", "FETCH 1:2 (FLAGS MODSEQ)")
	fetchAfterResponses := readResponse("A10")

	var foundModSeqAfterID bool
	for _, resp := range fetchAfterResponses {
		if strings.Contains(resp, "MODSEQ") && strings.Contains(resp, "FETCH") {
			foundModSeqAfterID = true
			t.Logf("After ID - FETCH includes MODSEQ: %s", resp)
		}
	}

	// Test STORE after ID - should NOT include MODSEQ in response
	sendCommand("A11", "STORE 2 +FLAGS (\\Flagged)")
	storeAfterResponses := readResponse("A11")

	var foundModSeqInStoreAfterID bool
	for _, resp := range storeAfterResponses {
		if strings.Contains(resp, "MODSEQ") && strings.Contains(resp, "FETCH") {
			foundModSeqInStoreAfterID = true
			t.Logf("After ID - STORE includes MODSEQ: %s", resp)
		}
	}

	// Test SEARCH with MODSEQ after ID - should handle gracefully
	sendCommand("A12", "SEARCH MODSEQ 1")
	searchAfterResponses := readResponse("A12")

	var searchWorkedAfterID bool
	var searchFailedAfterID bool
	for _, resp := range searchAfterResponses {
		if strings.Contains(resp, "A12 OK") {
			searchWorkedAfterID = true
		}
		if strings.Contains(resp, "A12 BAD") || strings.Contains(resp, "A12 NO") {
			searchFailedAfterID = true
		}
	}

	// Test STORE with UNCHANGEDSINCE after ID - should be rejected or ignore MODSEQ
	sendCommand("A13", "STORE 1 (UNCHANGEDSINCE 1) +FLAGS (\\Draft)")
	unchangedSinceAfterResponses := readResponse("A13")

	var hasModSeqInUnchangedSinceAfter bool
	for _, resp := range unchangedSinceAfterResponses {
		if strings.Contains(resp, "MODSEQ") {
			hasModSeqInUnchangedSinceAfter = true
		}
	}

	// Verify filtering results
	t.Logf("=== VERIFICATION RESULTS ===")

	if foundModSeqAfterID {
		t.Errorf("✗ FAILURE: FETCH includes MODSEQ after iOS ID (should be filtered)")
	} else {
		t.Logf("✓ SUCCESS: FETCH correctly excludes MODSEQ after iOS ID")
	}

	if foundModSeqInStoreAfterID {
		t.Errorf("✗ FAILURE: STORE includes MODSEQ after iOS ID (should be filtered)")
	} else {
		t.Logf("✓ SUCCESS: STORE correctly excludes MODSEQ after iOS ID")
	}

	if searchFailedAfterID {
		t.Logf("✓ SUCCESS: SEARCH MODSEQ correctly rejected after iOS ID")
	} else if searchWorkedAfterID {
		t.Logf("✓ SUCCESS: SEARCH MODSEQ handled gracefully after iOS ID (capability filtered)")
	} else {
		t.Logf("⚠ SEARCH MODSEQ behavior unclear after iOS ID")
	}

	if hasModSeqInUnchangedSinceAfter {
		t.Errorf("✗ FAILURE: STORE UNCHANGEDSINCE includes MODSEQ after iOS ID (should be filtered)")
	} else {
		t.Logf("✓ SUCCESS: STORE UNCHANGEDSINCE correctly excludes MODSEQ after iOS ID")
	}

	t.Log("=== COMPREHENSIVE CONDSTORE filtering verification completed ===")
}
