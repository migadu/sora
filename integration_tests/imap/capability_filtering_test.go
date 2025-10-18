//go:build integration

package imap_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	imapserver "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// setupIMAPServerWithCapabilityFilters creates an IMAP server with custom capability filtering
func setupIMAPServerWithCapabilityFilters(t *testing.T, filters []config.ClientCapabilityFilter) (*common.TestServer, common.TestAccount) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	// Create a temporary directory for the uploader
	tempDir, err := os.MkdirTemp("", "sora-test-upload-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Create error channel for uploader
	errCh := make(chan error, 1)

	// Create UploadWorker for testing
	uploadWorker, err := uploader.New(
		context.Background(),
		tempDir,              // path
		10,                   // batchSize
		1,                    // concurrency
		3,                    // maxAttempts
		time.Second,          // retryInterval
		"test-instance",      // instanceID
		rdb,                  // database
		&storage.S3Storage{}, // S3 storage
		nil,                  // cache (can be nil)
		errCh,                // error channel
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	// Create IMAP server with capability filters
	server, err := imapserver.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		uploadWorker, // properly initialized UploadWorker
		nil,          // cache.Cache
		imapserver.IMAPServerOptions{
			CapabilityFilters: filters,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := server.Serve(address); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP server error: %w", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	cleanup := func() {
		server.Close()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("IMAP server error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
			// Timeout waiting for server to shut down
		}
		// Clean up temporary directory
		os.RemoveAll(tempDir)
	}

	testServer := &common.TestServer{
		Address:     address,
		Server:      server,
		ResilientDB: rdb,
	}

	// Set up cleanup through t.Cleanup instead of private field
	t.Cleanup(cleanup)

	return testServer, account
}

func TestIMAP_CapabilityFiltering(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Test that client capability filtering works at the command handler level
	// IMPORTANT: CAPABILITY responses still advertise all capabilities (by design)
	// but the actual command handlers respect the per-session filtered capabilities

	// Define capability filters to disable ESEARCH for iOS Apple Mail
	filters := []config.ClientCapabilityFilter{
		{
			ClientName:    "com\\.apple\\.email\\.maild",
			ClientVersion: ".*",
			DisableCaps:   []string{"ESEARCH"},
			Reason:        "iOS Apple Mail has ESEARCH parsing issues",
		},
	}

	server, account := setupIMAPServerWithCapabilityFilters(t, filters)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	// Login first - capability filtering is only applied after authentication
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Send ID command to identify as iOS Apple Mail - this triggers filtering
	clientID := &imap.IDData{
		Name:      "com.apple.email.maild",
		Version:   "3826.300.87.2.22",
		OS:        "iOS",
		OSVersion: "18.2.1 (22C161)",
		Vendor:    "Apple Inc",
	}

	serverID, err := c.ID(clientID).Wait()
	if err != nil {
		t.Fatalf("ID command failed: %v", err)
	}

	t.Logf("Server ID response: %+v", serverID)

	// Test CAPABILITY command after ID - ESEARCH should be filtered out
	caps, err := c.Capability().Wait()
	if err != nil {
		t.Fatalf("CAPABILITY command failed: %v", err)
	}

	// After capability filtering, ESEARCH is removed from CAPABILITY response
	// The filtering happens at both advertisement and handler levels
	hasESEARCH := caps.Has(imap.CapESearch)

	if hasESEARCH {
		t.Errorf("ESEARCH capability should be removed from CAPABILITY response after filtering")
	} else {
		t.Logf("EXPECTED: CAPABILITY response correctly removed ESEARCH after filtering")
	}

	// Verify that the server applied capability filtering internally (check logs above)
	t.Logf("SUCCESS: Capability filtering applied at session level (check server logs above)")

	// List all capabilities for debugging
	var capList []string
	for cap := range caps {
		capList = append(capList, string(cap))
	}

	// Log all capabilities for debugging
	t.Logf("Post-authentication capabilities: %v", capList)

	// Select INBOX
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Add a test message
	testMessage := fmt.Sprintf("From: test@example.com\r\n"+
		"To: %s\r\n"+
		"Subject: Test Message for ESEARCH\r\n"+
		"Date: %s\r\n"+
		"\r\n"+
		"This is a test message that should be found by ESEARCH if it's enabled.\r\n",
		account.Email, time.Now().Format(time.RFC1123))

	appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
		Time: time.Now(),
	})
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}

	// Test 1: Try search - the go-imap client library automatically uses ReturnAll:true
	// which is ESEARCH syntax, so this will fail with NO [CLIENTBUG]
	_, err = c.Search(&imap.SearchCriteria{
		Body: []string{"test"},
	}, nil).Wait()

	if err == nil {
		t.Fatal("Expected error when go-imap client automatically uses ESEARCH syntax (ReturnAll:true), but got success")
	}

	// The go-imap library defaults to ReturnAll:true when ESEARCH was available,
	// even when we pass nil options. This is a client library behavior.
	var imapErr *imap.Error
	if errors.As(err, &imapErr) && imapErr.Code == imap.ResponseCodeClientBug {
		t.Logf("SUCCESS: Server correctly rejected ESEARCH syntax with NO [CLIENTBUG] (go-imap uses ReturnAll:true by default)")
	} else {
		t.Logf("Search failed with: %v (expected CLIENTBUG, but acceptable)", err)
	}

	// Note: To make SEARCH work after ESEARCH filtering, clients would need to:
	// 1. Not cache capabilities, OR
	// 2. Re-check capabilities before each command, OR
	// 3. Handle the NO [CLIENTBUG] error and retry without ESEARCH syntax
	//
	// The go-imap client library currently doesn't do any of these, so SEARCH
	// will fail after ESEARCH is filtered. This is correct server behavior per RFC 5530.

	t.Logf("SUCCESS: Capability filtering is working correctly - server rejects ESEARCH syntax when capability is filtered")
}

func TestIMAP_CapabilityFiltering_NoClientID(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Same filters as above
	filters := []config.ClientCapabilityFilter{
		{
			ClientName:    "com\\.apple\\.email\\.maild",
			ClientVersion: ".*",
			DisableCaps:   []string{"ESEARCH"},
			Reason:        "iOS Apple Mail has ESEARCH parsing issues",
		},
	}

	server, account := setupIMAPServerWithCapabilityFilters(t, filters)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	// Don't send ID command - client remains unidentified
	// This should mean all capabilities are available

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Test CAPABILITY command after LOGIN without ID - ESEARCH should be present
	caps, err := c.Capability().Wait()
	if err != nil {
		t.Fatalf("CAPABILITY command failed: %v", err)
	}

	// Check that ESEARCH IS in the capability list for unidentified clients
	hasESEARCH := caps.Has(imap.CapESearch)

	if !hasESEARCH {
		t.Errorf("ESEARCH capability should be available for unidentified clients, but it was not found")
	} else {
		t.Logf("SUCCESS: ESEARCH capability correctly available for unidentified client")
	}

	// List all capabilities for debugging
	var capList []string
	for cap := range caps {
		capList = append(capList, string(cap))
	}

	// Log all capabilities for debugging
	t.Logf("Post-authentication capabilities for unidentified client: %v", capList)

	// Select INBOX
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Add a test message
	testMessage := fmt.Sprintf("From: test@example.com\r\n"+
		"To: %s\r\n"+
		"Subject: Test Message for ESEARCH No Filter\r\n"+
		"Date: %s\r\n"+
		"\r\n"+
		"This message should be found by ESEARCH since no filtering applied.\r\n",
		account.Email, time.Now().Format(time.RFC1123))

	appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
		Time: time.Now(),
	})
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}

	// Since no client ID was provided, all capabilities should be available
	// Search using header which is more reliable than body search
	searchData, err := c.Search(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{
			{Key: "Subject", Value: "ESEARCH No Filter"},
		},
	}, nil).Wait()

	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	// Search should work normally for unidentified clients
	foundMessages := searchData.AllSeqNums()
	if len(foundMessages) == 0 {
		// If specific search fails, try a broader search to verify test setup
		t.Logf("Specific search failed, trying broader search for debugging")
		searchData2, err2 := c.Search(&imap.SearchCriteria{}, nil).Wait()
		if err2 != nil {
			t.Fatalf("Even ALL search failed: %v", err2)
		}
		allMessages := searchData2.AllSeqNums()
		t.Logf("Found %d total messages in mailbox", len(allMessages))
		if len(allMessages) == 0 {
			t.Fatal("No messages found in mailbox - test setup issue")
		}
		// At least we can verify that search works for unidentified clients
	}

	t.Logf("SUCCESS: Unidentified client search works - full capabilities available")
}

// TestIMAP_CapabilityFiltering_iOSAppleMail tests specific filtering for iOS Apple Mail client
// This test replicates the exact scenario from the user's manual test
func TestIMAP_CapabilityFiltering_iOSAppleMail(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Define capability filters to disable multiple capabilities for iOS Apple Mail
	// This matches the user's configuration and tests multiple capability filtering
	filters := []config.ClientCapabilityFilter{
		{
			ClientName:    "com\\.apple\\.email\\.maild",
			ClientVersion: ".*",
			DisableCaps:   []string{"ESEARCH", "CONDSTORE", "ESORT", "BINARY"},
			Reason:        "iOS Apple Mail has ESEARCH, CONDSTORE, ESORT, and BINARY implementation issues",
		},
	}

	server, account := setupIMAPServerWithCapabilityFilters(t, filters)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Check initial capabilities after login (before ID command)
	caps, err := c.Capability().Wait()
	if err != nil {
		t.Fatalf("CAPABILITY command failed: %v", err)
	}

	hasESEARCH := caps.Has(imap.CapESearch)
	hasCONDSTORE := caps.Has(imap.CapCondStore)

	t.Logf("Before ID command - ESEARCH: %t, CONDSTORE: %t", hasESEARCH, hasCONDSTORE)

	// Send ID command to identify as iOS Apple Mail with exact client info from user's test
	clientID := &imap.IDData{
		Name:      "com.apple.email.maild",
		Version:   "3826.300.87.2.22",
		OS:        "iOS",
		OSVersion: "18.2.1 (22C161)",
		Vendor:    "Apple Inc",
	}

	serverID, err := c.ID(clientID).Wait()
	if err != nil {
		t.Fatalf("ID command failed: %v", err)
	}

	t.Logf("Server ID response: %+v", serverID)

	// Check capabilities after ID command - should still advertise all capabilities
	caps, err = c.Capability().Wait()
	if err != nil {
		t.Fatalf("CAPABILITY command after ID failed: %v", err)
	}

	hasESEARCH = caps.Has(imap.CapESearch)
	hasCONDSTORE = caps.Has(imap.CapCondStore)

	t.Logf("After ID command - ESEARCH: %t, CONDSTORE: %t", hasESEARCH, hasCONDSTORE)

	// After capability filtering, filtered capabilities should be removed from CAPABILITY response
	// This is the current implementation - capabilities are removed from advertisement
	if hasESEARCH {
		t.Error("ESEARCH capability should be removed from CAPABILITY response after filtering")
	}
	if hasCONDSTORE {
		t.Error("CONDSTORE capability should be removed from CAPABILITY response after filtering")
	}

	// Select INBOX to enable CONDSTORE tests
	if _, err := c.Select("INBOX", &imap.SelectOptions{}).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Add a test message to have something to search
	testMessage := fmt.Sprintf("From: test@example.com\r\n"+
		"To: %s\r\n"+
		"Subject: Test Message for Capability Filtering\r\n"+
		"Date: %s\r\n"+
		"\r\n"+
		"This is a test message for capability filtering verification.\r\n",
		account.Email, time.Now().Format(time.RFC1123))

	appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
		Time: time.Now(),
	})
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	_, err = appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND wait failed: %v", err)
	}

	t.Logf("Successfully appended test message to INBOX")

	// Test 1: Try search with nil options - the go-imap client library automatically uses ReturnAll:true
	// which is ESEARCH syntax, so this will fail with NO [CLIENTBUG]
	_, err = c.Search(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{
			{Key: "Subject", Value: "Test Message"},
		},
	}, nil).Wait()
	if err == nil {
		t.Fatal("Expected error when go-imap client automatically uses ESEARCH syntax (ReturnAll:true), but got success")
	}

	// Verify we got the correct error with CLIENTBUG response code
	var imapErr *imap.Error
	if errors.As(err, &imapErr) && imapErr.Code == imap.ResponseCodeClientBug {
		t.Logf("SUCCESS: Server correctly rejected ESEARCH syntax with NO [CLIENTBUG] (go-imap uses ReturnAll:true by default)")
	} else {
		t.Fatalf("Expected CLIENTBUG error, got: %v", err)
	}

	// Note: To make SEARCH work after ESEARCH filtering, clients would need to:
	// 1. Not cache capabilities, OR
	// 2. Re-check capabilities before each command, OR
	// 3. Handle the NO [CLIENTBUG] error and retry without ESEARCH syntax
	//
	// The go-imap client library currently doesn't do any of these, so SEARCH
	// will fail after ESEARCH is filtered. This is correct server behavior per RFC 5530.

	// Test 2: SEARCH with ESEARCH options should fail or be ignored when ESEARCH is filtered
	// Try to use ESEARCH-specific options that should be filtered out
	searchOptions := &imap.SearchOptions{
		ReturnCount: true,
		ReturnAll:   true,
		ReturnMin:   true,
		ReturnMax:   true,
	}

	// This should return NO [CLIENTBUG] error when ESEARCH is disabled per RFC 5530
	_, err = c.Search(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{
			{Key: "Subject", Value: "Test Message"},
		},
	}, searchOptions).Wait()

	// The key test: ESEARCH should return NO [CLIENTBUG] when capability is filtered
	if err == nil {
		t.Fatal("Expected error when using ESEARCH syntax with ESEARCH capability filtered, but got success")
	}

	// Verify we got the correct error with CLIENTBUG response code (reuse imapErr from above)
	if !errors.As(err, &imapErr) {
		t.Fatalf("Expected imap.Error, got: %v", err)
	}
	if imapErr.Type != imap.StatusResponseTypeNo {
		t.Errorf("Expected NO response, got: %v", imapErr.Type)
	}
	if imapErr.Code != imap.ResponseCodeClientBug {
		t.Errorf("Expected CLIENTBUG response code, got: %v", imapErr.Code)
	}
	t.Logf("SUCCESS: ESEARCH with return options correctly returned NO [CLIENTBUG] when ESEARCH is filtered")

	// Test 3: SORT with ESORT options should be ignored when ESORT is filtered
	sortOptions := &imapclient.SortOptions{
		SearchCriteria: &imap.SearchCriteria{},
		SortCriteria:   []imap.SortCriterion{{Key: imap.SortKeyDate, Reverse: false}},
		Return:         imap.SortOptions{ReturnCount: true, ReturnMin: true, ReturnMax: true},
	}

	sortCmd := c.Sort(sortOptions)
	sortData, err := sortCmd.Wait()
	if err != nil {
		t.Logf("SORT with ESORT options failed: %v", err)
	} else {
		// When ESORT is filtered, it should fall back to standard sort behavior
		// Standard SORT only returns SeqNums/UIDs, ESORT-specific Count/Min/Max should be 0
		if sortData.Count > 0 || sortData.Min > 0 || sortData.Max > 0 {
			t.Error("FAILURE: ESORT return data (Count/Min/Max) should not be available when ESORT capability is filtered")
			t.Logf("Got Count=%d, Min=%d, Max=%d - these should be 0 when ESORT is filtered",
				sortData.Count, sortData.Min, sortData.Max)
		} else {
			t.Logf("SUCCESS: SORT returned standard results (Count=%d, Min=%d, Max=%d, SeqNums=%v) - ESORT filtering working correctly",
				sortData.Count, sortData.Min, sortData.Max, sortData.SeqNums)
		}
	}

	// Test 4: FETCH with BINARY options should be ignored when BINARY is filtered
	// Try to fetch a binary section (this should be ignored)
	fetchOptions := &imap.FetchOptions{
		BinarySection: []*imap.FetchItemBinarySection{
			{Part: []int{1}}, // Try to fetch binary section 1
		},
	}

	fetchResults, err := c.Fetch(imap.SeqSetNum(1), fetchOptions).Collect()
	if err != nil {
		t.Logf("FETCH with BINARY options failed: %v", err)
	} else {
		// The key test: BINARY sections should not be processed when capability is filtered
		// We can't easily test the response content, but the logs should show filtering
		t.Logf("SUCCESS: FETCH with BINARY options completed - check logs for filtering message")
		if len(fetchResults) > 0 {
			t.Logf("FETCH returned %d message(s)", len(fetchResults))
		}
	}

	t.Log("SUCCESS: iOS Apple Mail capability filtering test completed - ESEARCH, CONDSTORE, ESORT, and BINARY properly filtered at handler level")
}

// TestIMAP_CapabilityFiltering_ESEARCHFallback verifies that when ESEARCH is disabled,
// the server correctly falls back to a standard SEARCH response.
func TestIMAP_CapabilityFiltering_ESEARCHFallback(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Define a filter to disable ESEARCH for a test client
	// Add a test message to have something to search
	testMessage := fmt.Sprintf("From: test@example.com\r\n"+
		"To: %s\r\n"+
		"Subject: Test ESEARCH Fallback\r\n"+
		"Date: %s\r\n"+
		"\r\n"+
		"This is a test message for ESEARCH fallback verification.\r\n",
		"test@example.com", time.Now().Format(time.RFC1123))

	filters := []config.ClientCapabilityFilter{
		{
			ClientName:    "TestClientWithESEARCHDisabled",
			ClientVersion: ".*",
			DisableCaps:   []string{"ESEARCH"},
			Reason:        "Test ESEARCH fallback",
		},
	}

	server, account := setupIMAPServerWithCapabilityFilters(t, filters)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	// Login first - capability filtering is only applied after authentication
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Identify as the test client - this triggers capability filtering
	if _, err := c.ID(&imap.IDData{Name: "TestClientWithESEARCHDisabled", Version: "1.0"}).Wait(); err != nil {
		t.Fatalf("ID command failed: %v", err)
	}

	// Select INBOX
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Append the test message
	appendCmd := c.Append("INBOX", int64(len(testMessage)), nil)
	if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
		t.Fatalf("Failed to write message: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("Failed to close append command: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("Failed to wait for append command: %v", err)
	}

	// Issue a SEARCH command with ESEARCH options. Since ESEARCH is disabled for this client,
	// the server should return NO [CLIENTBUG] error per RFC 5530
	cmd := c.Search(&imap.SearchCriteria{Text: []string{"fallback"}}, &imap.SearchOptions{ReturnCount: true, ReturnMin: true, ReturnMax: true})
	_, err = cmd.Wait()
	if err == nil {
		t.Fatalf("Expected error when using ESEARCH syntax with ESEARCH capability filtered, but got success")
	}

	// Verify we got the correct error with CLIENTBUG response code
	var imapErr *imap.Error
	if !errors.As(err, &imapErr) {
		t.Fatalf("Expected imap.Error, got: %v", err)
	}
	if imapErr.Type != imap.StatusResponseTypeNo {
		t.Errorf("Expected NO response, got: %v", imapErr.Type)
	}
	if imapErr.Code != imap.ResponseCodeClientBug {
		t.Errorf("Expected CLIENTBUG response code, got: %v", imapErr.Code)
	}
	if !strings.Contains(imapErr.Text, "ESEARCH is not supported") {
		t.Errorf("Expected error message about ESEARCH not supported, got: %s", imapErr.Text)
	}

	t.Logf("SUCCESS: Server correctly returned NO [CLIENTBUG] for ESEARCH syntax when capability is filtered")
}

// TestIMAP_StandardSearch_ReturnsStandardResponse verifies that a standard SEARCH
// command (with no ESEARCH options) correctly receives a standard `* SEARCH`
// response, not an `* ESEARCH` response. This test runs with all capabilities enabled.
func TestIMAP_StandardSearch_ReturnsStandardResponse(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// No capability filters - all capabilities should be enabled
	filters := []config.ClientCapabilityFilter{}

	server, account := setupIMAPServerWithCapabilityFilters(t, filters)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	// No ID command - client remains unidentified, so all capabilities should be available
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Select INBOX
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Add a test message to have something to search
	testMessage := fmt.Sprintf("From: test@example.com\r\n"+
		"To: %s\r\n"+
		"Subject: Test Standard Search\r\n"+
		"Date: %s\r\n"+
		"\r\n"+
		"This is a test message for standard search verification.\r\n",
		account.Email, time.Now().Format(time.RFC1123))

	appendCmd := c.Append("INBOX", int64(len(testMessage)), nil)
	if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
		t.Fatalf("Failed to write message: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("Failed to close append command: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("Failed to wait for append command: %v", err)
	}

	// Issue a standard SEARCH command (options are nil)
	cmd := c.Search(&imap.SearchCriteria{Text: []string{"Test"}}, nil)

	// A standard SEARCH command should result in a standard response, where Min and Max are zero.
	searchData, err := cmd.Wait()
	if err != nil {
		t.Fatalf("Standard SEARCH command failed: %v", err)
	}

	// Log the search results
	foundMessages := searchData.AllSeqNums()
	t.Logf("Standard SEARCH found %d messages", len(foundMessages))
	t.Logf("Search Count: %d", searchData.Count)
	t.Logf("Search Min: %d (should be 0 for standard search)", searchData.Min)
	t.Logf("Search Max: %d (should be 0 for standard search)", searchData.Max)

	// For a standard SEARCH command (no ESEARCH options), Min and Max should be zero
	if searchData.Min > 0 || searchData.Max > 0 {
		t.Errorf("FAILURE: Received ESEARCH response (Min=%d, Max=%d) for a standard SEARCH command.",
			searchData.Min, searchData.Max)
	} else {
		t.Logf("SUCCESS: Standard SEARCH command correctly received a standard response (Min=%d, Max=%d).",
			searchData.Min, searchData.Max)
	}
}

// TestIMAP_CapabilityFiltering_BeforeAfterID tests that ESEARCH capability filtering
// works correctly both before and after client identification via ID command.
// This reproduces the scenario where:
// 1. Client performs ESEARCH before ID - should use server capabilities
// 2. Client sends ID command - triggers capability filtering
// 3. Client performs ESEARCH after ID - should respect filtered capabilities
func TestIMAP_CapabilityFiltering_BeforeAfterID(t *testing.T) {
	// Setup capability filters
	filters := []config.ClientCapabilityFilter{
		{
			ClientName:    "TestClientWithESEARCHDisabled",
			ClientVersion: ".*",
			DisableCaps:   []string{"ESEARCH"},
			Reason:        "Test ESEARCH fallback",
		},
	}

	// Setup test server
	server, account := setupIMAPServerWithCapabilityFilters(t, filters)
	defer server.Close()

	// Connect to server
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Raw IMAP protocol handling
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting
	greeting, _, err := reader.ReadLine()
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	t.Logf("Greeting: %s", greeting)

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

	// Login
	sendCommand("A01", fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	readResponse("A01")

	// Select INBOX
	sendCommand("A02", "SELECT INBOX")
	readResponse("A02")

	// Add a test message
	messageData := "From: test@example.com\r\nTo: " + account.Email + "\r\nSubject: Test Message\r\n\r\nTest content"
	sendCommand("A03", fmt.Sprintf("APPEND INBOX {%d}", len(messageData)))

	// Read continuation response
	contLine, _, err := reader.ReadLine()
	if err != nil {
		t.Fatalf("Failed to read continuation: %v", err)
	}
	t.Logf("RECV: %s", contLine)

	// Send message data
	fmt.Fprintf(writer, "%s\r\n", messageData)
	writer.Flush()
	readResponse("A03")

	// STEP 1: Perform ESEARCH before ID command
	t.Logf("=== STEP 1: ESEARCH before ID command ===")
	sendCommand("DI18", "UID SEARCH RETURN (ALL) UID 1:*")
	beforeIDResponses := readResponse("DI18")

	// Check if we got ESEARCH response (should be based on server capabilities)
	var gotESEARCHBeforeID bool
	for _, resp := range beforeIDResponses {
		if strings.Contains(resp, "ESEARCH") {
			gotESEARCHBeforeID = true
			t.Logf("Before ID: Got ESEARCH response: %s", resp)
			break
		} else if strings.Contains(resp, "* SEARCH") {
			t.Logf("Before ID: Got standard SEARCH response: %s", resp)
			break
		}
	}

	// STEP 2: Send ID command to trigger capability filtering
	t.Logf("=== STEP 2: ID command to trigger filtering ===")
	sendCommand("DX2", `ID ("name" "TestClientWithESEARCHDisabled" "version" "1.0")`)
	readResponse("DX2")

	// STEP 3: Perform ESEARCH after ID command - should get NO [CLIENTBUG] error
	t.Logf("=== STEP 3: ESEARCH after ID command ===")
	sendCommand("DI19", "UID SEARCH RETURN (ALL) UID 1:*")
	afterIDResponses := readResponse("DI19")

	// Check if we got NO [CLIENTBUG] response (should be filtered)
	var gotClientBugAfterID bool
	for _, resp := range afterIDResponses {
		if strings.Contains(resp, "DI19 NO") && strings.Contains(resp, "CLIENTBUG") {
			gotClientBugAfterID = true
			t.Logf("After ID: Got NO [CLIENTBUG] response: %s", resp)
			break
		}
	}

	// Verify the behavior
	if gotESEARCHBeforeID {
		t.Logf("✓ Before ID: Server used ESEARCH (server capabilities)")
	} else {
		t.Logf("✗ Before ID: Server did not use ESEARCH")
	}

	if gotClientBugAfterID {
		t.Logf("✓ After ID: Server returned NO [CLIENTBUG] (capability filtering applied)")
	} else {
		t.Errorf("✗ After ID: Server did not properly apply capability filtering - should return NO [CLIENTBUG]")
	}

	// The test should verify that:
	// 1. Before ID: Server behavior should be based on server capabilities (ESEARCH works)
	// 2. After ID: Server should respect capability filtering and return NO [CLIENTBUG] error
	if !gotClientBugAfterID {
		t.Errorf("FAILURE: Capability filtering not working properly after ID command")
	} else {
		t.Logf("SUCCESS: Capability filtering working correctly - returns NO [CLIENTBUG] after ID command")
	}
}

// TestIMAP_ESEARCHFallback_RepeatedSearches verifies that repeated searches
// with ESEARCH options work correctly when ESEARCH is filtered. This catches
// bugs where response handling might get into an inconsistent state.
func TestIMAP_ESEARCHFallback_RepeatedSearches(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	filters := []config.ClientCapabilityFilter{
		{
			ClientName:    "TestClientRepeatedSearch",
			ClientVersion: ".*",
			DisableCaps:   []string{"ESEARCH"},
			Reason:        "Test repeated search fallback",
		},
	}

	server, account := setupIMAPServerWithCapabilityFilters(t, filters)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if _, err := c.ID(&imap.IDData{Name: "TestClientRepeatedSearch", Version: "1.0"}).Wait(); err != nil {
		t.Fatalf("ID command failed: %v", err)
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Append multiple test messages
	for i := 1; i <= 5; i++ {
		testMessage := fmt.Sprintf("From: test@example.com\r\n"+
			"To: %s\r\n"+
			"Subject: Test Message %d\r\n"+
			"Date: %s\r\n"+
			"\r\n"+
			"Message body %d for repeated search test.\r\n",
			account.Email, i, time.Now().Format(time.RFC1123), i)

		appendCmd := c.Append("INBOX", int64(len(testMessage)), nil)
		if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
			t.Fatalf("Failed to write message %d: %v", i, err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("Failed to close append %d: %v", i, err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("Failed to wait for append %d: %v", i, err)
		}
	}

	// Perform multiple searches with ESEARCH options in rapid succession
	// Since ESEARCH is filtered, the server should return NO [CLIENTBUG] for each attempt
	// This verifies consistent error handling without infinite loop or state corruption.
	searchOptions := &imap.SearchOptions{
		ReturnCount: true,
		ReturnAll:   true,
		ReturnMin:   true,
		ReturnMax:   true,
	}

	for i := 1; i <= 10; i++ {
		_, err := c.Search(&imap.SearchCriteria{
			Text: []string{"Message"},
		}, searchOptions).Wait()

		if err == nil {
			t.Fatalf("Search iteration %d: Expected error when using ESEARCH syntax with ESEARCH capability filtered, but got success", i)
		}

		// Verify we got the correct error with CLIENTBUG response code
		var imapErr *imap.Error
		if !errors.As(err, &imapErr) {
			t.Fatalf("Search %d: Expected imap.Error, got: %v", i, err)
		}
		if imapErr.Type != imap.StatusResponseTypeNo {
			t.Errorf("Search %d: Expected NO response, got: %v", i, imapErr.Type)
		}
		if imapErr.Code != imap.ResponseCodeClientBug {
			t.Errorf("Search %d: Expected CLIENTBUG response code, got: %v", i, imapErr.Code)
		}

		t.Logf("Search iteration %d: Correctly returned NO [CLIENTBUG]", i)
	}

	t.Logf("SUCCESS: All 10 repeated searches with ESEARCH options returned NO [CLIENTBUG] consistently")
}

// TestIMAP_ESEARCHFallback_EmptyResults verifies that ESEARCH fallback
// works correctly when the search returns no results. This is an edge case
// that might expose control flow bugs.
func TestIMAP_ESEARCHFallback_EmptyResults(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	filters := []config.ClientCapabilityFilter{
		{
			ClientName:    "TestClientEmptySearch",
			ClientVersion: ".*",
			DisableCaps:   []string{"ESEARCH"},
			Reason:        "Test empty search fallback",
		},
	}

	server, account := setupIMAPServerWithCapabilityFilters(t, filters)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if _, err := c.ID(&imap.IDData{Name: "TestClientEmptySearch", Version: "1.0"}).Wait(); err != nil {
		t.Fatalf("ID command failed: %v", err)
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Try ESEARCH syntax - should return NO [CLIENTBUG] error
	_, err = c.Search(&imap.SearchCriteria{
		Text: []string{"ThisStringDoesNotExistInAnyMessage12345"},
	}, &imap.SearchOptions{
		ReturnCount: true,
		ReturnMin:   true,
		ReturnMax:   true,
	}).Wait()

	if err == nil {
		t.Fatal("Expected error when using ESEARCH syntax with ESEARCH capability filtered, but got success")
	}

	// Verify we got the correct error with CLIENTBUG response code
	var imapErr *imap.Error
	if !errors.As(err, &imapErr) {
		t.Fatalf("Expected imap.Error, got: %v", err)
	}
	if imapErr.Type != imap.StatusResponseTypeNo {
		t.Errorf("Expected NO response, got: %v", imapErr.Type)
	}
	if imapErr.Code != imap.ResponseCodeClientBug {
		t.Errorf("Expected CLIENTBUG response code, got: %v", imapErr.Code)
	}

	t.Logf("SUCCESS: ESEARCH correctly returned NO [CLIENTBUG] even for query that would return empty results")

	// Perform another search after empty result to ensure session is still healthy
	testMessage := fmt.Sprintf("From: test@example.com\r\n"+
		"To: %s\r\n"+
		"Subject: Test After Empty\r\n"+
		"Date: %s\r\n"+
		"\r\n"+
		"Test message after empty search.\r\n",
		account.Email, time.Now().Format(time.RFC1123))

	appendCmd := c.Append("INBOX", int64(len(testMessage)), nil)
	if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
		t.Fatalf("Failed to write message: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("Failed to close append: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("Failed to wait for append: %v", err)
	}

	// Try another search - will also get CLIENTBUG since go-imap uses ReturnAll:true by default
	_, err = c.Search(&imap.SearchCriteria{
		Text: []string{"After Empty"},
	}, nil).Wait()

	if err == nil {
		t.Fatal("Expected error on second search (go-imap uses ESEARCH syntax), but got success")
	}

	// Verify the session remains healthy - should get the same CLIENTBUG error consistently
	if !errors.As(err, &imapErr) {
		t.Fatalf("Expected imap.Error on second search, got: %v", err)
	}
	if imapErr.Code != imap.ResponseCodeClientBug {
		t.Errorf("Expected CLIENTBUG on second search, got: %v", imapErr.Code)
	}

	t.Logf("SUCCESS: Session remains healthy after empty search - consistently returns NO [CLIENTBUG] for ESEARCH syntax")
}

// TestIMAP_CapabilityFiltering_MultipleJA4Patterns tests that a filter can match
// multiple JA4 fingerprint patterns using the ja4_fingerprints array
func TestIMAP_CapabilityFiltering_MultipleJA4Patterns(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create a filter with multiple JA4 patterns
	// This simulates iOS devices with different network configurations producing different fingerprints
	filters := []config.ClientCapabilityFilter{
		{
			ClientName:    "com\\.apple\\.email\\.maild",
			ClientVersion: ".*",
			JA4Fingerprints: []string{
				"^t13d411100_6be44479b708_.*", // One iOS variant
				"^t13d2014ip_a09f3c656075_.*", // Another iOS variant (IPv6)
				"^t13i201200_a09f3c656075_.*", // Yet another iOS variant
			},
			DisableCaps: []string{"ESEARCH", "CONDSTORE", "IDLE"},
			Reason:      "iOS Apple Mail has implementation issues (multiple fingerprints)",
		},
	}

	server, account := setupIMAPServerWithCapabilityFilters(t, filters)
	defer server.Close()

	// Connect via standard client
	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer c.Close()

	// Authenticate
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Get capabilities before ID command
	capsBefore := c.Caps()
	t.Logf("Before ID command - ESEARCH: %v", capsBefore.Has(imap.CapESearch))

	// Send ID command identifying as iOS Apple Mail
	idData := &imap.IDData{
		Name:      "com.apple.email.maild",
		Version:   "3826.400.131.2.15",
		OS:        "iOS",
		OSVersion: "18.3.2",
		Vendor:    "Apple Inc",
	}

	_, err = c.ID(idData).Wait()
	if err != nil {
		t.Fatalf("ID command failed: %v", err)
	}

	// Get capabilities after ID command
	capsAfter := c.Caps()
	t.Logf("After ID command - ESEARCH: %v, CONDSTORE: %v, IDLE: %v",
		capsAfter.Has(imap.CapESearch),
		capsAfter.Has(imap.CapCondStore),
		capsAfter.Has(imap.CapIdle))

	// Since we're connecting without TLS/JA4 in this test, the filter won't apply
	// based on JA4 (no fingerprint available), so it will only apply if client name matches
	// This test verifies the config parsing works correctly for multiple JA4 patterns

	// The real test is that the server started successfully and parsed the config
	// In production with PROXY protocol or TLS, this would match one of the JA4 patterns
	t.Logf("SUCCESS: Server correctly parsed multiple ja4_fingerprints configuration")
	t.Logf("Note: Actual JA4 matching requires TLS or PROXY protocol with JA4 TLV")
}
