//go:build integration

package imap_test

import (
	"fmt"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIMAP_SearchAllVsSelect tests the critical imapsync scenario:
// Verifies that SEARCH ALL returns the same count as SELECT reports.
// If these don't match, imapsync crashes with an error.
func TestIMAP_SearchAllVsSelect(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup server and account
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Connect as IMAP client
	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()

	// Login
	err = c.Login(account.Email, account.Password).Wait()
	require.NoError(t, err)

	// Select INBOX
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	// Create a specific number of messages
	const messageCount = 50
	t.Logf("Creating %d test messages", messageCount)

	for i := 1; i <= messageCount; i++ {
		messageContent := fmt.Sprintf(
			"From: test@example.com\r\n"+
				"To: dest@example.com\r\n"+
				"Subject: Test %d\r\n"+
				"Message-ID: <%d@test.com>\r\n"+
				"\r\n"+
				"Body\r\n",
			i, i,
		)

		// Use the correct APPEND API
		appendCmd := c.Append("INBOX", int64(len(messageContent)), nil)
		_, err := appendCmd.Write([]byte(messageContent))
		require.NoError(t, err)
		err = appendCmd.Close()
		require.NoError(t, err)
	}

	// Re-select to get fresh message count
	selectData, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	selectCount := selectData.NumMessages
	t.Logf("SELECT reports %d messages", selectCount)

	// SEARCH ALL
	searchCmd := c.Search(&imap.SearchCriteria{}, nil)
	searchData, err := searchCmd.Wait()
	require.NoError(t, err)

	searchCount := uint32(0)
	for _, seq := range searchData.AllSeqNums() {
		_ = seq
		searchCount++
	}
	t.Logf("SEARCH ALL found %d messages", searchCount)

	// This is the critical check that imapsync performs
	assert.Equal(t, selectCount, searchCount,
		"SEARCH ALL count must match SELECT count (imapsync compatibility)")

	// Log what imapsync would see
	if selectCount == searchCount {
		t.Log("✓ imapsync check passed: SELECT and SEARCH ALL have the same count")
		t.Logf("  Host2: folder [INBOX] has %d messages mentioned by SELECT", selectCount)
		t.Logf("  Host2: folder [INBOX] has %d messages found by SEARCH ALL", searchCount)
		t.Log("  Host2: folder [INBOX] has the same messages count by SELECT and SEARCH ALL")
	} else {
		t.Errorf("✗ imapsync would fail and crash with this error:")
		t.Errorf("  Host2: folder [INBOX] has %d messages mentioned by SELECT", selectCount)
		t.Errorf("  Host2: folder [INBOX] has %d messages found by SEARCH ALL", searchCount)
		t.Error("  Host2: Warning, folder [INBOX] has not the same count by SELECT and SEARCH ALL")
		t.Error("  At least one account can not SEARCH ALL. So acting like --noabletosearch")
		t.Error("  Can't use an undefined value as a HASH reference at /usr/bin/imapsync line 12674.")
	}
}

// TestIMAP_SearchAllLargeMailbox verifies SEARCH ALL works with many messages
func TestIMAP_SearchAllLargeMailbox(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large mailbox test in short mode")
	}

	common.SkipIfDatabaseUnavailable(t)

	// Create more messages to verify unlimited SEARCH ALL
	const messageCount = 200 // Enough to be meaningful

	// Setup server and account
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Connect as IMAP client
	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()

	// Login
	err = c.Login(account.Email, account.Password).Wait()
	require.NoError(t, err)

	// Select INBOX
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	t.Logf("Creating %d messages (this may take a moment)", messageCount)

	// Create messages
	for i := 1; i <= messageCount; i++ {
		messageContent := fmt.Sprintf(
			"From: bulk@example.com\r\n"+
				"Subject: Bulk Message %d\r\n"+
				"Message-ID: <%d.%d@bulk.test>\r\n"+
				"Date: %s\r\n"+
				"\r\n"+
				"This is message %d of %d\r\n",
			i, time.Now().Unix(), i,
			time.Now().Format(time.RFC1123Z),
			i, messageCount,
		)

		appendCmd := c.Append("INBOX", int64(len(messageContent)), nil)
		_, err := appendCmd.Write([]byte(messageContent))
		require.NoError(t, err)
		err = appendCmd.Close()
		require.NoError(t, err)

		// Log progress
		if i%50 == 0 {
			t.Logf("Created %d/%d messages", i, messageCount)
		}
	}

	// Re-select to get fresh count
	selectData, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	t.Logf("SELECT reports %d messages", selectData.NumMessages)
	assert.Equal(t, uint32(messageCount), selectData.NumMessages)

	// Measure SEARCH ALL performance
	start := time.Now()
	searchCmd := c.Search(&imap.SearchCriteria{}, nil)
	searchData, err := searchCmd.Wait()
	require.NoError(t, err)
	duration := time.Since(start)

	// Count results
	searchCount := 0
	for _, seq := range searchData.AllSeqNums() {
		_ = seq
		searchCount++
	}

	t.Logf("SEARCH ALL returned %d UIDs in %v", searchCount, duration)

	// Critical assertion: SEARCH ALL must return ALL messages
	assert.Equal(t, messageCount, searchCount,
		"SEARCH ALL must return all %d messages to maintain imapsync compatibility", messageCount)

	// Verify this matches SELECT
	assert.Equal(t, selectData.NumMessages, uint32(searchCount),
		"SEARCH ALL count must match SELECT count")

	// Log success for imapsync compatibility
	t.Logf("✓ Large mailbox test passed: SELECT=%d, SEARCH ALL=%d (took %v)",
		selectData.NumMessages, searchCount, duration)
}

// TestIMAP_SearchAllAfterExpunge verifies SEARCH ALL correctly excludes expunged messages
func TestIMAP_SearchAllAfterExpunge(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup server and account
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Connect as IMAP client
	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()

	// Login
	err = c.Login(account.Email, account.Password).Wait()
	require.NoError(t, err)

	// Select INBOX
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	// Create 10 messages
	for i := 1; i <= 10; i++ {
		messageContent := fmt.Sprintf(
			"From: test@example.com\r\n"+
				"Subject: Message %d\r\n"+
				"Message-ID: <%d@expunge.test>\r\n"+
				"\r\n"+
				"Body\r\n",
			i, i,
		)

		appendCmd := c.Append("INBOX", int64(len(messageContent)), nil)
		_, err := appendCmd.Write([]byte(messageContent))
		require.NoError(t, err)
		err = appendCmd.Close()
		require.NoError(t, err)
	}

	// Re-select to update message count
	selectData, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, uint32(10), selectData.NumMessages)

	// SEARCH ALL before expunge
	searchCmd := c.Search(&imap.SearchCriteria{}, nil)
	searchData, err := searchCmd.Wait()
	require.NoError(t, err)

	beforeCount := 0
	for _, seq := range searchData.AllSeqNums() {
		_ = seq
		beforeCount++
	}
	assert.Equal(t, 10, beforeCount, "Should find all 10 messages initially")

	// Mark some messages as deleted and expunge
	// Using sequence numbers to delete messages in positions 3, 4, and 5
	storeCmd := c.Store(
		imap.SeqSetNum(3, 5),
		&imap.StoreFlags{
			Op:    imap.StoreFlagsAdd,
			Flags: []imap.Flag{imap.FlagDeleted},
		},
		nil,
	)
	storeResults, err := storeCmd.Collect()
	require.NoError(t, err)

	// Count how many messages were actually marked for deletion
	deletedCount := len(storeResults)
	t.Logf("Marked %d messages for deletion", deletedCount)

	_, err = c.Expunge().Collect()
	require.NoError(t, err)

	// SEARCH ALL after expunge
	searchCmd = c.Search(&imap.SearchCriteria{}, nil)
	searchData, err = searchCmd.Wait()
	require.NoError(t, err)

	afterCount := 0
	for _, seq := range searchData.AllSeqNums() {
		_ = seq
		afterCount++
	}

	expectedAfterCount := beforeCount - deletedCount
	assert.Equal(t, expectedAfterCount, afterCount,
		"Should find %d messages after expunging %d", expectedAfterCount, deletedCount)

	// Re-select to verify SELECT also reports the same
	selectData, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, uint32(afterCount), selectData.NumMessages)
	assert.Equal(t, selectData.NumMessages, uint32(afterCount),
		"SEARCH ALL and SELECT should still match after expunge")
}
