//go:build integration

package imap_test

import (
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIMAP_MetadataServerAnnotations tests server-level metadata operations
func TestIMAP_MetadataServerAnnotations(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()

	err = c.Login(account.Email, account.Password).Wait()
	require.NoError(t, err)

	t.Run("SetAndGetServerMetadata", func(t *testing.T) {
		// Set server metadata (empty mailbox name = server metadata)
		comment := []byte("My server comment")
		admin := []byte("admin@example.com")

		entries := map[string]*[]byte{
			"/private/comment": &comment,
			"/shared/admin":    &admin,
		}

		setCmd := c.SetMetadata("", entries)
		err := setCmd.Wait()
		require.NoError(t, err, "Failed to set server metadata")

		// Get server metadata
		getCmd := c.GetMetadata("", []string{"/private/comment", "/shared/admin"}, nil)
		result, err := getCmd.Wait()
		require.NoError(t, err, "Failed to get server metadata")
		require.NotNil(t, result)

		assert.Equal(t, 2, len(result.Entries))
		assert.Equal(t, "My server comment", string(*result.Entries["/private/comment"]))
		assert.Equal(t, "admin@example.com", string(*result.Entries["/shared/admin"]))
	})

	t.Run("UpdateServerMetadata", func(t *testing.T) {
		// Set initial value
		initialValue := []byte("Initial comment")
		entries := map[string]*[]byte{
			"/private/comment": &initialValue,
		}

		err := c.SetMetadata("", entries).Wait()
		require.NoError(t, err)

		// Update value
		updatedValue := []byte("Updated comment")
		entries = map[string]*[]byte{
			"/private/comment": &updatedValue,
		}

		err = c.SetMetadata("", entries).Wait()
		require.NoError(t, err)

		// Verify updated value
		result, err := c.GetMetadata("", []string{"/private/comment"}, nil).Wait()
		require.NoError(t, err)

		assert.Equal(t, "Updated comment", string(*result.Entries["/private/comment"]))
	})

	t.Run("DeleteServerMetadata", func(t *testing.T) {
		// Set value
		value := []byte("To be deleted")
		entries := map[string]*[]byte{
			"/private/temp": &value,
		}

		err := c.SetMetadata("", entries).Wait()
		require.NoError(t, err)

		// Delete value (set to nil)
		entries = map[string]*[]byte{
			"/private/temp": nil,
		}

		err = c.SetMetadata("", entries).Wait()
		require.NoError(t, err)

		// Verify deleted (should return empty)
		result, err := c.GetMetadata("", []string{"/private/temp"}, nil).Wait()
		require.NoError(t, err)

		// Entry should not exist or be nil
		_, exists := result.Entries["/private/temp"]
		assert.False(t, exists, "Deleted entry should not exist")
	})
}

// TestIMAP_MetadataMailboxAnnotations tests mailbox-level metadata operations
func TestIMAP_MetadataMailboxAnnotations(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()

	err = c.Login(account.Email, account.Password).Wait()
	require.NoError(t, err)

	// Create test mailbox
	mailboxName := "TestMetadata"
	err = c.Create(mailboxName, nil).Wait()
	require.NoError(t, err)

	t.Run("SetAndGetMailboxMetadata", func(t *testing.T) {
		comment := []byte("Important mailbox")
		vendor := []byte("Vendor specific data")

		entries := map[string]*[]byte{
			"/private/comment": &comment,
			"/shared/vendor":   &vendor,
		}

		err := c.SetMetadata(mailboxName, entries).Wait()
		require.NoError(t, err)

		// Get mailbox metadata
		result, err := c.GetMetadata(mailboxName, []string{"/private/comment", "/shared/vendor"}, nil).Wait()
		require.NoError(t, err)

		assert.Equal(t, 2, len(result.Entries))
		assert.Equal(t, "Important mailbox", string(*result.Entries["/private/comment"]))
		assert.Equal(t, "Vendor specific data", string(*result.Entries["/shared/vendor"]))
		assert.Equal(t, mailboxName, result.Mailbox)
	})

	t.Run("MailboxMetadataIndependent", func(t *testing.T) {
		// Create another mailbox
		mailbox2 := "TestMetadata2"
		err := c.Create(mailbox2, nil).Wait()
		require.NoError(t, err)

		// Set different metadata on second mailbox
		value2 := []byte("Different comment")
		entries := map[string]*[]byte{
			"/private/comment": &value2,
		}

		err = c.SetMetadata(mailbox2, entries).Wait()
		require.NoError(t, err)

		// Verify first mailbox still has original metadata
		result1, err := c.GetMetadata(mailboxName, []string{"/private/comment"}, nil).Wait()
		require.NoError(t, err)
		assert.Equal(t, "Important mailbox", string(*result1.Entries["/private/comment"]))

		// Verify second mailbox has different metadata
		result2, err := c.GetMetadata(mailbox2, []string{"/private/comment"}, nil).Wait()
		require.NoError(t, err)
		assert.Equal(t, "Different comment", string(*result2.Entries["/private/comment"]))
	})
}

// TestIMAP_MetadataDepth tests DEPTH option in GETMETADATA
func TestIMAP_MetadataDepth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()

	err = c.Login(account.Email, account.Password).Wait()
	require.NoError(t, err)

	// Set up hierarchical metadata entries
	root := []byte("root value")
	child1 := []byte("child1 value")
	child2 := []byte("child2 value")
	grandchild := []byte("grandchild value")

	entries := map[string]*[]byte{
		"/private/test":            &root,
		"/private/test/child1":     &child1,
		"/private/test/child2":     &child2,
		"/private/test/child1/sub": &grandchild,
	}

	err = c.SetMetadata("", entries).Wait()
	require.NoError(t, err)

	t.Run("Depth0_ExactMatch", func(t *testing.T) {
		options := &imap.GetMetadataOptions{
			Depth: imap.GetMetadataDepthZero,
		}

		result, err := c.GetMetadata("", []string{"/private/test"}, options).Wait()
		require.NoError(t, err)

		// Should only get exact match
		assert.Equal(t, 1, len(result.Entries))
		_, hasRoot := result.Entries["/private/test"]
		assert.True(t, hasRoot)
	})

	t.Run("Depth1_ImmediateChildren", func(t *testing.T) {
		options := &imap.GetMetadataOptions{
			Depth: imap.GetMetadataDepthOne,
		}

		result, err := c.GetMetadata("", []string{"/private/test"}, options).Wait()
		require.NoError(t, err)

		// Should get root + immediate children (not grandchildren)
		assert.GreaterOrEqual(t, len(result.Entries), 3) // root + child1 + child2
		_, hasRoot := result.Entries["/private/test"]
		_, hasChild1 := result.Entries["/private/test/child1"]
		_, hasChild2 := result.Entries["/private/test/child2"]

		assert.True(t, hasRoot)
		assert.True(t, hasChild1)
		assert.True(t, hasChild2)
	})

	t.Run("DepthInfinity_AllDescendants", func(t *testing.T) {
		options := &imap.GetMetadataOptions{
			Depth: imap.GetMetadataDepthInfinity,
		}

		result, err := c.GetMetadata("", []string{"/private/test"}, options).Wait()
		require.NoError(t, err)

		// Should get all descendants
		assert.Equal(t, 4, len(result.Entries))
		_, hasRoot := result.Entries["/private/test"]
		_, hasChild1 := result.Entries["/private/test/child1"]
		_, hasChild2 := result.Entries["/private/test/child2"]
		_, hasGrandchild := result.Entries["/private/test/child1/sub"]

		assert.True(t, hasRoot)
		assert.True(t, hasChild1)
		assert.True(t, hasChild2)
		assert.True(t, hasGrandchild)
	})
}

// TestIMAP_MetadataMaxSize tests MAXSIZE option
func TestIMAP_MetadataMaxSize(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()

	err = c.Login(account.Email, account.Password).Wait()
	require.NoError(t, err)

	// Set entries with different sizes
	small := []byte("small")            // 5 bytes
	large := []byte("large data value") // 16 bytes

	entries := map[string]*[]byte{
		"/private/small": &small,
		"/private/large": &large,
	}

	err = c.SetMetadata("", entries).Wait()
	require.NoError(t, err)

	// Request with MAXSIZE that only allows small entry
	maxSize := uint32(10)
	options := &imap.GetMetadataOptions{
		MaxSize: &maxSize,
	}

	result, err := c.GetMetadata("", []string{"/private/small", "/private/large"}, options).Wait()
	require.NoError(t, err)

	// With MAXSIZE=10, should respect size limit
	// The query returns results ordered by entry_name
	// We should get entries that fit within the limit
	if len(result.Entries) > 0 {
		// Verify total size doesn't exceed limit
		totalSize := uint32(0)
		for _, v := range result.Entries {
			if v != nil {
				totalSize += uint32(len(*v))
			}
		}
		assert.LessOrEqual(t, totalSize, maxSize, "Total size should not exceed MAXSIZE")
	}
}

// TestIMAP_MetadataErrors tests error conditions
func TestIMAP_MetadataErrors(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()

	err = c.Login(account.Email, account.Password).Wait()
	require.NoError(t, err)

	t.Run("NonexistentMailbox", func(t *testing.T) {
		// Try to get metadata for non-existent mailbox
		_, err := c.GetMetadata("NonExistentMailbox", []string{"/private/comment"}, nil).Wait()
		assert.Error(t, err, "Should fail for non-existent mailbox")
	})

	t.Run("InvalidEntryName", func(t *testing.T) {
		// Try to set metadata with invalid entry name (not starting with /private/ or /shared/)
		invalidValue := []byte("value")
		entries := map[string]*[]byte{
			"/invalid/path": &invalidValue,
		}

		err := c.SetMetadata("", entries).Wait()
		assert.Error(t, err, "Should fail for invalid entry name")
	})

	t.Run("GetNonexistentEntry", func(t *testing.T) {
		// Get entry that doesn't exist
		result, err := c.GetMetadata("", []string{"/private/nonexistent"}, nil).Wait()
		require.NoError(t, err, "Should not error for non-existent entry")

		// Should return empty or entry not present
		_, exists := result.Entries["/private/nonexistent"]
		assert.False(t, exists, "Non-existent entry should not be in result")
	})
}

// TestIMAP_MetadataMultipleEntries tests operations with multiple entries
func TestIMAP_MetadataMultipleEntries(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()

	err = c.Login(account.Email, account.Password).Wait()
	require.NoError(t, err)

	// Set multiple entries at once
	entries := map[string]*[]byte{
		"/private/comment":  bytePtr([]byte("Comment 1")),
		"/private/keywords": bytePtr([]byte("important urgent")),
		"/shared/admin":     bytePtr([]byte("admin@example.com")),
		"/shared/vendor":    bytePtr([]byte("VendorX")),
	}

	err = c.SetMetadata("", entries).Wait()
	require.NoError(t, err)

	// Get all entries
	entryNames := []string{"/private/comment", "/private/keywords", "/shared/admin", "/shared/vendor"}
	result, err := c.GetMetadata("", entryNames, nil).Wait()
	require.NoError(t, err)

	// Verify all entries
	assert.Equal(t, 4, len(result.Entries))
	assert.Equal(t, "Comment 1", string(*result.Entries["/private/comment"]))
	assert.Equal(t, "important urgent", string(*result.Entries["/private/keywords"]))
	assert.Equal(t, "admin@example.com", string(*result.Entries["/shared/admin"]))
	assert.Equal(t, "VendorX", string(*result.Entries["/shared/vendor"]))
}

func bytePtr(b []byte) *[]byte {
	return &b
}
