package db

import (
	"context"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMetadataSetAndGet tests basic set and get operations
func TestMetadataSetAndGet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	db := setupTestDatabase(t)
	ctx := context.Background()

	// Create test account
	accountID := createTestAccount(t, db, "test-setget@example.com", "password")

	// Test server metadata (mailbox_id = nil)
	t.Run("ServerMetadata", func(t *testing.T) {
		entries := map[string]*[]byte{
			"/private/comment": bytePtr([]byte("My server comment")),
			"/shared/admin":    bytePtr([]byte("Admin contact")),
		}

		// Set metadata
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)

		err = db.SetMetadata(ctx, tx, accountID, nil, entries, nil)
		require.NoError(t, err)

		err = tx.Commit(ctx)
		require.NoError(t, err)

		// Get metadata
		tx, err = db.GetReadPool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)

		result, err := db.GetMetadata(ctx, tx, accountID, nil, []string{"/private/comment", "/shared/admin"}, nil)
		require.NoError(t, err)
		require.NotNil(t, result)

		err = tx.Commit(ctx)
		require.NoError(t, err)

		assert.Equal(t, 2, len(result.Entries))
		assert.Equal(t, "My server comment", string(*result.Entries["/private/comment"]))
		assert.Equal(t, "Admin contact", string(*result.Entries["/shared/admin"]))
	})

	// Test mailbox metadata
	t.Run("MailboxMetadata", func(t *testing.T) {
		// Create test mailbox
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)

		err = db.CreateMailbox(ctx, tx, accountID, "TestMailbox", nil)
		require.NoError(t, err)

		err = tx.Commit(ctx)
		require.NoError(t, err)

		// Get the mailbox ID
		mailboxes, err := db.GetMailboxes(ctx, accountID, false)
		require.NoError(t, err)
		var mailboxID int64
		for _, mb := range mailboxes {
			if mb.Name == "TestMailbox" {
				mailboxID = mb.ID
				break
			}
		}
		require.NotZero(t, mailboxID, "TestMailbox should exist")

		entries := map[string]*[]byte{
			"/private/comment": bytePtr([]byte("Mailbox comment")),
			"/shared/vendor":   bytePtr([]byte("Vendor data")),
		}

		// Set metadata
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)

		err = db.SetMetadata(ctx, tx, accountID, &mailboxID, entries, nil)
		require.NoError(t, err)

		err = tx.Commit(ctx)
		require.NoError(t, err)

		// Get metadata
		tx, err = db.GetReadPool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)

		result, err := db.GetMetadata(ctx, tx, accountID, &mailboxID, []string{"/private/comment", "/shared/vendor"}, nil)
		require.NoError(t, err)
		require.NotNil(t, result)

		err = tx.Commit(ctx)
		require.NoError(t, err)

		assert.Equal(t, 2, len(result.Entries))
		assert.Equal(t, "Mailbox comment", string(*result.Entries["/private/comment"]))
		assert.Equal(t, "Vendor data", string(*result.Entries["/shared/vendor"]))
	})
}

// TestMetadataUpdate tests updating existing entries
func TestMetadataUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	db := setupTestDatabase(t)
	ctx := context.Background()
	accountID := createTestAccount(t, db, "test-update@example.com", "password")

	entryName := "/private/comment"
	initialValue := bytePtr([]byte("Initial value"))
	updatedValue := bytePtr([]byte("Updated value"))

	// Set initial value
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.SetMetadata(ctx, tx, accountID, nil, map[string]*[]byte{entryName: initialValue}, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Update value
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.SetMetadata(ctx, tx, accountID, nil, map[string]*[]byte{entryName: updatedValue}, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify updated value
	tx, err = db.GetReadPool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	result, err := db.GetMetadata(ctx, tx, accountID, nil, []string{entryName}, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	assert.Equal(t, "Updated value", string(*result.Entries[entryName]))
}

// TestMetadataDelete tests deleting entries
func TestMetadataDelete(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	db := setupTestDatabase(t)
	ctx := context.Background()
	accountID := createTestAccount(t, db, "test-delete@example.com", "password")

	entryName := "/private/comment"
	value := bytePtr([]byte("To be deleted"))

	// Set value
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.SetMetadata(ctx, tx, accountID, nil, map[string]*[]byte{entryName: value}, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Delete value (set to nil)
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.SetMetadata(ctx, tx, accountID, nil, map[string]*[]byte{entryName: nil}, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify deleted
	tx, err = db.GetReadPool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	result, err := db.GetMetadata(ctx, tx, accountID, nil, []string{entryName}, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	assert.Equal(t, 0, len(result.Entries))
}

// TestMetadataDepth tests different DEPTH query options
func TestMetadataDepth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	db := setupTestDatabase(t)
	ctx := context.Background()
	accountID := createTestAccount(t, db, "test-depth@example.com", "password")

	// Set up hierarchical entries
	entries := map[string]*[]byte{
		"/private/comment":         bytePtr([]byte("root")),
		"/private/comment/user":    bytePtr([]byte("user comment")),
		"/private/comment/admin":   bytePtr([]byte("admin comment")),
		"/private/comment/user/v1": bytePtr([]byte("user v1")),
		"/private/vendor":          bytePtr([]byte("vendor root")),
	}

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.SetMetadata(ctx, tx, accountID, nil, entries, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	tests := []struct {
		name          string
		requestedKeys []string
		depth         imap.GetMetadataDepth
		expectedKeys  []string
	}{
		{
			name:          "Depth0_ExactMatch",
			requestedKeys: []string{"/private/comment"},
			depth:         imap.GetMetadataDepthZero,
			expectedKeys:  []string{"/private/comment"},
		},
		{
			name:          "Depth1_ImmediateChildren",
			requestedKeys: []string{"/private/comment"},
			depth:         imap.GetMetadataDepthOne,
			expectedKeys:  []string{"/private/comment", "/private/comment/user", "/private/comment/admin"},
		},
		{
			name:          "DepthInfinity_AllDescendants",
			requestedKeys: []string{"/private/comment"},
			depth:         imap.GetMetadataDepthInfinity,
			expectedKeys:  []string{"/private/comment", "/private/comment/user", "/private/comment/admin", "/private/comment/user/v1"},
		},
		{
			name:          "MultipleKeys_Depth0",
			requestedKeys: []string{"/private/comment", "/private/vendor"},
			depth:         imap.GetMetadataDepthZero,
			expectedKeys:  []string{"/private/comment", "/private/vendor"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := &imap.GetMetadataOptions{Depth: tt.depth}

			tx, err := db.GetReadPool().Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)

			result, err := db.GetMetadata(ctx, tx, accountID, nil, tt.requestedKeys, options)
			require.NoError(t, err)

			err = tx.Commit(ctx)
			require.NoError(t, err)

			assert.Equal(t, len(tt.expectedKeys), len(result.Entries), "Expected %d entries, got %d", len(tt.expectedKeys), len(result.Entries))

			for _, key := range tt.expectedKeys {
				_, exists := result.Entries[key]
				assert.True(t, exists, "Expected key %s to exist", key)
			}
		})
	}
}

// TestMetadataMaxSize tests MAXSIZE limiting
func TestMetadataMaxSize(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	db := setupTestDatabase(t)
	ctx := context.Background()
	accountID := createTestAccount(t, db, "test-maxsize@example.com", "password")

	// Set entries with different sizes
	entries := map[string]*[]byte{
		"/private/small": bytePtr([]byte("small")),            // 5 bytes
		"/private/large": bytePtr([]byte("large data value")), // 16 bytes
	}

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.SetMetadata(ctx, tx, accountID, nil, entries, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Request with MAXSIZE that only allows first entry
	maxSize := uint32(10)
	options := &imap.GetMetadataOptions{MaxSize: &maxSize}

	tx, err = db.GetReadPool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	result, err := db.GetMetadata(ctx, tx, accountID, nil, []string{"/private/small", "/private/large"}, options)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// With MAXSIZE=10, should stop when size limit is reached
	// The query returns results ordered by entry_name, so we get what fits
	// We should get at least some results (not exceed limit)
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

// TestMetadataEmptyValue tests storing empty/nil values
func TestMetadataEmptyValue(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	db := setupTestDatabase(t)
	ctx := context.Background()
	accountID := createTestAccount(t, db, "test-empty@example.com", "password")

	// Set entry with empty byte slice
	emptyValue := bytePtr([]byte{})
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.SetMetadata(ctx, tx, accountID, nil, map[string]*[]byte{"/private/empty": emptyValue}, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get and verify
	tx, err = db.GetReadPool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	result, err := db.GetMetadata(ctx, tx, accountID, nil, []string{"/private/empty"}, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Empty value should still be retrievable
	value, exists := result.Entries["/private/empty"]
	assert.True(t, exists)
	assert.Nil(t, value) // Empty bytes are stored as nil in result
}

// Helper functions

func bytePtr(b []byte) *[]byte {
	return &b
}
