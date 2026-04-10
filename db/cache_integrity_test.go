package db

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTriggerTestMailbox creates an account and mailbox for trigger testing.
// Returns the database, account ID, mailbox ID, and mailbox name.
func setupTriggerTestMailbox(t *testing.T) (*Database, int64, int64, string) {
	t.Helper()
	db := setupTestDatabase(t)
	ctx := context.Background()

	testEmail := fmt.Sprintf("test_trigger_%s_%d@example.com", t.Name(), time.Now().UnixNano())

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	req := CreateAccountRequest{Email: testEmail, Password: "password", IsPrimary: true, HashType: "bcrypt"}
	_, err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	mailboxName := "TestTriggerBox"
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	err = db.CreateMailbox(ctx, tx, accountID, mailboxName, nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	mailbox, err := db.GetMailboxByName(ctx, accountID, mailboxName)
	require.NoError(t, err)

	return db, accountID, mailbox.ID, mailboxName
}

// insertTestMsg is a concise helper to insert a message with a given UID.
func insertTestMsg(t *testing.T, db *Database, ctx context.Context, accountID, mailboxID int64, mailboxName string, uid uint32, flags []imap.Flag) {
	t.Helper()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	insertTestMessageWithUIDForTrigger(t, db, ctx, tx, accountID, mailboxID, mailboxName, uid, flags)
	require.NoError(t, tx.Commit(ctx))
}

// insertTestMessageWithUIDForTrigger inserts a test message with a given UID within a transaction.
func insertTestMessageWithUIDForTrigger(t *testing.T, db *Database, ctx context.Context, tx pgx.Tx, accountID, mailboxID int64, mailboxName string, uid uint32, flags []imap.Flag) {
	t.Helper()
	defaultBodyStructure := &imap.BodyStructureSinglePart{
		Type:    "text",
		Subtype: "plain",
		Size:    512,
	}
	var bs imap.BodyStructure = defaultBodyStructure
	now := time.Now()
	options := &InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailboxID,
		MailboxName:   mailboxName,
		S3Domain:      "example.com",
		S3Localpart:   fmt.Sprintf("test/trigger/%s/%d", t.Name(), uid),
		ContentHash:   fmt.Sprintf("trigger_%s_%d", t.Name(), uid),
		MessageID:     fmt.Sprintf("<trigger_%s_%d@example.com>", t.Name(), uid),
		Flags:         flags,
		InternalDate:  now,
		Size:          512,
		Subject:       fmt.Sprintf("Trigger Test %d", uid),
		PlaintextBody: "body",
		RawHeaders:    "headers",
		SentDate:      now,
		PreservedUID:  &uid,
		BodyStructure: &bs,
	}
	_, _, err := db.InsertMessageFromImporter(ctx, tx, options)
	require.NoError(t, err, "failed to insert test message with UID %d", uid)
}

// getCustomFlagsCache reads the custom_flags_cache column from mailbox_stats.
func getCustomFlagsCache(t *testing.T, db *Database, ctx context.Context, mailboxID int64) ([]string, bool) {
	t.Helper()
	var cacheJSON []byte
	err := db.GetReadPool().QueryRow(ctx,
		"SELECT custom_flags_cache FROM mailbox_stats WHERE mailbox_id = $1", mailboxID).Scan(&cacheJSON)
	if err == pgx.ErrNoRows || cacheJSON == nil {
		return nil, false
	}
	require.NoError(t, err)

	var flags []string
	require.NoError(t, json.Unmarshal(cacheJSON, &flags))
	return flags, true
}

// cleanupMailbox removes all messages from a mailbox.
func cleanupMailbox(t *testing.T, db *Database, ctx context.Context, mailboxID int64) {
	t.Helper()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, "DELETE FROM messages WHERE mailbox_id = $1", mailboxID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
}

// ============================================================================
// CUSTOM FLAGS CACHE TRIGGER TESTS
// ============================================================================

func TestCustomFlagsCache_EmptyOnNewMailbox(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, mailboxID, _ := setupTriggerTestMailbox(t)
	defer db.Close()
	ctx := context.Background()

	// New mailbox with no messages should have NULL cache (not yet populated)
	// OR '[]' if the trigger initialized it
	flags, hasCacheRow := getCustomFlagsCache(t, db, ctx, mailboxID)
	if hasCacheRow {
		assert.Empty(t, flags, "New mailbox should have empty custom flags cache")
	}
	// NULL is also acceptable (no mailbox_stats row yet)
}

func TestCustomFlagsCache_PopulatedOnInsertWithCustomFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID, mailboxName := setupTriggerTestMailbox(t)
	defer db.Close()
	ctx := context.Background()

	// Insert message with custom flags
	customFlags := []imap.Flag{imap.FlagSeen, imap.Flag("Important"), imap.Flag("Work")}
	insertTestMsg(t, db, ctx, accountID, mailboxID, mailboxName, 10, customFlags)

	cache, hasCache := getCustomFlagsCache(t, db, ctx, mailboxID)
	assert.True(t, hasCache, "Should have cache after inserting message with custom flags")
	assert.Contains(t, cache, "Important")
	assert.Contains(t, cache, "Work")
	// System flags should NOT be in cache
	for _, f := range cache {
		assert.NotEqual(t, "\\Seen", f, "System flags should not appear in custom flags cache")
	}

	cleanupMailbox(t, db, ctx, mailboxID)
}

func TestCustomFlagsCache_NotRebuiltForSystemFlagsOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID, mailboxName := setupTriggerTestMailbox(t)
	defer db.Close()
	ctx := context.Background()

	// Insert message with only system flags (no custom flags)
	systemFlags := []imap.Flag{imap.FlagSeen, imap.FlagFlagged}
	insertTestMsg(t, db, ctx, accountID, mailboxID, mailboxName, 10, systemFlags)

	// Cache should be empty (or null) since no custom flags
	cache, hasCache := getCustomFlagsCache(t, db, ctx, mailboxID)
	if hasCache {
		assert.Empty(t, cache, "Cache should be empty when only system flags exist")
	}

	cleanupMailbox(t, db, ctx, mailboxID)
}

func TestCustomFlagsCache_UpdatedOnFlagChange(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID, mailboxName := setupTriggerTestMailbox(t)
	defer db.Close()
	ctx := context.Background()

	// Insert message with no custom flags
	insertTestMsg(t, db, ctx, accountID, mailboxID, mailboxName, 10, nil)

	// Add custom flags
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, _, err = db.SetMessageFlags(ctx, tx, 10, mailboxID, []imap.Flag{imap.FlagSeen, imap.Flag("Project-X")})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	cache, hasCache := getCustomFlagsCache(t, db, ctx, mailboxID)
	assert.True(t, hasCache)
	assert.Contains(t, cache, "Project-X")

	// Now change to different custom flags
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, _, err = db.SetMessageFlags(ctx, tx, 10, mailboxID, []imap.Flag{imap.FlagSeen, imap.Flag("Project-Y")})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	cache, hasCache = getCustomFlagsCache(t, db, ctx, mailboxID)
	assert.Contains(t, cache, "Project-Y")
	assert.Contains(t, cache, "Project-X", "Old custom flag should be retained in cache per migration 019 optimizations")

	cleanupMailbox(t, db, ctx, mailboxID)
}

func TestCustomFlagsCache_ClearedOnExpunge(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID, mailboxName := setupTriggerTestMailbox(t)
	defer db.Close()
	ctx := context.Background()

	// Insert message with custom flags
	insertTestMsg(t, db, ctx, accountID, mailboxID, mailboxName, 10,
		[]imap.Flag{imap.Flag("CustomFlag1")})

	cache, _ := getCustomFlagsCache(t, db, ctx, mailboxID)
	assert.Contains(t, cache, "CustomFlag1")

	// Expunge the message
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.ExpungeMessageUIDs(ctx, tx, mailboxID, 10)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	// Cache should retain the flags per migration 019
	cache, hasCache := getCustomFlagsCache(t, db, ctx, mailboxID)
	if hasCache {
		assert.Contains(t, cache, "CustomFlag1", "Cache should explicitly retain flags on expunge")
	}

	cleanupMailbox(t, db, ctx, mailboxID)
}

func TestCustomFlagsCache_MultipleMessagesAggregated(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID, mailboxName := setupTriggerTestMailbox(t)
	defer db.Close()
	ctx := context.Background()

	// Insert messages with different custom flags
	insertTestMsg(t, db, ctx, accountID, mailboxID, mailboxName, 10,
		[]imap.Flag{imap.Flag("Alpha"), imap.Flag("Beta")})
	insertTestMsg(t, db, ctx, accountID, mailboxID, mailboxName, 20,
		[]imap.Flag{imap.Flag("Beta"), imap.Flag("Gamma")})

	cache, hasCache := getCustomFlagsCache(t, db, ctx, mailboxID)
	assert.True(t, hasCache)
	assert.Contains(t, cache, "Alpha")
	assert.Contains(t, cache, "Beta")
	assert.Contains(t, cache, "Gamma")

	// Expunge message with Alpha+Beta, only Gamma (from message 20) should remain
	// But Beta is shared so it should also remain
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.ExpungeMessageUIDs(ctx, tx, mailboxID, 10)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	cache, hasCache = getCustomFlagsCache(t, db, ctx, mailboxID)
	assert.True(t, hasCache)
	assert.Contains(t, cache, "Alpha", "Alpha should remain per migration 019 monotonic cache design")
	assert.Contains(t, cache, "Beta", "Beta should remain (on message UID 20)")
	assert.Contains(t, cache, "Gamma", "Gamma should remain (on message UID 20)")

	cleanupMailbox(t, db, ctx, mailboxID)
}

func TestCustomFlagsCache_MatchesGoFunction(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID, mailboxName := setupTriggerTestMailbox(t)
	defer db.Close()
	ctx := context.Background()

	// Insert messages with various custom flags
	insertTestMsg(t, db, ctx, accountID, mailboxID, mailboxName, 10,
		[]imap.Flag{imap.FlagSeen, imap.Flag("Todo"), imap.Flag("Urgent")})
	insertTestMsg(t, db, ctx, accountID, mailboxID, mailboxName, 20,
		[]imap.Flag{imap.Flag("Urgent"), imap.Flag("Archive")})

	// Get flags via Go function (which reads from cache)
	goFlags, err := db.GetUniqueCustomFlagsForMailbox(ctx, mailboxID)
	require.NoError(t, err)

	// Get flags directly from cache
	cacheFlags, hasCache := getCustomFlagsCache(t, db, ctx, mailboxID)

	if hasCache && len(cacheFlags) > 0 {
		// Both should contain the same flags (order may differ)
		assert.ElementsMatch(t, cacheFlags, goFlags,
			"Go function result should match cached flags")
	}

	// Verify expected flags
	assert.Contains(t, goFlags, "Todo")
	assert.Contains(t, goFlags, "Urgent")
	assert.Contains(t, goFlags, "Archive")

	cleanupMailbox(t, db, ctx, mailboxID)
}
