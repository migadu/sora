package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetActiveUIDsInSetManyRanges: a fragmented known-uids ("1,3,5,...") is one range
// per UID, and the query must not grow with it (#1354). It had an OR term and one or
// two bind parameters per range, so a set of 70,000 ranges could not even be sent
// (the extended protocol allows 65,535 parameters).
func TestGetActiveUIDsInSetManyRanges(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	accountID := createTestAccount(t, database, fmt.Sprintf("knownuids_%d@example.com", ts), "password")
	mailboxName := fmt.Sprintf("KnownUIDs_%d", ts)
	mailboxID := createTestMailbox(t, database, accountID, mailboxName)

	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	for _, uid := range []uint32{1, 2, 3, 139_999, 200_000, 200_002} {
		insertTestMessageWithUIDForPoll(t, database, ctx, tx, accountID, mailboxID, mailboxName, uid, nil)
	}
	require.NoError(t, tx.Commit(ctx))

	// Every odd UID below 140,000, then 200,001:200,005.
	var known imap.UIDSet
	for uid := imap.UID(1); uid < 140_000; uid += 2 {
		known = append(known, imap.UIDRange{Start: uid, Stop: uid})
	}
	known = append(known, imap.UIDRange{Start: 200_001, Stop: 200_005})
	want := []imap.UID{1, 3, 139_999, 200_002}

	active, err := database.GetActiveUIDsInSet(ctx, mailboxID, known)
	require.NoError(t, err)
	assert.Equal(t, want, active)

	view := WithSeqView(ctx, getHighestModSeq(t, database, ctx, mailboxID))
	active, err = database.GetActiveUIDsInSet(view, mailboxID, known)
	require.NoError(t, err)
	assert.Equal(t, want, active, "in a view at the current modseq")
}
