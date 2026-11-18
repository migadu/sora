package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

// RFC 9051 §6.4.8: '*' is the highest UID still present, and range endpoint
// order does not matter. UIDNEXT:* therefore includes that message even when
// UIDNEXT is greater than every UID that has been assigned.
func TestStreamMessagesByUIDSetWildcardEndpoints(t *testing.T) {
	database := setupTestDatabase(t)
	ctx := context.Background()
	ts := time.Now().UnixNano()
	accountID := createTestAccount(t, database, fmt.Sprintf("fetchuid_%d@example.com", ts), "password")
	mailboxID := seedDenseMailbox(t, database, accountID, fmt.Sprintf("FetchUID_%d", ts), 10)
	// The last allocated UID is gone, so '*' must resolve to UID 9, not 10.
	_, err := database.GetWritePool().Exec(ctx,
		`UPDATE messages SET expunged_at = now() WHERE mailbox_id = $1 AND uid = 10`, mailboxID)
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		set  imap.UIDSet
		want []imap.UID
	}{
		{"uidnext to wildcard", imap.UIDSet{{Start: 11, Stop: 0}}, []imap.UID{9}},
		{"wildcard to uidnext", imap.UIDSet{{Start: 0, Stop: 11}}, []imap.UID{9}},
		{"wildcard alone", imap.UIDSet{{Start: 0, Stop: 0}}, []imap.UID{9}},
		{"within mailbox to wildcard", imap.UIDSet{{Start: 7, Stop: 0}}, []imap.UID{7, 8, 9}},
		{"wildcard to within mailbox", imap.UIDSet{{Start: 0, Stop: 7}}, []imap.UID{7, 8, 9}},
		{"mixed fixed and wildcard ranges", imap.UIDSet{{Start: 1, Stop: 2}, {Start: 11, Stop: 0}}, []imap.UID{1, 2, 9}},
		{"explicit range past end", imap.UIDSet{{Start: 11, Stop: 12}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Match go-imap's parser, which normalizes '*:n' to 'n:*'.
			var set imap.UIDSet
			for _, r := range tc.set {
				set.AddRange(r.Start, r.Stop)
			}
			var got []imap.UID
			err := database.StreamMessagesByNumSet(ctx, mailboxID, set, func(chunk []Message) error {
				for _, msg := range chunk {
					got = append(got, msg.UID)
				}
				return nil
			})
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestStreamMessagesByUIDSetWildcardEmptyMailbox(t *testing.T) {
	database := setupTestDatabase(t)
	ctx := context.Background()
	accountID := createTestAccount(t, database, fmt.Sprintf("fetchuid_empty_%d@example.com", time.Now().UnixNano()), "password")
	mailboxID := seedDenseMailbox(t, database, accountID, "EmptyWildcard", 3)
	_, err := database.GetWritePool().Exec(ctx,
		`UPDATE messages SET expunged_at = now() WHERE mailbox_id = $1`, mailboxID)
	require.NoError(t, err)
	for _, set := range []imap.UIDSet{
		{{Start: 0, Stop: 0}},
		{{Start: 1, Stop: 0}},
		{{Start: 99, Stop: 0}},
		{{Start: 1, Stop: 2}, {Start: 99, Stop: 0}},
	} {
		t.Run(set.String(), func(t *testing.T) {
			messages, err := database.GetMessagesByNumSet(ctx, mailboxID, set)
			require.NoError(t, err)
			require.Empty(t, messages)
		})
	}
}

// A UID wildcard uses the live tail even while sequence numbering retains a
// later message whose EXPUNGE has not been reported to the client.
func TestStreamMessagesByUIDSetWildcardWithHeldExpungedTail(t *testing.T) {
	database := setupTestDatabase(t)
	ctx := context.Background()
	accountID := createTestAccount(t, database, fmt.Sprintf("fetchuid_view_%d@example.com", time.Now().UnixNano()), "password")
	mailboxID := seedDenseMailbox(t, database, accountID, "HeldTailWildcard", 10)
	_, err := database.GetWritePool().Exec(ctx,
		`UPDATE messages SET expunged_at = now(), expunged_modseq = 11 WHERE mailbox_id = $1 AND uid IN (9, 10)`, mailboxID)
	require.NoError(t, err)
	ctx = WithSeqView(ctx, 10)
	for _, set := range []imap.UIDSet{
		{{Start: 0, Stop: 0}},
		{{Start: 11, Stop: 0}},
	} {
		t.Run(set.String(), func(t *testing.T) {
			messages, err := database.GetMessagesByNumSet(ctx, mailboxID, set)
			require.NoError(t, err)
			require.Len(t, messages, 1)
			require.Equal(t, imap.UID(8), messages[0].UID)
			require.Equal(t, uint32(8), messages[0].Seq)
		})
	}
}

// Resolve '*' once for the whole command, rather than accepting new arrivals
// between chunks of a UID FETCH 1:*.
func TestStreamMessagesByUIDSetWildcardStableAcrossChunks(t *testing.T) {
	database := setupTestDatabase(t)
	database.fetchChunkSize = 2
	ctx := context.Background()
	accountID := createTestAccount(t, database, fmt.Sprintf("fetchuid_chunks_%d@example.com", time.Now().UnixNano()), "password")
	mailboxID := seedDenseMailbox(t, database, accountID, "ChunkWildcard", 6)
	var got []imap.UID
	appended := false
	err := database.StreamMessagesByNumSet(ctx, mailboxID, imap.UIDSet{{Start: 1, Stop: 0}}, func(chunk []Message) error {
		for _, msg := range chunk {
			got = append(got, msg.UID)
		}
		if !appended {
			tx, err := database.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)
			for _, uid := range []uint32{7, 8} {
				insertTestMessageWithUIDForPoll(t, database, ctx, tx, accountID, mailboxID, "ChunkWildcard", uid, nil)
			}
			require.NoError(t, tx.Commit(ctx))
			appended = true
		}
		return nil
	})
	require.NoError(t, err)
	require.True(t, appended)
	require.Equal(t, []imap.UID{1, 2, 3, 4, 5, 6}, got)
}
