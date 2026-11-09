package db

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

type wildcardSnapshotAppend struct {
	once           sync.Once
	appendMessages func()
}

type wildcardSnapshotKey struct{}

func (g *wildcardSnapshotAppend) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	if strings.Contains(q.SQL, "ranked.seqnum") {
		return context.WithValue(ctx, wildcardSnapshotKey{}, true)
	}
	return ctx
}
func (g *wildcardSnapshotAppend) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryEndData) {
	if q.Err == nil && ctx.Value(wildcardSnapshotKey{}) == true {
		g.once.Do(g.appendMessages)
	}
}

func TestSearchWildcardUsesOneMailboxSnapshot(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()
	accountID := createTestAccount(t, database, fmt.Sprintf("wildcard_snapshot_%d@example.com", time.Now().UnixNano()), "password")
	mailboxID := seedDenseMailbox(t, database, accountID, "WildcardSnapshot", 98)
	appended := false
	gate := &wildcardSnapshotAppend{appendMessages: func() {
		// Commit after the ranked endpoint query has read 98 messages, before a
		// separate last-UID query could run. 99:* initially means UID 98; after
		// this append it means UIDs 99:100. UID 100 alone is never a valid answer.
		tx, err := database.WritePool.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		for _, uid := range []uint32{99, 100} {
			insertTestMessageWithUIDForPoll(t, database, ctx, tx, accountID, mailboxID, "WildcardSnapshot", uid, nil)
		}
		require.NoError(t, tx.Commit(ctx))
		appended = true
	}}
	poolCfg := database.ReadPool.Config().Copy()
	poolCfg.ConnConfig.Tracer = gate
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	require.NoError(t, err)
	defer pool.Close()
	reader := &Database{ReadPool: pool, WritePool: database.WritePool}
	criteria := &imap.SearchCriteria{SeqNum: []imap.SeqSet{{{Start: 99, Stop: 0}}}}
	require.NoError(t, reader.mapSeqNumCriteriaToUID(ctx, mailboxID, criteria))
	require.True(t, appended, "the race control must have committed both messages")
	require.Equal(t, []imap.UIDSet{imap.UIDSetNum(98)}, criteria.UID, "range endpoints must share the same read snapshot")
}
