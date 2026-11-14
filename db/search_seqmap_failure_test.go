package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

// failSeqMapping fails the statement that maps sequence numbers to UIDs (uidsBySeqNum)
// and lets every other statement through.
type failSeqMapping struct{ failed atomic.Int32 }

func (f *failSeqMapping) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	if !strings.Contains(q.SQL, "ranked.seqnum") {
		return ctx
	}
	f.failed.Add(1)
	failed, cancel := context.WithCancel(ctx)
	cancel()
	return failed
}

func (f *failSeqMapping) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// A search naming sequence numbers whose mapping to UIDs fails must fail with that
// error. It must neither run some other query that numbers the whole mailbox, nor
// replace the mapping error with the error of such a query.
func TestSearchFailsWhenSequenceMappingFails(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	accountID := createTestAccount(t, database, fmt.Sprintf("seqmapfail_%d@example.com", ts), "password")
	mailboxID := seedDenseMailbox(t, database, accountID, fmt.Sprintf("SeqMapFail_%d", ts), 10)

	tracer := &failSeqMapping{}
	poolCfg := database.ReadPool.Config().Copy()
	poolCfg.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	require.NoError(t, err)
	defer pool.Close()
	failing := &Database{WritePool: database.WritePool, ReadPool: pool}

	seqSet := []imap.SeqSet{{imap.SeqRange{Start: 1, Stop: 5}}}
	cases := []struct {
		name     string
		criteria imap.SearchCriteria
	}{
		{"sequence set", imap.SearchCriteria{SeqNum: seqSet}},
		{"sequence set and UID set", imap.SearchCriteria{
			SeqNum: seqSet,
			UID:    []imap.UIDSet{{imap.UIDRange{Start: 1, Stop: 3}}},
		}},
		{"sequence set and Message-ID", imap.SearchCriteria{
			SeqNum: seqSet,
			Header: []imap.SearchCriteriaHeaderField{{Key: "Message-ID", Value: "<a@example.com>"}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := tracer.failed.Load()
			found, err := failing.SearchMessagesWithCriteria(ctx, mailboxID, accountID, &tc.criteria, 0, 10)
			require.Greater(t, tracer.failed.Load(), before, "the sequence mapping must have been attempted")
			require.Error(t, err, "a failed sequence mapping must fail the search, got %d messages", len(found))
			require.Truef(t, errors.Is(err, context.Canceled),
				"the search must report the mapping failure, got: %v", err)
		})
	}
}
