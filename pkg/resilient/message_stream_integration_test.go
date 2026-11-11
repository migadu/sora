//go:build integration

package resilient_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/stretchr/testify/require"
)

// TestStreamMessagesByNumSetWithRetry_PerChunkTimeoutIgnoresSlowConsumer verifies end-to-end
// against PostgreSQL that a multi-chunk stream whose consumer spends longer than
// search_timeout in total (e.g. downloading bodies from S3 or flushing to a slow client)
// refreshes the database timeout per chunk rather than expiring mid-stream or tripping
// queryBreaker.
func TestStreamMessagesByNumSetWithRetry_PerChunkTimeoutIgnoresSlowConsumer(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	dbName := os.Getenv("SORA_TEST_DB_NAME")
	if dbName == "" {
		dbName = "sora_test_db"
	}
	cfg := &config.DatabaseConfig{
		SearchTimeout:  "80ms",
		FetchChunkSize: 2,
		Write: &config.DatabaseEndpointConfig{
			Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: dbName,
		},
	}
	rdb, err := resilient.NewResilientDatabase(context.Background(), cfg, false, true)
	require.NoError(t, err)
	t.Cleanup(rdb.Close)

	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	inbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	require.NoError(t, err)

	const totalMessages = 6 // 3 chunks of size 2
	wantUIDs := make([]imap.UID, 0, totalMessages)
	for i := range totalMessages {
		tx, err := rdb.BeginTxWithRetry(ctx, pgx.TxOptions{})
		require.NoError(t, err)
		now := time.Now()
		msgID := fmt.Sprintf("<stream-timeout-%d-%d@example.com>", i, now.UnixNano())
		opts := &db.InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     inbox.ID,
			MailboxName:   "INBOX",
			S3Domain:      "example.com",
			S3Localpart:   "stream",
			ContentHash:   fmt.Sprintf("stream-hash-%d-%d", i, now.UnixNano()),
			MessageID:     msgID,
			InternalDate:  now,
			Size:          128,
			Subject:       fmt.Sprintf("msg %d", i+1),
			PlaintextBody: "body",
			SentDate:      now,
			InReplyTo:     []string{},
		}
		upload := db.PendingUpload{AccountID: accountID, ContentHash: opts.ContentHash, InstanceID: "test", Size: 128, CreatedAt: now, UpdatedAt: now}
		_, uid, err := rdb.GetDatabase().InsertMessage(ctx, tx, opts, upload)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		wantUIDs = append(wantUIDs, imap.UID(uid))
	}

	cases := []struct {
		name   string
		numSet imap.NumSet
	}{
		{"uid_set", imap.UIDSet{{Start: 1, Stop: 0}}},
		{"seq_set_all_1_star", imap.SeqSet{{Start: 1, Stop: 0}}},
		{"seq_set_bounded", imap.SeqSet{{Start: 1, Stop: totalMessages}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotUIDs []imap.UID
			var gotSeqs []uint32
			chunks := 0
			err := rdb.StreamMessagesByNumSetWithRetry(ctx, inbox.ID, tc.numSet, func(chunk []db.Message) error {
				chunks++
				for _, m := range chunk {
					gotUIDs = append(gotUIDs, m.UID)
					gotSeqs = append(gotSeqs, m.Seq)
				}
				// 3 chunks * 55ms = 165ms > 2x SearchTimeout (80ms).
				time.Sleep(55 * time.Millisecond)
				return nil
			})
			require.NoError(t, err)
			require.Equal(t, 3, chunks)
			require.Equal(t, wantUIDs, gotUIDs)
			require.Equal(t, []uint32{1, 2, 3, 4, 5, 6}, gotSeqs)
			require.Equal(t, circuitbreaker.StateClosed, rdb.GetQueryBreakerState())
		})
	}
}
