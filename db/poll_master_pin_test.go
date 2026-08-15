package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newLaggingReplicaPool builds a SECOND, independent pgx pool against the same
// PostgreSQL server, whose sessions have their search_path pointed at a shadow
// schema. The shadow schema holds a point-in-time snapshot of the four tables
// PollMailbox reads (mailboxes, mailbox_stats, messages, message_state), so it
// behaves exactly like a read replica that is lagging behind the master: every
// unqualified table reference resolves to the stale copy.
func newLaggingReplicaPool(t *testing.T, ctx context.Context, schema string) *pgxpool.Pool {
	t.Helper()

	configPath, err := findTestConfig()
	require.NoError(t, err)
	var cfg TestConfig
	_, err = toml.DecodeFile(configPath, &cfg)
	require.NoError(t, err)

	connString := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cfg.Database.Write.User,
		cfg.Database.Write.Password,
		cfg.Database.Write.Hosts[0],
		cfg.Database.Write.Port,
		cfg.Database.Write.Name,
	)

	poolCfg, err := pgxpool.ParseConfig(connString)
	require.NoError(t, err)
	poolCfg.MaxConns = 4
	poolCfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, fmt.Sprintf("SET search_path TO %s, public", schema))
		return err
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	require.NoError(t, err)
	return pool
}

// TestPollMailboxHonoursMasterDBPin proves (or disproves) that db.PollMailbox
// drops the session's master-DB pin.
//
// server/imap/poll.go:39-45 puts consts.UseMasterDBKey into the context before
// calling PollMailboxWithRetry, exactly so that a session which just wrote
// (APPEND/STORE/EXPUNGE) reads its own writes back from the master instead of a
// possibly-lagging replica. db.PollMailbox, however, calls db.GetReadPool()
// rather than db.GetReadPoolWithContext(ctx) for every one of its queries
// (db/poll.go:37, 65, 204, 225), so the pin has no effect.
//
// Setup: a *Database whose WritePool is the real (master) test DB and whose
// ReadPool is a lagging-replica pool (see newLaggingReplicaPool). Three messages
// are appended to the master AFTER the replica snapshot is taken.
//
// Correct behaviour with a master-pinned context: PollMailbox observes the
// master -> 3 messages, 3 updates, the master's modseq.
// Buggy behaviour: PollMailbox observes the stale replica -> 0 messages, no
// updates, the stale modseq (and therefore takes the "modseq unchanged" early
// return at db/poll.go:55).
func TestPollMailboxHonoursMasterDBPin(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	master := setupTestDatabase(t)
	defer master.Close()
	ctx := context.Background()

	// ---- master state: account + mailbox -------------------------------
	testEmail := fmt.Sprintf("test_pollpin_%d@example.com", time.Now().UnixNano())
	tx, err := master.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = master.CreateAccount(ctx, tx, CreateAccountRequest{
		Email: testEmail, Password: "password", IsPrimary: true, HashType: "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	accountID, err := master.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	tx, err = master.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, master.CreateMailbox(ctx, tx, accountID, "INBOX", nil))
	require.NoError(t, tx.Commit(ctx))

	mailbox, err := master.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	mailboxID := mailbox.ID

	// ---- snapshot the replica BEFORE the messages are appended ---------
	schema := fmt.Sprintf("poll_pin_replica_%d", time.Now().UnixNano())
	_, err = master.GetWritePool().Exec(ctx, fmt.Sprintf("CREATE SCHEMA %s", schema))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = master.GetWritePool().Exec(context.Background(),
			fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", schema))
	})

	for _, stmt := range []string{
		fmt.Sprintf("CREATE TABLE %s.mailboxes AS SELECT * FROM public.mailboxes WHERE id = %d", schema, mailboxID),
		fmt.Sprintf("CREATE TABLE %s.mailbox_stats AS SELECT * FROM public.mailbox_stats WHERE mailbox_id = %d", schema, mailboxID),
		fmt.Sprintf("CREATE TABLE %s.messages AS SELECT * FROM public.messages WHERE mailbox_id = %d", schema, mailboxID),
		fmt.Sprintf("CREATE TABLE %s.message_state AS SELECT * FROM public.message_state WHERE mailbox_id = %d", schema, mailboxID),
	} {
		_, err = master.GetWritePool().Exec(ctx, stmt)
		require.NoError(t, err, "failed to build replica snapshot: %s", stmt)
	}

	// The modseq the session would be sitting at when it took the snapshot.
	sinceModSeq := getHighestModSeq(t, master, ctx, mailboxID)

	// ---- master moves ahead: 3 new messages ----------------------------
	tx, err = master.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	for _, uid := range []uint32{101, 102, 103} {
		insertTestMessageWithUIDForPoll(t, master, ctx, tx, accountID, mailboxID, "INBOX", uid, nil)
	}
	require.NoError(t, tx.Commit(ctx))

	masterModSeq := getHighestModSeq(t, master, ctx, mailboxID)
	require.Greater(t, masterModSeq, sinceModSeq, "sanity: master modseq must have advanced")

	var masterCount int
	require.NoError(t, master.GetWritePool().QueryRow(ctx,
		"SELECT COUNT(*)::int FROM public.messages WHERE mailbox_id = $1 AND expunged_at IS NULL",
		mailboxID).Scan(&masterCount))
	require.Equal(t, 3, masterCount, "sanity: master must hold the 3 appended messages")

	// ---- a Database with a real master pool and a lagging read pool ----
	replicaPool := newLaggingReplicaPool(t, ctx, schema)
	defer replicaPool.Close()

	split := &Database{
		WritePool: master.GetWritePool(),
		ReadPool:  replicaPool,
	}

	pinnedCtx := context.WithValue(ctx, consts.UseMasterDBKey, true)

	// ---- control 1: the pin mechanism itself ---------------------------
	require.NotSame(t, split.GetReadPool(), split.GetReadPoolWithContext(pinnedCtx),
		"harness broken: pinned accessor must return a different pool than GetReadPool()")
	require.Same(t, split.GetWritePool(), split.GetReadPoolWithContext(pinnedCtx),
		"harness broken: pinned accessor must return the write (master) pool")

	// ---- control 2: the replica really is stale ------------------------
	var replicaCount int
	require.NoError(t, replicaPool.QueryRow(ctx,
		"SELECT COUNT(*)::int FROM messages WHERE mailbox_id = $1", mailboxID).Scan(&replicaCount))
	require.Equal(t, 0, replicaCount, "harness broken: replica snapshot should hold no messages")

	// ---- control 3: a context-aware read path DOES honour the pin ------
	// getUIDBySeqNum (db/message.go) uses GetReadPoolWithContext, so with the
	// same wiring and the same pinned context it sees the master's messages.
	uid, err := split.getUIDBySeqNum(pinnedCtx, mailboxID, 1)
	require.NoError(t, err,
		"harness broken: a GetReadPoolWithContext-based read should have found the master's messages")
	require.EqualValues(t, 101, uid,
		"harness broken: pinned read should return the master's first UID")

	// ---- control 4: unpinned PollMailbox sees the stale replica --------
	unpinned, err := split.PollMailbox(ctx, mailboxID, sinceModSeq)
	require.NoError(t, err)
	require.Equal(t, uint32(0), unpinned.NumMessages,
		"harness broken: an unpinned poll must read the lagging replica")

	// ---- THE ASSERTION -------------------------------------------------
	poll, err := split.PollMailbox(pinnedCtx, mailboxID, sinceModSeq)
	require.NoError(t, err)

	assert.Equal(t, uint32(3), poll.NumMessages,
		"PollMailbox ignored the master-DB pin: it reported the lagging replica's message count "+
			"instead of the master's (db/poll.go uses GetReadPool(), not GetReadPoolWithContext(ctx))")
	assert.Equal(t, masterModSeq, poll.ModSeq,
		"PollMailbox ignored the master-DB pin: it reported the replica's stale highest_modseq")
	assert.Len(t, poll.Updates, 3,
		"PollMailbox ignored the master-DB pin: the 3 messages appended on the master produced no updates")
}
