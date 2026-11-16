package db

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// This is a real duration regression against the former one-minute overlap.
// SET CONSTRAINTS IMMEDIATE stamps/inserts the event before the writer waits;
// an unrelated writer must commit and be delivered while that writer is open.
func TestCredentialChangesSnapshotSeesEarlyTriggerAfterLongCommit(t *testing.T) {
	d := setupTestDatabaseWithSuffix(t, "_feed_long")
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	slowID, slowEmail := credentialChangesAccount(t, d, "slow-immediate")
	fastID, fastEmail := credentialChangesAccount(t, d, "fast-independent")
	slow, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer slow.Rollback(context.Background())
	_, err = slow.Exec(ctx, "UPDATE credentials SET password='slow-new-hash' WHERE address=$1", slowEmail)
	require.NoError(t, err)
	_, err = slow.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE")
	require.NoError(t, err)
	var writer int64
	var stamped time.Time
	require.NoError(t, slow.QueryRow(ctx, "SELECT writer_xid,changed_at FROM credential_changes WHERE account_id=$1", slowID).Scan(&writer, &stamped))
	fastCtx, fastCancel := context.WithTimeout(ctx, 3*time.Second)
	fast, err := d.GetWritePool().Begin(fastCtx)
	require.NoError(t, err)
	_, err = fast.Exec(fastCtx, "UPDATE credentials SET password='fast-new-hash' WHERE address=$1", fastEmail)
	require.NoError(t, err)
	require.NoError(t, fast.Commit(fastCtx), "an open early-trigger writer must not stall unrelated revocation commits")
	fastCancel()
	first, err := d.GetCredentialChangesSince(ctx, 0)
	require.NoError(t, err)
	require.Contains(t, first.Accounts, fastID)
	require.NotContains(t, first.Accounts, slowID)
	require.LessOrEqual(t, first.NextCursor, writer, "active writer stays at or above the safe cursor")
	t.Logf("visible unrelated revocation delivered while writer%d remains open; holding it for65 real seconds", writer)
	_, err = slow.Exec(ctx, "SELECT pg_sleep(65)")
	require.NoError(t, err)
	beforeCommit, err := d.GetCredentialChangesSince(ctx, first.NextCursor)
	require.NoError(t, err)
	require.Contains(t, beforeCommit.Accounts, fastID)
	require.NotContains(t, beforeCommit.Accounts, slowID)
	require.Greater(t, beforeCommit.ReadAt.Sub(stamped), time.Minute)
	require.LessOrEqual(t, beforeCommit.NextCursor, writer)
	require.NoError(t, slow.Commit(ctx))
	after, err := d.GetCredentialChangesSince(ctx, beforeCommit.NextCursor)
	require.NoError(t, err)
	require.Contains(t, after.Accounts, slowID, "the late commit remains eligible without a time window")
	// Execute the archived implementation's timestamp predicate on the same real
	// writer/history. A previous poll's clock minus one minute has lost this row.
	var legacyVisible bool
	require.NoError(t, d.GetWritePool().QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM credential_changes WHERE account_id=$1 AND changed_at >=$2)", slowID, beforeCommit.ReadAt.Add(-time.Minute)).Scan(&legacyVisible))
	require.False(t, legacyVisible, "old fixed overlap should miss the actual65second late commit")
}

func TestCredentialChangesRetentionStartsOnlyAfterVisibleObservation(t *testing.T) {
	d := setupTestDatabaseWithSuffix(t, "_feed_observation")
	defer d.Close()
	ctx := context.Background()
	accountID := -time.Now().UnixNano()
	writer, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer writer.Rollback(ctx)
	_, err = writer.Exec(ctx, "INSERT INTO credential_changes(account_id,ends_sessions,changed_at) VALUES($1,FALSE,clock_timestamp()-interval '8 days')", accountID)
	require.NoError(t, err)
	cutoff := dbNow(t, d).Add(-7 * 24 * time.Hour)
	inTx(t, d, func(tx pgx.Tx) { _, err := d.PruneCredentialChanges(ctx, tx, cutoff); require.NoError(t, err) })
	var observed *time.Time
	require.NoError(t, writer.QueryRow(ctx, "SELECT first_observed_at FROM credential_changes WHERE account_id=$1", accountID).Scan(&observed))
	require.Nil(t, observed)
	require.NoError(t, writer.Commit(ctx))
	beforeObservation := dbNow(t, d)
	inTx(t, d, func(tx pgx.Tx) { _, err := d.PruneCredentialChanges(ctx, tx, cutoff); require.NoError(t, err) })
	require.NoError(t, d.GetWritePool().QueryRow(ctx, "SELECT first_observed_at FROM credential_changes WHERE account_id=$1", accountID).Scan(&observed))
	require.NotNil(t, observed)
	require.False(t, observed.Before(beforeObservation), "writer timestamp cannot consume the exposure interval")
	// This models an event which has actually been observed for a retention period.
	_, err = d.GetWritePool().Exec(ctx, "UPDATE credential_changes SET first_observed_at=clock_timestamp()-interval '8 days' WHERE account_id=$1", accountID)
	require.NoError(t, err)
	inTx(t, d, func(tx pgx.Tx) { _, err := d.PruneCredentialChanges(ctx, tx, cutoff); require.NoError(t, err) })
	var left int
	require.NoError(t, d.GetWritePool().QueryRow(ctx, "SELECT count(*) FROM credential_changes WHERE account_id=$1", accountID).Scan(&left))
	require.Zero(t, left)
}

func TestCredentialChangesObservationUsesIndexWithRetainedHistory(t *testing.T) {
	d := setupTestDatabaseWithSuffix(t, "_feed_plan")
	defer d.Close()
	ctx := context.Background()
	_, err := d.GetWritePool().Exec(ctx, `INSERT INTO credential_changes(account_id,ends_sessions,first_observed_at)
 SELECT -g,FALSE,clock_timestamp()-interval '6 days' FROM generate_series(1,10000)g;
 INSERT INTO credential_changes(account_id,ends_sessions) SELECT -10000-g,FALSE FROM generate_series(1,10)g;
 ANALYZE credential_changes`)
	require.NoError(t, err)
	tx, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	var plan []byte
	require.NoError(t, tx.QueryRow(ctx, `EXPLAIN(ANALYZE,BUFFERS,FORMAT JSON) UPDATE credential_changes SET first_observed_at=clock_timestamp() WHERE first_observed_at IS NULL`).Scan(&plan))
	require.Contains(t, string(plan), "idx_credential_changes_observed")
	var decoded any
	require.NoError(t, json.Unmarshal(plan, &decoded))
	t.Logf("default observation plan:%s", plan)
}

// An opt-in dedicated DSN permits this test on a private PostgreSQL instance
// configured for prepared transactions, without changing the shared server.
// The normal database path explicitly skips if its administrator disabled them.
func preparedCredentialFeedDatabase(t *testing.T) *Database {
	t.Helper()
	skipDatabaseTestInShortMode(t)
	dsn := os.Getenv("SORA_CREDCHANGES_PREPARED_DSN")
	if dsn == "" {
		d := setupTestDatabaseWithSuffix(t, "_feed_prepared")
		t.Cleanup(d.Close)
		return d
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	var name string
	require.NoError(t, pool.QueryRow(context.Background(), "SELECT current_database()").Scan(&name))
	require.True(t, strings.HasPrefix(name, "sora_credfeed_prepared_"), "opt-in DSN must name a dedicated test database")
	_, err = pool.Exec(context.Background(), `CREATE TABLE IF NOT EXISTS accounts(id bigint PRIMARY KEY,deleted_at timestamptz);
 CREATE TABLE IF NOT EXISTS credentials(id bigserial PRIMARY KEY,account_id bigint REFERENCES accounts(id) ON DELETE CASCADE,address text,password text)`)
	require.NoError(t, err)
	up, err := os.ReadFile("migrations/000069_credential_changes.up.sql")
	require.NoError(t, err)
	_, err = pool.Exec(context.Background(), string(up))
	require.NoError(t, err)
	return &Database{WritePool: pool, ReadPool: pool}
}

func TestCredentialChangesSnapshotKeepsPreparedWriterEligible(t *testing.T) {
	d := preparedCredentialFeedDatabase(t)
	ctx := context.Background()
	var enabled int
	require.NoError(t, d.GetWritePool().QueryRow(ctx, "SELECT current_setting('max_prepared_transactions')::int").Scan(&enabled))
	if enabled == 0 {
		t.Skip("prepared transactions disabled; run with dedicated SORA_CREDCHANGES_PREPARED_DSN for this control")
	}
	slowID := -time.Now().UnixNano()
	fastID := slowID - 1
	// The dedicated fixture deliberately uses only schema needed by migration69.
	_, err := d.GetWritePool().Exec(ctx, "INSERT INTO accounts(id)VALUES($1),($2)", slowID, fastID)
	require.NoError(t, err)
	_, err = d.GetWritePool().Exec(ctx, "INSERT INTO credentials(account_id,address,password)VALUES($1,$3,'old'),($2,$4,'old')", slowID, fastID, fmt.Sprintf("prepared-slow-%d", -slowID), fmt.Sprintf("prepared-fast-%d", -slowID))
	require.NoError(t, err)
	slow, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer slow.Rollback(ctx)
	_, err = slow.Exec(ctx, "UPDATE credentials SET password='new' WHERE account_id=$1", slowID)
	require.NoError(t, err)
	_, err = slow.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE")
	require.NoError(t, err)
	var writer int64
	require.NoError(t, slow.QueryRow(ctx, "SELECT writer_xid FROM credential_changes WHERE account_id=$1", slowID).Scan(&writer))
	gid := fmt.Sprintf("credfeed_%d", time.Now().UnixNano())
	_, err = slow.Exec(ctx, "PREPARE TRANSACTION '"+gid+"'")
	require.NoError(t, err)
	t.Cleanup(func() { d.GetWritePool().Exec(context.Background(), "ROLLBACK PREPARED '"+gid+"'") })
	// Release the now-idle connection; the prepared transaction survives it.
	require.NoError(t, slow.Rollback(ctx))
	var prepared bool
	require.NoError(t, d.GetWritePool().QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_prepared_xacts WHERE gid=$1)", gid).Scan(&prepared))
	require.True(t, prepared, "prepared writer survives release of its original connection")
	_, err = d.GetWritePool().Exec(ctx, "UPDATE credentials SET password='new' WHERE account_id=$1", fastID)
	require.NoError(t, err)
	before, err := d.GetCredentialChangesSince(ctx, 0)
	require.NoError(t, err)
	require.Contains(t, before.Accounts, fastID)
	require.NotContains(t, before.Accounts, slowID)
	require.LessOrEqual(t, before.NextCursor, writer)
	_, err = d.GetWritePool().Exec(ctx, "COMMIT PREPARED '"+gid+"'")
	require.NoError(t, err)
	after, err := d.GetCredentialChangesSince(ctx, before.NextCursor)
	require.NoError(t, err)
	require.Contains(t, after.Accounts, slowID)
}
