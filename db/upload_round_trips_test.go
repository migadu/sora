package db

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// roundTripCounter counts client->server request bursts over a single PostgreSQL
// connection: each Write that follows a Read (or connection setup) adds 1, while
// consecutive Writes before any Read (a pipelined pgx.Batch) count once (#1813).
type roundTripCounter struct {
	mu    sync.Mutex
	armed bool
	trips int64
}

func (r *roundTripCounter) onWrite(n int) {
	if n <= 0 {
		return
	}
	r.mu.Lock()
	if r.armed {
		r.trips++
		r.armed = false
	}
	r.mu.Unlock()
}

func (r *roundTripCounter) onRead(n int) {
	if n <= 0 {
		return
	}
	r.mu.Lock()
	r.armed = true
	r.mu.Unlock()
}

func (r *roundTripCounter) reset() {
	r.mu.Lock()
	r.trips = 0
	r.armed = true
	r.mu.Unlock()
}

func (r *roundTripCounter) count() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.trips
}

type countingNetConn struct {
	net.Conn
	counter *roundTripCounter
}

func (c *countingNetConn) Write(p []byte) (int, error) {
	c.counter.onWrite(len(p))
	return c.Conn.Write(p)
}

func (c *countingNetConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.counter.onRead(n)
	return n, err
}

func newSingleConnCountingDB(t *testing.T, base *Database) (*Database, *roundTripCounter) {
	t.Helper()
	ctx := context.Background()
	cfg := base.GetWritePool().Config()
	cfg.MaxConns = 1
	cfg.MinConns = 0
	cfg.MinIdleConns = 0
	cfg.HealthCheckPeriod = time.Hour
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = time.Hour

	counter := &roundTripCounter{armed: true}
	baseDial := cfg.ConnConfig.DialFunc
	if baseDial == nil {
		var d net.Dialer
		baseDial = d.DialContext
	}
	cfg.ConnConfig.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := baseDial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &countingNetConn{Conn: conn, counter: counter}, nil
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return &Database{WritePool: pool, ReadPool: pool}, counter
}

func TestUploadFenceRoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	baseDB, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer baseDB.Close()
	ctx := context.Background()

	countedDB, counter := newSingleConnCountingDB(t, baseDB)

	// Warm statement cache for PassS3WriteGate, CompleteLeasedS3Upload, and CompleteS3Upload.
	warmHash1 := fmt.Sprintf("rt_warm_leased_%d", time.Now().UnixNano())
	insertKeyedMessage(t, baseDB, accountID, mailboxID, 9001, warmHash1, "rtuser", false, time.Time{})
	warmPending1 := createPendingUpload(t, baseDB, accountID, "rt-node", warmHash1, 0, time.Time{}, 100)
	gate, err := countedDB.PassS3WriteGate(ctx, warmPending1, accountID, warmHash1, gateTestOwner, gateTestLease)
	require.NoError(t, err)
	require.Equal(t, S3WriteOpen, gate)
	tx, err := countedDB.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, countedDB.CompleteLeasedS3Upload(ctx, tx, warmPending1, gateTestOwner, warmHash1, accountID,
		[]string{"example.com/rtuser/" + warmHash1}))
	require.NoError(t, tx.Commit(ctx))

	warmHash2 := fmt.Sprintf("rt_warm_direct_%d", time.Now().UnixNano())
	insertKeyedMessage(t, baseDB, accountID, mailboxID, 9002, warmHash2, "rtuser", false, time.Time{})
	_ = createPendingUpload(t, baseDB, accountID, "rt-node", warmHash2, 0, time.Time{}, 100)
	tx, err = countedDB.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, countedDB.CompleteS3Upload(ctx, tx, warmHash2, accountID,
		[]string{"example.com/rtuser/" + warmHash2}))
	require.NoError(t, tx.Commit(ctx))

	// 1. PassS3WriteGate (contended by exclusive body lock) -> 1 round trip, and
	//    must NOT invalidate the prepared statement cache for the next call.
	hash := fmt.Sprintf("rt_measured_%d", time.Now().UnixNano())
	insertKeyedMessage(t, baseDB, accountID, mailboxID, 9003, hash, "rtuser", false, time.Time{})
	pendingID := createPendingUpload(t, baseDB, accountID, "rt-node", hash, 0, time.Time{}, 100)
	lockID := GetS3ObjectLockID(accountID, hash)

	holder, err := baseDB.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer holder.Rollback(ctx)
	_, err = holder.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockID)
	require.NoError(t, err)

	counter.reset()
	gate, err = countedDB.PassS3WriteGate(ctx, pendingID, accountID, hash, gateTestOwner, gateTestLease)
	require.NoError(t, err)
	require.Equal(t, S3WriteBusy, gate)
	assert.Equal(t, int64(1), counter.count(), "contended PassS3WriteGate must take 1 round trip")

	require.NoError(t, holder.Rollback(ctx))

	// 2. PassS3WriteGate (open gate immediately after busy gate) -> 1 round trip.
	counter.reset()
	gate, err = countedDB.PassS3WriteGate(ctx, pendingID, accountID, hash, gateTestOwner, gateTestLease)
	require.NoError(t, err)
	require.Equal(t, S3WriteOpen, gate)
	assert.Equal(t, int64(1), counter.count(), "open PassS3WriteGate must take 1 round trip (with warm cache intact)")

	// 3. CompleteLeasedS3Upload inside caller's transaction -> 4 round trips
	//    (1 pipelined lock+intent batch + markS3Uploaded + unlease + dropFinishedPendingUpload).
	tx, err = countedDB.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	counter.reset()
	err = countedDB.CompleteLeasedS3Upload(ctx, tx, pendingID, gateTestOwner, hash, accountID,
		[]string{"example.com/rtuser/" + hash})
	require.NoError(t, err)
	assert.Equal(t, int64(4), counter.count(), "CompleteLeasedS3Upload inside caller tx must take 4 round trips")
	require.NoError(t, tx.Commit(ctx))

	// 4. CompleteS3Upload inside caller's transaction -> 4 round trips.
	hashDirect := fmt.Sprintf("rt_direct_%d", time.Now().UnixNano())
	insertKeyedMessage(t, baseDB, accountID, mailboxID, 9004, hashDirect, "rtuser", false, time.Time{})
	_ = createPendingUpload(t, baseDB, accountID, "rt-node", hashDirect, 0, time.Time{}, 100)

	tx2, err := countedDB.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	counter.reset()
	err = countedDB.CompleteS3Upload(ctx, tx2, hashDirect, accountID,
		[]string{"example.com/rtuser/" + hashDirect})
	require.NoError(t, err)
	assert.Equal(t, int64(4), counter.count(), "CompleteS3Upload inside caller tx must take 4 round trips")
	require.NoError(t, tx2.Commit(ctx))

	// 5. Quarantined body and abandoned row also stay 1 round trip in PassS3WriteGate.
	quarantineHash := fmt.Sprintf("rt_quarantine_%d", time.Now().UnixNano())
	quarantinePending := createPendingUpload(t, baseDB, accountID, "rt-node", quarantineHash, 0, time.Time{}, 100)
	_, err = baseDB.GetWritePool().Exec(ctx, `
		INSERT INTO s3_body_delete_intents (content_hash, operation_id, object_keys, retire_snapshot)
		VALUES ($1, $2::uuid, ARRAY['example.com/rtuser/' || $1], '[]'::jsonb)
	`, quarantineHash, uuid.NewString())
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = baseDB.GetWritePool().Exec(ctx, `DELETE FROM s3_body_delete_intents WHERE content_hash = $1`, quarantineHash)
	})

	counter.reset()
	gate, err = countedDB.PassS3WriteGate(ctx, quarantinePending, accountID, quarantineHash, gateTestOwner, gateTestLease)
	require.NoError(t, err)
	require.Equal(t, S3WriteBusy, gate)
	assert.Equal(t, int64(1), counter.count(), "quarantined PassS3WriteGate must take 1 round trip")

	counter.reset()
	gate, err = countedDB.PassS3WriteGate(ctx, -999999, accountID, hash, gateTestOwner, gateTestLease)
	require.NoError(t, err)
	require.Equal(t, S3WriteAbandoned, gate)
	assert.Equal(t, int64(1), counter.count(), "abandoned PassS3WriteGate must take 1 round trip")

	// 6. CompleteLeasedS3Upload rejects non-READ COMMITTED transactions with ErrS3BodyQuarantined.
	rrTx, err := countedDB.GetWritePool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	require.NoError(t, err)
	defer rrTx.Rollback(ctx)
	err = countedDB.CompleteLeasedS3Upload(ctx, rrTx, pendingID, gateTestOwner, hash, accountID, nil)
	require.ErrorIs(t, err, ErrS3BodyQuarantined)
}
