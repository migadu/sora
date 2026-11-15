//go:build integration

package resilient

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/stretchr/testify/require"
)

// snapshotConnectionTrace exposes the connection already checked out by this
// callback so the test can terminate only its own PostgreSQL backend.
type snapshotConnectionTrace struct{ conn atomic.Pointer[pgx.Conn] }

func (tr *snapshotConnectionTrace) TraceQueryStart(ctx context.Context, c *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	tr.conn.Store(c)
	return ctx
}
func (*snapshotConnectionTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestInReadSnapshotRollbackFailureCountsAsDatabaseFailure(t *testing.T) {
	cfg := testDatabaseConfig()
	admin := newTestPool(t, cfg, nil)
	f := newCopyFixture(t, admin, 0)
	tr := &snapshotConnectionTrace{}
	pc := admin.Config().Copy()
	pc.MaxConns = 1
	pc.ConnConfig.Tracer = tr
	pool, err := pgxpool.NewWithConfig(context.Background(), pc)
	require.NoError(t, err)
	defer pool.Close()
	rd := newTestResilientDatabase(cfg, pool)
	settings := circuitbreaker.DefaultSettings("snapshot-rollback")
	settings.IsSuccessful = isBreakerSuccess
	rd.queryBreaker = circuitbreaker.NewCircuitBreaker(settings)
	err = rd.InReadSnapshotWithRetry(context.Background(), func(sc context.Context) error {
		_, err := rd.GetMailboxSummaryWithRetry(sc, f.srcID)
		if err != nil {
			return err
		}
		c := tr.conn.Load()
		require.NotNil(t, c)
		nonfatal, fatal := rd.OptionalReadInSnapshot(sc, func(oc context.Context) error {
			var n int
			statementErr := c.QueryRow(oc, "SELECT 1/0").Scan(&n)
			var pe *pgconn.PgError
			require.ErrorAs(t, statementErr, &pe)
			require.Equal(t, "22012", pe.Code)
			var killed bool
			require.NoError(t, admin.QueryRow(context.Background(), "SELECT pg_terminate_backend($1)", c.PgConn().PID()).Scan(&killed))
			require.True(t, killed)
			return statementErr
		})
		require.NoError(t, nonfatal)
		return fatal
	})
	require.Error(t, err)
	require.ErrorIs(t, err, db.ErrReadSnapshotAborted)
	t.Logf("actual error=%v breaker=%+v", err, rd.queryBreaker.Counts())
	require.True(t, isDatabaseFailure(err), "original statement error must not hide the lost connection")
	require.Equal(t, uint32(1), rd.queryBreaker.Counts().TotalFailures)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer c.Release()
	var one int
	require.NoError(t, c.QueryRow(ctx, "SELECT 1").Scan(&one))
}
