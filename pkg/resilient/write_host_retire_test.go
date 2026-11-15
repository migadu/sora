package resilient

import (
	"context"
	"io"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The failover looks for a healthy write host starting after the current one, and its
// last candidate is the current host itself. When every other host is down and the
// current one turns healthy again while it looks (the health check flips it
// concurrently), that candidate is no switch at all. Taken for one, it reinstated and
// then retired the host that stays the writer, and every lock transaction on it was
// refused from then on: no cleanup cycle, account purge or cross-account COPY on this
// node until a restart, since with one write host nothing ever switches back.
func TestGetHealthyDatabaseWithFailover_RecoveringWriterIsNotRetired(t *testing.T) {
	prev := logger.Swap(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { logger.Swap(prev) })

	// Never dialled: BeginAdvisoryLockTx only has to get past its fence to reach it.
	pool, err := pgxpool.New(context.Background(), "postgres://nobody@127.0.0.1:1/none")
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	only := &DatabasePool{database: &db.Database{WritePool: pool}, host: "pg.example.com"}
	only.isHealthy.Store(true)
	rd := &ResilientDatabase{failoverManager: &RuntimeFailoverManager{writePools: []*DatabasePool{only}}}

	// The health check marks the only write host down and up again while write
	// operations keep asking for it.
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			only.isHealthy.Store(false)
			only.isHealthy.Store(true)
		}
	}()
	for w := 0; w < runtime.GOMAXPROCS(0)+1; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				rd.getHealthyDatabaseWithFailover(true)
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	stop.Store(true)
	wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = only.database.BeginAdvisoryLockTx(ctx)
	require.Error(t, err, "the pool is never dialled")
	assert.NotErrorIs(t, err, db.ErrAdvisoryLocksFenced,
		"the only write host, still the writer, refuses lock transactions")
}
