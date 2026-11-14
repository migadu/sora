//go:build integration

package resilient

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// A dedicated read pool only keeps writes from starving reads on a host that serves
// both. A read replica takes no writes, and with [database.read] configured the write
// hosts take no reads, so each of those hosts gets one pool, sized by max_connections.
func TestCreateDatabasePool_OnePoolPerHostUnlessItServesReadsAndWrites(t *testing.T) {
	base := testDatabaseConfig()
	migrateTestDatabase(t, base)
	ctx := context.Background()
	host := base.Write.Hosts[0]

	withRead := *base
	withRead.Read = base.Write

	cases := []struct {
		name          string
		cfg           *config.DatabaseConfig
		endpoint      *config.DatabaseEndpointConfig
		poolType      string
		dedicatedRead bool
	}{
		{"write host without [database.read]", base, base.Write, "write", true},
		{"write host with [database.read]", &withRead, withRead.Write, "write", false},
		{"read replica", &withRead, withRead.Read, "read", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			database, err := createDatabasePool(ctx, host, tc.cfg, tc.endpoint, tc.poolType, false)
			if err != nil {
				t.Fatalf("createDatabasePool: %v", err)
			}
			defer database.Close()

			if got := database.ReadPool != database.WritePool; got != tc.dedicatedRead {
				t.Fatalf("separate read pool opened = %v, want %v", got, tc.dedicatedRead)
			}
		})
	}
}

func newSizedTestPool(t *testing.T, cfg *config.DatabaseConfig, maxConns int32) *pgxpool.Pool {
	t.Helper()
	endpoint := cfg.Write
	poolCfg, err := pgxpool.ParseConfig(fmt.Sprintf("postgres://%s@%s:%s/%s?sslmode=disable",
		endpoint.User, endpoint.Hosts[0], endpoint.Port, endpoint.Name))
	if err != nil {
		t.Fatalf("parse pool config: %v", err)
	}
	poolCfg.MaxConns = maxConns
	pool, err := pgxpool.NewWithConfig(context.Background(), poolCfg)
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// Without [database.read] the reads run on the write host's dedicated read pool. The
// role="read" pool gauges and the exhaustion check must see it.
func TestPoolMetrics_CoverTheWriteHostsReadPool(t *testing.T) {
	cfg := testDatabaseConfig()
	migrateTestDatabase(t, cfg)
	ctx := context.Background()

	writePool := newSizedTestPool(t, cfg, 2)
	readPool := newSizedTestPool(t, cfg, 2)
	dbPool := &DatabasePool{database: &db.Database{WritePool: writePool, ReadPool: readPool}, host: "localhost"}
	dbPool.isHealthy.Store(true)
	pools := []*DatabasePool{dbPool}
	rd := &ResilientDatabase{
		failoverManager: &RuntimeFailoverManager{
			// No replicas: newRuntimeFailoverManager points readPools at writePools.
			writePools:      pools,
			readPools:       pools,
			config:          cfg,
			healthCheckStop: make(chan struct{}),
		},
		config: cfg,
	}

	// Exhaust the read pool: every connection acquired.
	for i := 0; i < 2; i++ {
		conn, err := readPool.Acquire(ctx)
		if err != nil {
			t.Fatalf("acquire read connection: %v", err)
		}
		defer conn.Release()
	}

	rd.collectAggregatedPoolStats()
	if got := testutil.ToFloat64(metrics.DBPoolInUseConns.WithLabelValues("read")); got != 2 {
		t.Errorf("sora_db_pool_in_use_conns{role=read} = %v, want 2 (the reads' pool is not reported)", got)
	}
	if got := testutil.ToFloat64(metrics.DBPoolTotalConns.WithLabelValues("read")); got != 2 {
		t.Errorf("sora_db_pool_total_conns{role=read} = %v, want 2", got)
	}

	before := testutil.ToFloat64(metrics.DBPoolExhaustion.WithLabelValues("read"))
	rd.monitorAggregatedPoolHealth()
	if got := testutil.ToFloat64(metrics.DBPoolExhaustion.WithLabelValues("read")) - before; got != 1 {
		t.Errorf("sora_db_pool_exhaustion_total{role=read} grew by %v, want 1 (the exhausted reads' pool is not checked)", got)
	}
	if got := testutil.ToFloat64(metrics.DBPoolInUseConns.WithLabelValues("read")); got != 2 {
		t.Errorf("after the health monitor, sora_db_pool_in_use_conns{role=read} = %v, want 2", got)
	}
}
