//go:build integration

package resilient

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// With every replica down at startup, reads use the write pools. When a replica
// reconnects, reads move to it, and from then on the read pools are the replicas: they
// are health-checked and reported as such. That must not depend on whether the write
// pool slice happens to have spare capacity (three write hosts: length 3, capacity 4).
func TestReconnectedReplicaMakesReadPoolsDistinct(t *testing.T) {
	base := testDatabaseConfig()
	migrateTestDatabase(t, base)
	ctx := context.Background()

	write := *base.Write
	write.Hosts = []string{"localhost", "127.0.0.1", "localhost:5432"} // three names, one server
	read := *base.Write
	read.Hosts = []string{"127.0.0.1:1"} // down at startup: nothing listens on port 1
	cfg := &config.DatabaseConfig{Write: &write, Read: &read}

	manager, err := newRuntimeFailoverManager(ctx, cfg, false, false)
	if err != nil {
		t.Fatalf("newRuntimeFailoverManager: %v", err)
	}
	defer func() {
		for _, p := range append(manager.writePools, manager.readPools...) {
			p.database.Close()
		}
	}()
	if len(manager.writePools) != 3 || manager.readPoolsAreDistinct() {
		t.Fatalf("setup: %d write pools, read pools distinct %v; want 3 write pools serving reads",
			len(manager.writePools), manager.readPoolsAreDistinct())
	}

	// The replica comes back.
	for _, f := range manager.failedHosts {
		f.host = "localhost"
		f.lastAttempt = time.Now().Add(-time.Hour)
	}
	rd := &ResilientDatabase{failoverManager: manager, config: cfg}
	rd.attemptReconnectFailedHosts(ctx)

	if !manager.readPoolsAreDistinct() {
		t.Fatalf("reads moved to the reconnected replica, but the read pools are still taken for the write pools "+
			"(write pools: len %d cap %d); the replica is neither health-checked nor reported as a read pool",
			len(manager.writePools), cap(manager.writePools))
	}
	if len(manager.readPools) != 1 || manager.readPools[0].host != "localhost" {
		t.Fatalf("read pools after the replica reconnected: %d, want just the replica", len(manager.readPools))
	}
	if len(manager.writePools) != 3 {
		t.Fatalf("write pools changed to %d", len(manager.writePools))
	}
}
