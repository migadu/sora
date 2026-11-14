package resilient

import (
	"testing"

	"github.com/migadu/sora/db"
)

// When every read replica is unhealthy at runtime, reads must move to a healthy write
// pool (as startup does when every replica is down) instead of staying on the failed
// replica until it comes back.
func TestGetHealthyDatabaseWithFailover_ReadsFallBackToWritePool(t *testing.T) {
	newPool := func(host string, healthy bool) *DatabasePool {
		p := &DatabasePool{database: &db.Database{}, host: host}
		p.isHealthy.Store(healthy)
		return p
	}
	primary := newPool("primary.example.com", true)
	replica := newPool("replica.example.com", false)

	rd := &ResilientDatabase{failoverManager: &RuntimeFailoverManager{
		writePools:      []*DatabasePool{primary},
		readPools:       []*DatabasePool{replica},
		healthCheckStop: make(chan struct{}),
	}}

	if got := rd.getHealthyDatabaseWithFailover(false); got != primary.database {
		t.Fatalf("reads with every replica down went to %s, want the healthy write pool",
			hostOf(rd, got))
	}

	// Once the replica is healthy again, reads return to it.
	replica.isHealthy.Store(true)
	if got := rd.getHealthyDatabaseWithFailover(false); got != replica.database {
		t.Fatalf("reads with the replica healthy again went to %s, want the replica", hostOf(rd, got))
	}

	// With the write pool down too there is nothing better than the current replica.
	replica.isHealthy.Store(false)
	primary.isHealthy.Store(false)
	if got := rd.getHealthyDatabaseWithFailover(false); got != replica.database {
		t.Fatalf("reads with every pool down went to %s, want the current replica as last resort", hostOf(rd, got))
	}
}

func hostOf(rd *ResilientDatabase, database *db.Database) string {
	for _, p := range append(append([]*DatabasePool{}, rd.failoverManager.writePools...), rd.failoverManager.readPools...) {
		if p.database == database {
			return p.host
		}
	}
	return "an unknown pool"
}
