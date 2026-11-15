package cache

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// busy_timeout is a setting of one SQLite connection, and each shard index's *sql.DB is a
// pool: set by an Exec after sql.Open it configured only the connection that ran it, and
// every further connection the pool opened (PurgeOrphanedContentHashes still iterates its
// rows when a Put on the shard takes another one) failed at once on a lock, such as
// sora-admin's cache purge, instead of waiting.
func TestEveryPooledShardConnectionHasBusyTimeout(t *testing.T) {
	c, _ := newTestCache(t, 1024*NumShards, 1024)
	ctx := context.Background()
	var wrong []string
	for i, shard := range c.shards {
		var conns []*sql.Conn
		for n := 1; n <= 2; n++ {
			conn, err := shard.db.Conn(ctx) // the earlier one is still held: a new connection
			require.NoError(t, err)
			conns = append(conns, conn)
			var busyTimeout int
			require.NoError(t, conn.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busyTimeout))
			if busyTimeout != 5000 {
				wrong = append(wrong, fmt.Sprintf("shard %02x connection %d: busy_timeout=%d", i, n, busyTimeout))
			}
		}
		for _, conn := range conns {
			conn.Close()
		}
	}
	if len(wrong) > 0 {
		t.Errorf("%d of %d shard connections lack busy_timeout=5000, first: %s", len(wrong), 2*NumShards, wrong[0])
	}
}
