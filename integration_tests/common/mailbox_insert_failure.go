//go:build integration

package common

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/migadu/sora/pkg/resilient"
	"github.com/stretchr/testify/require"
)

// FailMailboxInserts keeps the target resolvable but fails its INSERT. The caller
// defers the returned cleanup before closing its database and removes the failure
// before retrying. Other mailboxes remain writable, so preceding copies really store.
func FailMailboxInserts(t *testing.T, rdb *resilient.ResilientDatabase, mailboxID int64) func() {
	t.Helper()
	ctx := context.Background()
	name := fmt.Sprintf("test_fail_mailbox_insert_%d", mailboxID)
	_, err := rdb.ExecWithRetry(ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'forced mailbox insert failure'; RETURN NEW; END $$`, name))
	require.NoError(t, err)
	_, err = rdb.ExecWithRetry(ctx, fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON messages FOR EACH ROW WHEN (NEW.mailbox_id = %d) EXECUTE FUNCTION %s()`, name, mailboxID, name))
	require.NoError(t, err)
	var once sync.Once
	return func() {
		once.Do(func() {
			_, err := rdb.ExecWithRetry(ctx, "DROP TRIGGER IF EXISTS "+name+" ON messages")
			require.NoError(t, err)
			_, err = rdb.ExecWithRetry(ctx, "DROP FUNCTION IF EXISTS "+name+"()")
			require.NoError(t, err)
		})
	}
}
