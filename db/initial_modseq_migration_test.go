package db

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestInitialModSeqMigrationLifecycle(t *testing.T) {
	d := setupTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	up, err := os.ReadFile("migrations/000071_message_state_initial_modseq.up.sql")
	require.NoError(t, err)
	down, err := os.ReadFile("migrations/000071_message_state_initial_modseq.down.sql")
	require.NoError(t, err)
	c, err := d.GetWritePool().Acquire(ctx)
	require.NoError(t, err)
	defer c.Release()
	schema := pgx.Identifier{fmt.Sprintf("initial_version_%d", time.Now().UnixNano())}.Sanitize()
	_, err = c.Exec(ctx, "CREATE SCHEMA "+schema+"; SET search_path="+schema)
	require.NoError(t, err)
	defer c.Exec(ctx, "RESET search_path; DROP SCHEMA "+schema+" CASCADE")
	_, err = c.Exec(ctx, `CREATE TABLE message_state(message_id bigint PRIMARY KEY,updated_modseq bigint); INSERT INTO message_state VALUES(1,10)`)
	require.NoError(t, err)
	var before string
	require.NoError(t, c.QueryRow(ctx, `SELECT ctid::text FROM message_state WHERE message_id=1`).Scan(&before))
	apply := func(src []byte) { t.Helper(); _, e := c.Exec(ctx, string(src)); require.NoError(t, e) }
	apply(up)
	apply(up)
	var after string
	var unknown bool
	require.NoError(t, c.QueryRow(ctx, `SELECT ctid::text,initial_modseq IS NULL FROM message_state WHERE message_id=1`).Scan(&after, &unknown))
	require.Equal(t, before, after, "migration does not rewrite or infer historical states")
	require.True(t, unknown)
	_, err = c.Exec(ctx, `UPDATE message_state SET updated_modseq=11,initial_modseq=11 WHERE message_id=1;
		INSERT INTO message_state(message_id,updated_modseq,initial_modseq) VALUES(2,20,999),(3,NULL,999);
		UPDATE message_state SET updated_modseq=21,initial_modseq=21 WHERE message_id=2;
		UPDATE message_state SET updated_modseq=31,initial_modseq=31 WHERE message_id=3`)
	require.NoError(t, err)
	var initial int64
	require.NoError(t, c.QueryRow(ctx, `SELECT initial_modseq IS NULL FROM message_state WHERE message_id=1`).Scan(&unknown))
	require.True(t, unknown, "legacy unknown survives UPDATE")
	require.NoError(t, c.QueryRow(ctx, `SELECT initial_modseq FROM message_state WHERE message_id=2`).Scan(&initial))
	require.Equal(t, int64(20), initial, "INSERT captures actual state, UPDATE cannot overwrite it")
	require.NoError(t, c.QueryRow(ctx, `SELECT initial_modseq IS NULL FROM message_state WHERE message_id=3`).Scan(&unknown))
	require.True(t, unknown, "NULL insertion is never guessed from a later version")
	apply(down)
	apply(down)
	var absent bool
	require.NoError(t, c.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='message_state'::regclass AND attname='initial_modseq' AND NOT attisdropped) AND to_regprocedure('preserve_message_state_initial_modseq()') IS NULL`).Scan(&absent))
	require.True(t, absent)
	apply(up)
	apply(up)
	var unknownCount int
	require.NoError(t, c.QueryRow(ctx, `SELECT count(*) FROM message_state WHERE initial_modseq IS NULL`).Scan(&unknownCount))
	require.Equal(t, 3, unknownCount, "down/up safely forgets knowledge instead of reconstructing it")
	_, err = c.Exec(ctx, `INSERT INTO message_state(message_id,updated_modseq) VALUES(4,40)`)
	require.NoError(t, err)
	require.NoError(t, c.QueryRow(ctx, `SELECT initial_modseq FROM message_state WHERE message_id=4`).Scan(&initial))
	require.Equal(t, int64(40), initial)
}

// A database prepared out-of-band must migrate without any lock on message_state, which every
// flag change writes. ADD COLUMN IF NOT EXISTS would lock it even with the column present.
func TestInitialModSeqMigrationPreparedTakesNoTableLock(t *testing.T) {
	d := setupTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	up, err := os.ReadFile("migrations/000071_message_state_initial_modseq.up.sql")
	require.NoError(t, err)
	c, err := d.GetWritePool().Acquire(ctx)
	require.NoError(t, err)
	defer c.Release()
	name := fmt.Sprintf("initial_version_lock_%d", time.Now().UnixNano())
	schema := pgx.Identifier{name}.Sanitize()
	_, err = c.Exec(ctx, "CREATE SCHEMA "+schema+"; SET search_path="+schema)
	require.NoError(t, err)
	defer c.Exec(ctx, "RESET search_path; DROP SCHEMA "+schema+" CASCADE")
	_, err = c.Exec(ctx, `CREATE TABLE message_state(message_id bigint PRIMARY KEY, updated_modseq bigint)`)
	require.NoError(t, err)
	_, err = c.Exec(ctx, string(up))
	require.NoError(t, err)

	locker, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = locker.Exec(ctx, "LOCK TABLE "+pgx.Identifier{name, "message_state"}.Sanitize()+" IN ACCESS EXCLUSIVE MODE")
	require.NoError(t, err)
	_, err = c.Exec(ctx, "SET lock_timeout = '200ms'")
	require.NoError(t, err)
	_, err = c.Exec(ctx, string(up))
	_, _ = c.Exec(ctx, "RESET lock_timeout")
	require.NoError(t, locker.Rollback(ctx))
	require.NoError(t, err, "the prepared migration must only inspect catalogs, even with message_state exclusively locked")
}

// A same-named trigger that does not call preserve_message_state_initial_modseq is replaced.
func TestInitialModSeqMigrationReplacesForeignTrigger(t *testing.T) {
	d := setupTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	up, err := os.ReadFile("migrations/000071_message_state_initial_modseq.up.sql")
	require.NoError(t, err)
	c, err := d.GetWritePool().Acquire(ctx)
	require.NoError(t, err)
	defer c.Release()
	schema := pgx.Identifier{fmt.Sprintf("initial_version_foreign_%d", time.Now().UnixNano())}.Sanitize()
	_, err = c.Exec(ctx, "CREATE SCHEMA "+schema+"; SET search_path="+schema)
	require.NoError(t, err)
	defer c.Exec(ctx, "RESET search_path; DROP SCHEMA "+schema+" CASCADE")
	_, err = c.Exec(ctx, `CREATE TABLE message_state(message_id bigint PRIMARY KEY, updated_modseq bigint, initial_modseq bigint);
		CREATE FUNCTION foreign_state_trigger() RETURNS TRIGGER AS $$ BEGIN RETURN NEW; END; $$ LANGUAGE plpgsql;
		CREATE TRIGGER trigger_message_state_initial_modseq BEFORE INSERT OR UPDATE ON message_state
			FOR EACH ROW EXECUTE FUNCTION foreign_state_trigger()`)
	require.NoError(t, err)
	_, err = c.Exec(ctx, string(up))
	require.NoError(t, err)
	_, err = c.Exec(ctx, `INSERT INTO message_state(message_id, updated_modseq) VALUES (1, 10)`)
	require.NoError(t, err)
	var initial int64
	require.NoError(t, c.QueryRow(ctx, `SELECT initial_modseq FROM message_state WHERE message_id = 1`).Scan(&initial))
	require.Equal(t, int64(10), initial, "the foreign trigger must have been replaced by the migration's")
}
