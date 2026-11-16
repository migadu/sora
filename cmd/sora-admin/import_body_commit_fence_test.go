//go:build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/stretchr/testify/require"
)

// A replacement DELETE may finish and clear its intent before a stale importer
// resumes its SQL write. An inner lock alone cannot prove the earlier GET survived
// that interval; the old holder must still be valid when the inner lock overlaps it.
func TestS3ImportRefusesStaleReadAfterHolderLossAndCompletedDelete(t *testing.T) {
	f := newRekeyFixture(t)
	ctx := context.Background()
	account, domain, local := f.account("commit-fence")
	body := f.body("commit-fence")
	hash := helpers.HashContent(body)
	key := helpers.NewS3Key(domain, local, hash)
	fake, st := common.NewFakeS3Storage(t)
	require.NoError(t, st.PutContext(ctx, key, bytes.NewReader(body), int64(len(body))))
	si, err := NewS3Importer(ctx, f.rdb, st, S3ImporterOptions{Email: local + "@" + domain, Workers: 1, BatchSize: 1, InstanceID: "commit-fence"})
	require.NoError(t, err)
	defer si.Close()
	require.NoError(t, si.lookupAccount())
	// Pause at the application's DB call boundary after the importer has made
	// its WithoutCancel completion context. The delegated operation below still
	// executes all real PostgreSQL admission/insert/finalize code unchanged.
	ready, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	si.rdb = &pausedBodyCommitDB{ResilientDatabase: f.rdb, before: func() { close(ready); <-release }}
	done := make(chan error, 1)
	go func() { done <- si.importS3Object(S3ObjectInfo{Key: key}) }()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("actual S3 GET did not reach the completion call boundary")
	}
	pool := f.rdb.GetOperationalDatabase().GetWritePool()
	id := uint64(db.GetS3ObjectLockID(account, hash))
	var outerPID int
	require.NoError(t, pool.QueryRow(ctx, `SELECT pid FROM pg_locks WHERE locktype='advisory' AND granted AND mode='ShareLock' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=$1::bigint::oid AND objid=$2::bigint::oid AND objsubid=1`, int64(id>>32), int64(id&0xffffffff)).Scan(&outerPID))
	var killed bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT pg_terminate_backend($1)`, outerPID).Scan(&killed))
	require.True(t, killed)
	candidate := db.UserScopedObjectForCleanup{AccountID: 0, ContentHash: hash, S3Domain: domain, S3Localpart: local}
	_, err = f.rdb.ExecuteWithS3BodyCleanup(ctx, []db.UserScopedObjectForCleanup{candidate}, time.Hour, func(c context.Context, objects []db.UserScopedObjectForCleanup) (db.S3BodyCleanupResult, error) {
		require.Len(t, objects, 1)
		require.False(t, objects[0].KeepObject)
		if err := st.DeleteContext(c, key); err != nil {
			return db.S3BodyCleanupResult{}, err
		}
		return db.S3BodyCleanupResult{Gone: objects}, nil
	})
	require.NoError(t, err)
	require.Empty(t, fake.Keys(key), "replacement DELETE must have completed, not merely started")
	var intents int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM s3_body_delete_intents WHERE content_hash=$1`, hash).Scan(&intents))
	require.Zero(t, intents, "fixture must exercise the cleared-intent interval")
	unblock()
	select {
	case err = <-done:
		t.Logf("outerPG=%d import=%v", outerPID, err)
	case <-time.After(8 * time.Second):
		t.Fatal("import did not finish after completion call boundary released")
	}
	var uploaded int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM messages WHERE account_id=$1 AND content_hash=$2 AND uploaded`, account, hash).Scan(&uploaded))
	require.Zerof(t, uploaded, "stale S3 GET admitted %d uploaded rows after its holder died and a replacement DELETE completed", uploaded)
	require.Error(t, err, fmt.Sprintf("lost holder for %s must refuse stale completion", hash))
}

// This seam delays a call, never fabricates a database response or skips SQL.
type pausedBodyCommitDB struct {
	*resilient.ResilientDatabase
	before func()
}

func (d *pausedBodyCommitDB) InsertStoredMessageWithRetry(ctx context.Context, o *db.InsertMessageOptions, u db.PendingUpload, keys []string) (int64, int64, error) {
	d.before()
	return d.ResilientDatabase.InsertStoredMessageWithRetry(ctx, o, u, keys)
}

func TestS3ImportInnerWriteLockExcludesDeleteAndRollsBackLostCompletion(t *testing.T) {
	f := newRekeyFixture(t)
	ctx := context.Background()
	account, domain, local := f.account("commit-fence")
	body := f.body("commit-fence")
	hash := helpers.HashContent(body)
	key := helpers.NewS3Key(domain, local, hash)
	fake, st := common.NewFakeS3Storage(t)
	require.NoError(t, st.PutContext(ctx, key, bytes.NewReader(body), int64(len(body))))
	si, err := NewS3Importer(ctx, f.rdb, st, S3ImporterOptions{Email: local + "@" + domain, Workers: 1, BatchSize: 1, InstanceID: "commit-fence"})
	require.NoError(t, err)
	defer si.Close()
	require.NoError(t, si.lookupAccount())
	got, allow := make(chan struct{}), make(chan struct{})
	var once sync.Once
	releaseGet := func() { once.Do(func() { close(allow) }) }
	defer releaseGet()
	fake.OnGet(func(k string) {
		if k == key {
			close(got)
			<-allow
		}
	})
	done := make(chan error, 1)
	go func() { done <- si.importS3Object(S3ObjectInfo{Key: key}) }()
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("actual S3 GET did not begin under shared holder")
	}
	pool := f.rdb.GetOperationalDatabase().GetWritePool()
	hold, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer hold.Rollback(ctx)
	var holderPID int
	require.NoError(t, hold.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&holderPID))
	_, err = hold.Exec(ctx, `SELECT 1 FROM mailboxes WHERE account_id=$1 AND name='INBOX' FOR UPDATE`, account)
	require.NoError(t, err)
	releaseGet()
	require.Eventually(t, func() bool {
		var blocked bool
		err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, holderPID).Scan(&blocked)
		return err == nil && blocked
	}, 5*time.Second, 10*time.Millisecond, "import never reached its actual SQL write after GET")
	var writerPID int
	require.NoError(t, pool.QueryRow(ctx, `SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))`, holderPID).Scan(&writerPID))
	id := uint64(db.GetS3ObjectLockID(account, hash))
	var outerPID int
	require.NoError(t, pool.QueryRow(ctx, `SELECT pid FROM pg_locks WHERE locktype='advisory' AND granted AND mode='ShareLock' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=$1::bigint::oid AND objid=$2::bigint::oid AND objsubid=1 AND pid<>$3`, int64(id>>32), int64(id&0xffffffff), writerPID).Scan(&outerPID))
	var killed bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT pg_terminate_backend($1)`, outerPID).Scan(&killed))
	require.True(t, killed)
	candidate := db.UserScopedObjectForCleanup{AccountID: 0, ContentHash: hash, S3Domain: domain, S3Localpart: local}
	_, err = f.rdb.ExecuteWithS3BodyCleanup(ctx, []db.UserScopedObjectForCleanup{candidate}, time.Hour, func(c context.Context, objects []db.UserScopedObjectForCleanup) (db.S3BodyCleanupResult, error) {
		require.Empty(t, objects, "inner admission must retain its own global shared lock through commit")
		return db.S3BodyCleanupResult{}, nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, fake.Keys(key), "DELETE ran while an overlapped inner write transaction protected the body")
	var intents int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM s3_body_delete_intents WHERE content_hash=$1`, hash).Scan(&intents))
	require.Zero(t, intents, "fixture must exercise the cleared-intent interval")
	require.NoError(t, hold.Commit(ctx))
	select {
	case err = <-done:
		t.Logf("outerPG=%d blockedWriter=%d import=%v", outerPID, holderPID, err)
	case <-time.After(8 * time.Second):
		t.Fatal("import did not finish after SQL wait released")
	}
	var uploaded int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM messages WHERE account_id=$1 AND content_hash=$2 AND uploaded`, account, hash).Scan(&uploaded))
	require.Zero(t, uploaded)
	var allRows int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM messages WHERE account_id=$1 AND content_hash=$2`, account, hash).Scan(&allRows))
	require.Zero(t, allRows, "failed finalization left a spool-less pending message")
	require.Error(t, err, fmt.Sprintf("lost holder for %s must refuse stale completion", hash))
}

func TestS3ImportAdmittedCompletionSurvivesUserInterrupt(t *testing.T) {
	f := newRekeyFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	account, domain, local := f.account("admitted-interrupt")
	body := f.body("admitted-interrupt")
	hash := helpers.HashContent(body)
	key := helpers.NewS3Key(domain, local, hash)
	_, st := common.NewFakeS3Storage(t)
	require.NoError(t, st.PutContext(ctx, key, bytes.NewReader(body), int64(len(body))))
	si, err := NewS3Importer(ctx, f.rdb, st, S3ImporterOptions{Email: local + "@" + domain, Workers: 1, BatchSize: 1, InstanceID: "admitted-interrupt"})
	require.NoError(t, err)
	defer si.Close()
	require.NoError(t, si.lookupAccount())
	si.rdb = &pausedBodyCommitDB{ResilientDatabase: f.rdb, before: cancel}
	require.NoError(t, si.importS3Object(S3ObjectInfo{Key: key}), "the admitted atomic completion must not fail merely because the command context was canceled")
	var uploaded bool
	require.NoError(t, f.rdb.QueryRowWithRetry(context.Background(), `SELECT uploaded FROM messages WHERE account_id=$1 AND content_hash=$2`, account, hash).Scan(&uploaded))
	require.True(t, uploaded)
	require.EqualValues(t, 1, si.importedMessages)
}
