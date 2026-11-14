//go:build integration

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deleteUnderCleanerLock runs the cleaner's delete of obj: it takes the body's S3 object
// lock, confirms the body is an orphan, and only then runs claim, an import that brings
// the body back. It runs del, the DELETE, once claim has either finished or is waiting
// for the lock, and returns claim's result. An import that does not take the lock thus
// lands between the cleaner's re-check and its DELETE.
func deleteUnderCleanerLock(t *testing.T, f *rekeyFixture, obj db.UserScopedObjectForCleanup, del func() error, claim func() error) error {
	t.Helper()
	pool := f.rdb.GetOperationalDatabase().GetWritePool()
	lockID := uint64(db.GetS3ObjectLockID(obj.AccountID, obj.ContentHash))
	done := make(chan error, 1)
	var claimErr error
	finished := false

	err := f.rdb.ExecuteWithLockedS3Orphans(f.ctx, []db.UserScopedObjectForCleanup{obj}, time.Hour,
		func(ctx context.Context, orphans []db.UserScopedObjectForCleanup) error {
			require.Len(t, orphans, 1, "precondition: the cleaner confirms the body as an orphan before the import")
			go func() { done <- claim() }()

			deadline := time.After(30 * time.Second)
			for !finished {
				var waiting bool
				require.NoError(t, pool.QueryRow(ctx, `
					SELECT EXISTS (SELECT 1 FROM pg_locks
					               WHERE locktype = 'advisory' AND NOT granted
					                 AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
					                 AND classid = $1::bigint::oid AND objid = $2::bigint::oid AND objsubid = 1)`,
					int64(lockID>>32), int64(lockID&0xffffffff)).Scan(&waiting))
				if waiting {
					break
				}
				select {
				case claimErr = <-done:
					finished = true
				case <-deadline:
					t.Fatal("the import neither finished nor waited for the body's S3 object lock")
				case <-time.After(10 * time.Millisecond):
				}
			}
			return del()
		})
	require.NoError(t, err)
	if !finished {
		claimErr = <-done
	}
	return claimErr
}

// expungedCandidate gives accountID a message of body that was expunged long ago, so
// that its body is a cleaner candidate, and returns the cleaner's view of the body.
func expungedCandidate(f *rekeyFixture, accountID int64, domain, localpart string, body []byte) db.UserScopedObjectForCleanup {
	hash := helpers.HashContent(body)
	row := f.insert(accountID, "INBOX", domain, localpart, hash, body, "expunged-"+hash[:16])
	f.exec(`UPDATE messages SET expunged_at = now() - interval '30 days' WHERE id = $1`, row)
	return db.UserScopedObjectForCleanup{AccountID: accountID, ContentHash: hash, S3Domain: domain, S3Localpart: localpart}
}

// liveRows counts accountID's live rows of hash, and of those the ones marked uploaded.
func liveRows(t *testing.T, f *rekeyFixture, accountID int64, hash string) (live, uploaded int) {
	t.Helper()
	require.NoError(t, f.rdb.GetOperationalDatabase().GetWritePool().QueryRow(f.ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE uploaded)
		FROM messages WHERE account_id = $1 AND content_hash = $2 AND expunged_at IS NULL`,
		accountID, hash).Scan(&live, &uploaded))
	return live, uploaded
}

// TestImportMaildirWaitsForCleanerDeleteOfBody (#788): the user deleted a message, and
// after the grace period the cleaner confirms its body as an orphan. An admin imports a
// maildir holding the same message back into the account in the meantime. The import
// writes the body and inserts a row marked uploaded; if it does so between the cleaner's
// re-check and its DELETE, the DELETE removes the body under the imported row.
func TestImportMaildirWaitsForCleanerDeleteOfBody(t *testing.T) {
	for _, mode := range []struct {
		name  string
		batch bool
	}{{"individual transactions", false}, {"batch transaction", true}} {
		t.Run(mode.name, func(t *testing.T) {
			f := newRekeyFixture(t)
			name := "import-maildir"
			if mode.batch {
				name += "-batch"
			}
			accountID, domain, localpart := f.account(name)
			body := f.body(name)
			obj := expungedCandidate(f, accountID, domain, localpart, body)
			key := helpers.NewS3Key(domain, localpart, obj.ContentHash)
			f.put(key, body)

			maildir := filepath.Join(t.TempDir(), "Maildir")
			for _, dir := range []string{"cur", "new", "tmp"} {
				require.NoError(t, os.MkdirAll(filepath.Join(maildir, dir), 0o755))
			}
			require.NoError(t, os.WriteFile(filepath.Join(maildir, "cur", "1700000001.M1P1.host:2,S"), body, 0o644))
			importer, err := NewImporter(f.ctx, maildir, localpart+"@"+domain, 1, f.rdb, f.store,
				ImporterOptions{BatchTransactionMode: mode.batch})
			require.NoError(t, err)
			t.Cleanup(func() { importer.Close() })

			err = deleteUnderCleanerLock(t, f, obj, func() error { return f.store.Delete(key) }, importer.Run)
			require.NoError(t, err, "import maildir")

			live, uploaded := liveRows(t, f, accountID, obj.ContentHash)
			require.Equal(t, 1, live, "the import brings the message back")
			assert.Equal(t, 1, uploaded)
			_, stored := f.stored(key)
			assert.True(t, stored, "the cleaner's DELETE removed the body the import had just written: the imported row is marked uploaded with no object behind it")
		})
	}
}

// TestImportS3WaitsForCleanerDeleteOfBody (#788) is the same race for `import s3`, which
// makes a row point at a body that is already stored and marks it uploaded at once. A
// body the cleaner deletes after its import read it must not end up under a row marked
// uploaded; once the DELETE is over, the object is gone and there is nothing to import.
func TestImportS3WaitsForCleanerDeleteOfBody(t *testing.T) {
	f := newRekeyFixture(t)
	accountID, domain, localpart := f.account("import-s3")
	body := f.body("import-s3")
	obj := expungedCandidate(f, accountID, domain, localpart, body)
	key := helpers.NewS3Key(domain, localpart, obj.ContentHash)

	fake, s3storage := common.NewFakeS3Storage(t)
	require.NoError(t, s3storage.Put(key, bytes.NewReader(body), int64(len(body))))
	importer, err := NewS3Importer(f.rdb, s3storage, S3ImporterOptions{
		Email:      localpart + "@" + domain,
		Workers:    1,
		BatchSize:  1,
		InstanceID: "import-s3-lock-test",
	})
	require.NoError(t, err)
	t.Cleanup(func() { importer.Close() })

	err = deleteUnderCleanerLock(t, f, obj, func() error { return s3storage.Delete(key) }, func() error {
		return importer.importS3Object(S3ObjectInfo{Key: key, Size: int64(len(body))})
	})

	live, uploaded := liveRows(t, f, accountID, obj.ContentHash)
	require.Empty(t, fake.Keys(key), "the cleaner deleted the body")
	assert.Zero(t, uploaded, "the imported row is marked uploaded, but the cleaner's DELETE removed its body")
	assert.Zero(t, live, "a row was imported for a body that is gone")
	assert.Error(t, err, "the import reported success for a body that is gone")
}
