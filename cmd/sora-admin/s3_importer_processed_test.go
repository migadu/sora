package main

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// insertS3Objects records n objects under domain/localPart in si's work database, as
// scanS3Objects does, and sets the run's object count.
func insertS3Objects(t *testing.T, si *S3Importer, domain, localPart string, n int) {
	t.Helper()
	tx, err := si.db.Begin()
	require.NoError(t, err)
	for i := 0; i < n; i++ {
		hash := fmt.Sprintf("%064x", i)
		_, err := tx.Exec(`INSERT INTO s3_objects (key, size, last_modified, etag, domain, local_part, content_hash)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, domain+"/"+localPart+"/"+hash, 100, "2026-11-01T12:00:00Z", "etag",
			domain, localPart, hash)
		require.NoError(t, err)
	}
	require.NoError(t, tx.Commit())
	si.totalObjects = int64(n)
}

// Every object importFromS3 hands to a worker is marked processed in the work database,
// with its outcome, so a database kept with --cleanup-db=false says which objects were
// imported and why the others failed. The feeder kept its query's rows open for the
// whole run while the workers wrote: on the default rollback journal that read holds the
// SHARED lock a worker's UPDATE must see released to commit, and with no busy timeout
// nearly every update failed with SQLITE_BUSY. A failed object was not marked at all.
//
// The workers' updates must not pile up in the write-ahead log either: a read held open
// across the run keeps the checkpointer from ever resetting the log, which then grows by
// at least a page per object in the temporary directory.
func TestS3ImporterMarksEveryObjectProcessed(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	si, err := NewS3Importer(context.Background(), nil, nil, S3ImporterOptions{Email: "user@example.com", Workers: 5, CleanupDB: true})
	require.NoError(t, err)
	defer si.Close()

	// Objects under another user's prefix fail in importS3Object before it reaches the
	// database or S3, so the run needs neither past the account Run looks up first.
	si.rdb = &s3ImportTestDB{}
	require.NoError(t, si.lookupAccount())
	const n = 2000
	insertS3Objects(t, si, "example.org", "other", n)
	// Empty the WAL of the inserts, so that it holds only the run's updates.
	_, err = si.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	require.NoError(t, err)

	require.NoError(t, si.importFromS3())

	var unprocessed, marked int
	require.NoError(t, si.db.QueryRow(`SELECT COUNT(*) FROM s3_objects WHERE NOT processed`).Scan(&unprocessed))
	require.NoError(t, si.db.QueryRow(`SELECT COUNT(*) FROM s3_objects WHERE processed AND NOT success
		AND error_message LIKE '%is not under the prefix of user@example.com'`).Scan(&marked))
	assert.Zero(t, unprocessed, "objects left unprocessed")
	assert.Equal(t, n, marked, "objects marked processed with their failure")

	if info, err := os.Stat(si.dbPath + "-wal"); err == nil {
		var pageSize, autoCheckpoint int64
		require.NoError(t, si.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize))
		require.NoError(t, si.db.QueryRow(`PRAGMA wal_autocheckpoint`).Scan(&autoCheckpoint))
		assert.Less(t, info.Size(), 2*autoCheckpoint*pageSize,
			"the WAL grew past twice its auto-checkpoint size: the checkpointer never reset it")
	}
}
