package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The S3 importer's tracking database is a file in the temporary directory. A plain SQLite
// DSN is cut at its first '?', so a '?' in TMPDIR used to create the database outside it,
// at the path truncated there, and --cleanup-db then failed to remove a file that was
// never written.
func TestS3ImporterDatabaseStaysInTempDir(t *testing.T) {
	root := t.TempDir()
	tmpDir := filepath.Join(root, "a?b")
	require.NoError(t, os.Mkdir(tmpDir, 0700))
	t.Setenv("TMPDIR", tmpDir)

	importer, err := NewS3Importer(context.Background(), nil, nil, S3ImporterOptions{CleanupDB: true})
	require.NoError(t, err)
	assert.FileExists(t, importer.dbPath)
	assert.Equal(t, tmpDir, filepath.Dir(importer.dbPath))
	assert.Equal(t, []string{"a?b"}, dirNames(t, root), "the database was created outside TMPDIR")

	require.NoError(t, importer.Close())
	assert.Empty(t, dirNames(t, tmpDir), "--cleanup-db left the database behind")
	assert.Equal(t, []string{"a?b"}, dirNames(t, root))
}

// Each `import s3` run tracks the objects its scan found in its own work database. The
// file used to be named after the current second, so two runs started in the same
// second (a script importing several users in parallel) opened the same file, and each
// imported the other's scanned objects into its own account. The file sits in a shared
// temporary directory, so it is also created exclusively and readable by its owner only.
func TestS3ImporterRunsDoNotShareDatabase(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)

	first, err := NewS3Importer(context.Background(), nil, nil, S3ImporterOptions{CleanupDB: true})
	require.NoError(t, err)
	defer first.Close()
	_, err = first.db.Exec(`INSERT INTO s3_objects (key, size, last_modified, etag, domain, local_part, content_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, "example.com/a/hash", 100, "2026-11-01T12:00:00Z", "etag",
		"example.com", "a", "hash")
	require.NoError(t, err)

	second, err := NewS3Importer(context.Background(), nil, nil, S3ImporterOptions{CleanupDB: true})
	require.NoError(t, err)
	defer second.Close()

	assert.NotEqual(t, first.dbPath, second.dbPath, "two runs opened the same work database")
	var rows int
	require.NoError(t, second.db.QueryRow("SELECT COUNT(*) FROM s3_objects").Scan(&rows))
	assert.Zero(t, rows, "the second run sees the first run's objects")

	for _, si := range []*S3Importer{first, second} {
		info, err := os.Stat(si.dbPath)
		require.NoError(t, err)
		assert.Equal(t, "-rw-------", info.Mode().Perm().String(), "work database %s", si.dbPath)
	}
}
