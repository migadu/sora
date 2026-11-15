package main

import (
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

	importer, err := NewS3Importer(nil, nil, S3ImporterOptions{CleanupDB: true})
	require.NoError(t, err)
	assert.FileExists(t, importer.dbPath)
	assert.Equal(t, tmpDir, filepath.Dir(importer.dbPath))
	assert.Equal(t, []string{"a?b"}, dirNames(t, root), "the database was created outside TMPDIR")

	require.NoError(t, importer.Close())
	assert.Empty(t, dirNames(t, tmpDir), "--cleanup-db left the database behind")
	assert.Equal(t, []string{"a?b"}, dirNames(t, root))
}
