package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SQLite's unix VFS resolves every symbolic link in a database's name and opens the
// file by the resolved path; /proc/self/fd/N, through which the cache is opened on
// Linux, is such a link, to the directory's path. maildirCacheVFS opens the name as
// it is given: here a link on the way stays in the name SQLite reports, and the
// cache, its -wal and its -shm are still created where the kernel resolves it.
func TestMaildirCacheVFSOpensTheNameItIsGiven(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	real := filepath.Join(base, "real")
	require.NoError(t, os.Mkdir(real, 0755))
	link := filepath.Join(base, "link")
	require.NoError(t, os.Symlink(real, link))
	path := filepath.Join(link, maildirCacheName)
	require.NoError(t, os.WriteFile(path, nil, 0644))

	cache, err := openMaildirCacheFile(path, nil)
	require.NoError(t, err)
	defer cache.Close()
	_, err = cache.Exec(`CREATE TABLE proof (n INTEGER)`)
	require.NoError(t, err)

	assert.Equal(t, path, mainDatabaseName(t, cache), "SQLite resolved the name it was given")
	assert.FileExists(t, filepath.Join(real, maildirCacheName+"-wal"))
	assert.FileExists(t, filepath.Join(real, maildirCacheName+"-shm"))
}

// On Linux the cache is opened through the descriptor of the directory that was
// checked, so the name keeps leading there however the directory is renamed after.
func TestMaildirCacheOpensThroughTheDirectoryDescriptorOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only Linux names a directory's entries through its descriptor (/proc/self/fd)")
	}
	maildirPath := newMaildirWith(t, nil)
	victim := newMaildirWith(t, nil)
	require.NoError(t, os.WriteFile(filepath.Join(victim, maildirCacheName), nil, 0644))
	root, err := openImportRoot(maildirPath)
	require.NoError(t, err)
	defer root.Close()

	cache, err := openMaildirCache(root)
	require.NoError(t, err)
	defer cache.Close()
	// sql.DB has not connected yet: SQLite opens the cache, its -wal and its -shm now.
	checked := replaceMaildirPath(t, maildirPath, victim)
	_, err = cache.Exec(`CREATE TABLE proof (n INTEGER)`)
	require.NoError(t, err)

	assert.Regexp(t, `^/proc/self/fd/[0-9]+/`+maildirCacheName+`$`, mainDatabaseName(t, cache))
	assert.FileExists(t, filepath.Join(checked, maildirCacheName+"-wal"))
	assert.ElementsMatch(t, []string{"cur", "new", "tmp", maildirCacheName}, dirNames(t, victim), "SQLite created files in the directory the path leads to now")
	info, err := os.Stat(filepath.Join(victim, maildirCacheName))
	require.NoError(t, err)
	assert.Zero(t, info.Size(), "SQLite wrote the cache the path leads to now")
}

// mainDatabaseName is the name SQLite opened cache's main database by.
func mainDatabaseName(t *testing.T, cache *sql.DB) string {
	t.Helper()
	var seq int
	var name, file string
	require.NoError(t, cache.QueryRow(`SELECT seq, name, file FROM pragma_database_list WHERE name = 'main'`).Scan(&seq, &name, &file))
	return file
}
