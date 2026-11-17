package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// An automount point that is not mounted yet (systemd's x-systemd.automount, an autofs
// direct map, an NFSv4 submount) lstats as the directory that triggers the mount: stat
// does not mount (Linux's fstatat adds AT_NO_AUTOMOUNT), while the open of a directory
// does. So the directory openImportRoot opens there is not the one it lstatted, and it
// is the same directory a path walk reaches.

// statAsAutomountPoint makes the entry name of dir lstat as trigger, a directory that
// stands for the automount point before it is mounted, until the test ends.
func statAsAutomountPoint(t *testing.T, dir, name, trigger string) {
	t.Helper()
	dirInfo, err := os.Stat(dir)
	require.NoError(t, err)
	triggerInfo, err := os.Stat(trigger)
	require.NoError(t, err)
	prev := lstatAt
	t.Cleanup(func() { lstatAt = prev })
	lstatAt = func(dirfd int, entry string) (*statInfo, error) {
		var st unix.Stat_t
		if entry == name && unix.Fstat(dirfd, &st) == nil && sameFileID(&statInfo{st: st}, dirInfo) {
			info, err := prev(unix.AT_FDCWD, trigger)
			if err == nil {
				require.True(t, sameFileID(info, triggerInfo))
				info.name = entry
			}
			return info, err
		}
		return prev(dirfd, entry)
	}
}

func TestOpenImportRootCrossesAnAutomountPointThatIsNotMountedYet(t *testing.T) {
	const name = "1700000001.M1P1.host:2,S"
	const script = "keep;\n"
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	mounted := filepath.Join(base, "home")
	require.NoError(t, os.Mkdir(mounted, 0755))
	trigger := filepath.Join(base, "autofs")
	require.NoError(t, os.Mkdir(trigger, 0755))
	maildirPath := filepath.Join(mounted, "alice", "Maildir")
	for _, dir := range []string{"cur", "new", "tmp"} {
		require.NoError(t, os.MkdirAll(filepath.Join(maildirPath, dir), 0755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(maildirPath, "cur", name), cachedSizeMessage("Own", 100), 0644))
	sievePath := filepath.Join(mounted, "alice", "sieve", "managesieve.sieve")
	require.NoError(t, os.Mkdir(filepath.Dir(sievePath), 0755))
	require.NoError(t, os.WriteFile(sievePath, []byte(script), 0644))
	statAsAutomountPoint(t, base, "home", trigger)

	t.Run("maildir", func(t *testing.T) {
		importer, err := NewImporter(context.Background(), maildirPath, "alice@example.com", 1, nil, nil, ImporterOptions{TestMode: true})
		require.NoError(t, err, "a maildir below an automount point was refused")
		t.Cleanup(func() { importer.Close() })
		importer.rdb = newMockResilientDatabase()
		require.NoError(t, importer.scanMaildir())
		assert.Equal(t, map[string]string{filepath.Join(maildirPath, "cur", name): "INBOX"}, scannedMessages(t, importer))
	})
	t.Run("sieve", func(t *testing.T) {
		content, err := readSieveFile(sievePath)
		require.NoError(t, err, "a --sieve file below an automount point was refused")
		assert.Equal(t, script, string(content))
	})
}
