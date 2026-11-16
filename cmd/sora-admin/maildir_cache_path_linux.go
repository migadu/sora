package main

import (
	"fmt"
	"os"
)

// maildirCachePath returns the name SQLite opens the cache in the directory dir, named
// name, by: /proc/self/fd/N/sora-maildir.db, which reaches the directory through its
// descriptor, wherever its name leads meanwhile (maildirCacheVFS keeps SQLite from
// resolving it to the directory's path).
func maildirCachePath(dir *os.File, name string) (string, error) {
	fdName := fmt.Sprintf("/proc/self/fd/%d", dir.Fd())
	info, err := os.Stat(fdName)
	if err == nil {
		var dirInfo os.FileInfo
		if dirInfo, err = dir.Stat(); err == nil && !os.SameFile(info, dirInfo) {
			err = fmt.Errorf("%s leads to another directory", fdName)
		}
	}
	if err != nil {
		return "", fmt.Errorf("failed to open the maildir database in %s through its descriptor (is /proc mounted?): %w", name, err)
	}
	return fdName + "/" + maildirCacheName, nil
}
