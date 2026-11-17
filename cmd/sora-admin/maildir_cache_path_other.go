//go:build !linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// maildirCachePath returns the name SQLite opens the cache in the directory dir, named
// name, by. No name reaches the entries of a directory through its descriptor here
// (macOS's /dev/fd/N is not a directory), so it is the directory's own name. Hard
// links are not protected here (hardLinksProtected), so maildirCacheLinkRule has
// accepted the directory only if no user but root and this one can rename it or a
// directory above it, and nobody else can make the name lead elsewhere; it must still
// lead to dir.
func maildirCachePath(dir *os.File, name string) (string, error) {
	info, err := os.Lstat(name)
	if err == nil {
		var dirInfo os.FileInfo
		if dirInfo, err = dir.Stat(); err == nil && !os.SameFile(info, dirInfo) {
			err = fmt.Errorf("%s is no longer the directory that was checked", name)
		}
	}
	if err != nil {
		return "", fmt.Errorf("refusing to open the maildir database in %s: %w", name, err)
	}
	return filepath.Join(name, maildirCacheName), nil
}
