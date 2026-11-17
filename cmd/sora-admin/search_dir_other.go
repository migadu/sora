//go:build unix && !linux && !darwin && !freebsd

package main

import "golang.org/x/sys/unix"

// searchDirFlags is an open for reading where no search-only open is known to work:
// the directories on the way to the import root must then be readable too.
const searchDirFlags = unix.O_RDONLY
