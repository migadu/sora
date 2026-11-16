package main

import "golang.org/x/sys/unix"

// swapPaths exchanges the files at a and b in one rename (renameat2 RENAME_EXCHANGE).
func swapPaths(a, b string) error {
	return unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE)
}
