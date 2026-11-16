package main

import "golang.org/x/sys/unix"

// swapPaths exchanges the files at a and b in one rename (renamex_np RENAME_SWAP).
func swapPaths(a, b string) error {
	return unix.RenamexNp(a, b, unix.RENAME_SWAP)
}
