//go:build darwin || linux

package main

import "golang.org/x/sys/unix"

func makeExportSnapshotFIFO(path string) error { return unix.Mkfifo(path, 0600) }

func countExportSnapshotFDs() int {
	n := 0
	for fd := 0; fd < 2048; fd++ {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
			n++
		}
	}
	return n
}
