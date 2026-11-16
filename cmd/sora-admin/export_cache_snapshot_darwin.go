package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func requireExportSnapshotFilesystem(f *os.File) error {
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &st); err != nil {
		return err
	}
	kind := strings.TrimRight(string(st.Fstypename[:]), "\x00")
	if kind != "apfs" && kind != "hfs" && kind != "ufs" && kind != "tmpfs" {
		return fmt.Errorf("cache snapshot requires a local POSIX-locking filesystem, got %s", kind)
	}
	return nil
}
