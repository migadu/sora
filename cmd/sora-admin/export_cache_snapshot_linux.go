package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func requireExportSnapshotFilesystem(f *os.File) error {
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &st); err != nil {
		return err
	}
	switch st.Type {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC:
		return nil
	default:
		return fmt.Errorf("cache snapshot requires a supported local POSIX-locking filesystem, got type0x%x", st.Type)
	}
}
