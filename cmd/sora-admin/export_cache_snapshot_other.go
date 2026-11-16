//go:build !darwin && !linux

package main

import "fmt"

func copyExportCacheSnapshot(exportSnapshotRequest) error {
	return fmt.Errorf("safe cache snapshots are supported only on local POSIX-locking Linux/macOS filesystems")
}
