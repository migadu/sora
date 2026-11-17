package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const exportSnapshotHelperArg = "--internal-export-cache-snapshot"
const exportSnapshotHelperEnv = "SORA_INTERNAL_EXPORT_CACHE_SNAPSHOT"

// exportSnapshotRequest invokes the internal cache snapshot helper. Both the checked
// source maildir (exportSnapshotDirFD) and the verified private destination directory
// (exportSnapshotDestDirFD) reach the helper as extra open directory descriptors, so
// neither directory path is resolved again.
type exportSnapshotRequest struct{}

// The helper has a separate POSIX lock owner from every SQLite connection in the
// caller. Closing another descriptor for the same inode cannot release its lock.
// Dispatch in init also permits the identical path in the admin test executable.
func init() {
	if len(os.Args) != 2 || os.Args[1] != exportSnapshotHelperArg || os.Getenv(exportSnapshotHelperEnv) != "1" {
		return
	}
	var req exportSnapshotRequest
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20)).Decode(&req); err != nil {
		fmt.Fprintln(os.Stderr, "invalid cache snapshot request:", err)
		os.Exit(1)
	}
	if err := copyExportCacheSnapshot(req); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

// Source is never opened by SQLite: even a query-only/read-only connection may
// recover/checkpoint WAL or create/change/remove its sidecars. Only the private
// DB+WAL copy is opened; SQLite rebuilds SHM there. A live/unsafe source fails.
//
// The cache is the one in root, the directory the dry run checked
// (openExportPreviewRoot): the helper gets root's descriptor, so the owner of a
// directory on the way cannot make it copy another directory's cache meanwhile.
func openExportCacheForDryRun(ctx context.Context, root *os.Root) (_ *sql.DB, _ *privateTempDir, retErr error) {
	dbPath := filepath.Join(root.Name(), maildirCacheName)
	info, err := root.Lstat(maildirCacheName)
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("inspect dry-run cache: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("dry-run cache must be a regular file: %s", dbPath)
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, nil, fmt.Errorf("open dry-run cache directory: %w", err)
	}
	defer dir.Close()
	private, err := newPrivateTempDir("sora-export-preview-*", maildirCacheName, "the export preview's cache snapshot")
	if err != nil {
		return nil, nil, fmt.Errorf("create private cache snapshot: %w", err)
	}
	defer func() {
		if retErr != nil {
			_ = private.cleanup()
		}
	}()
	executable, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	req, err := json.Marshal(exportSnapshotRequest{})
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.CommandContext(ctx, executable, exportSnapshotHelperArg)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, exportSnapshotHelperEnv+"=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, exportSnapshotHelperEnv+"=1")
	cmd.Stdin = strings.NewReader(string(req))
	cmd.ExtraFiles = []*os.File{dir, private.dir} // exportSnapshotDirFD, exportSnapshotDestDirFD
	if output, err := cmd.CombinedOutput(); err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, fmt.Errorf("cannot safely preview maildir cache: %w: %s", err, strings.TrimSpace(string(output)))
	}
	uri, err := private.sqliteDSN("mode=rw&_pragma=query_only(1)")
	if err != nil {
		return nil, nil, fmt.Errorf("open private cache snapshot: %w", err)
	}
	cache, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, nil, fmt.Errorf("open private cache snapshot: %w", err)
	}
	cache.SetMaxOpenConns(1)
	var hasMessages bool
	if err := cache.QueryRowContext(ctx, `SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='messages'`).Scan(&hasMessages); err != nil {
		cache.Close()
		return nil, nil, fmt.Errorf("read private cache snapshot: %w", err)
	}
	if !hasMessages {
		cache.Close()
		if err := private.cleanup(); err != nil {
			return nil, nil, err
		}
		return nil, nil, nil
	}
	// Old schemas need no migration, but an incompatible messages table must
	// fail before the report can silently count unreadable entries as new.
	rows, err := cache.QueryContext(ctx, `SELECT hash, mailbox, filename FROM messages LIMIT 0`)
	if err != nil {
		cache.Close()
		return nil, nil, fmt.Errorf("unsupported maildir cache schema: %w", err)
	}
	if err := rows.Close(); err != nil {
		cache.Close()
		return nil, nil, err
	}
	return cache, private, nil
}
