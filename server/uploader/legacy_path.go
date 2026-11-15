package uploader

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/migadu/sora/logger"
)

// AnyOwner, as the uid for CheckLegacyStaging, is for a caller that does not run as the
// user the server stages bodies as, such as sora-admin, often run as root: every entry
// counts whoever owns it, and one it cannot read is an error.
const AnyOwner = -1

func sameStagedFile(legacyFile, activeFile string) bool {
	legacyInfo, err := os.Stat(legacyFile)
	if err != nil {
		return false
	}
	activeInfo, err := os.Stat(activeFile)
	if err != nil {
		return false
	}
	return os.SameFile(legacyInfo, activeInfo)
}

// spoolError returns nil for an error the legacy startup check ignores: the entry at
// p is gone, or, unless uid is AnyOwner, this process cannot read it, which it logs.
// An unreadable entry can still contain a body recoverable after permissions are repaired.
// Otherwise it returns err.
func spoolError(p string, err error, uid int) error {
	if errors.Is(err, fs.ErrPermission) && uid != AnyOwner {
		logger.Warn("Uploader: ignoring an entry under the previous default [uploader] path that this process cannot read", "path", p, "error", err)
		return nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// foreignEntry reports, and logs, that the legacy spool entry info describes belongs to
// a user other than root and uid, unless uid is AnyOwner. The uploader stages as the user
// it runs as, so no such entry is a body it staged, while /tmp lets every local user
// create one. Root is trusted: an administrator's link or directory is followed.
func foreignEntry(p string, info fs.FileInfo, uid int) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uid == AnyOwner || st.Uid == 0 || int(st.Uid) == uid {
		return false
	}
	logger.Warn("Uploader: ignoring an entry under the previous default [uploader] path that belongs to another user", "path", p, "uid", st.Uid)
	return true
}

// walkSpool is filepath.WalkDir over a legacy spool directory that passes over what
// spoolError and foreignEntry rule out, with the directory below it, so fn sees only
// entries of uid or root that this process can read. A symlink's own owner counts: fn
// follows only a link that user or root made.
func walkSpool(root string, uid int, fn func(p string, d fs.DirEntry) error) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		var info fs.FileInfo
		if err == nil {
			info, err = d.Info()
		}
		if err != nil {
			return spoolError(p, err, uid)
		}
		if foreignEntry(p, info, uid) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		return fn(p, d)
	})
}

// firstStagedBody checks physical targets once each. It is used for a cyclic alias:
// an empty cycle strands nothing, but a nonempty one must not hide a body just because
// its target was already visited under a different account path.
func firstStagedBody(entryPath string, uid int) (string, error) {
	visited := make(map[string]bool)
	var walk func(string) (string, error)
	walk = func(entryPath string) (string, error) {
		root, err := filepath.EvalSymlinks(entryPath)
		if err != nil || visited[root] {
			return "", spoolError(entryPath, err, uid)
		}
		visited[root] = true
		found := ""
		err = walkSpool(root, uid, func(p string, d fs.DirEntry) error {
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			logicalPath := filepath.Join(entryPath, rel)
			if d.Type()&fs.ModeSymlink != 0 {
				found, err = walk(logicalPath)
				if err != nil {
					return err
				}
			} else if d.Type().IsRegular() {
				found = logicalPath
			}
			if found != "" {
				return fs.SkipAll
			}
			return nil
		})
		return found, err
	}
	return walk(entryPath)
}

// CheckLegacyStaging refuses to start the uploader on path when path is the current
// default staging directory (newDefault) and legacyPath, the default of earlier releases,
// still holds staged bodies. A node upgraded without setting [uploader] path would look for
// those bodies under the new default, count every upload as missing its file and, once
// max_attempts is used up, have their messages reaped: the staged file is the only copy of
// a message until it reaches S3.
//
// uid is the user bodies were staged as: the server passes its own, as its uploader
// stages as the user it runs as. Every local user can create the legacy default under
// /tmp, so an entry that belongs to another user (root aside), or that this process
// cannot read, is logged and passed over with what is below it: otherwise any local user
// could keep the server from starting. A caller that cannot tell which user the server
// runs as passes AnyOwner, and refuses on such entries rather than miss a staged body.
func CheckLegacyStaging(path, newDefault, legacyPath string, uid int) error {
	if filepath.Clean(path) != filepath.Clean(newDefault) {
		return nil
	}
	if activeRoot, err := filepath.EvalSymlinks(path); err == nil {
		if legacyRoot, err := filepath.EvalSymlinks(legacyPath); err == nil && legacyRoot == activeRoot {
			return nil
		}
	}
	// The uploader follows symlinks in the root, account directories and body
	// paths. WalkDir does not: visit link targets explicitly, guarding ancestor
	// cycles so a loop in an otherwise empty spool cannot keep startup stuck here.
	// A body reachable at the same relative path under path is not stranded.
	found := ""
	ancestors := make(map[string]bool)
	empty := make(map[string]bool)
	var walk func(entryPath, logicalRel string) (bool, error)
	walk = func(entryPath, logicalRel string) (bool, error) {
		root, err := filepath.EvalSymlinks(entryPath)
		if err != nil {
			// A missing directory or dangling link holds no body.
			return false, spoolError(entryPath, err, uid)
		}
		// Identical physical subtrees make every relative body path reachable under
		// the active spool, without inspecting the subtree's files individually.
		if activeRoot, err := filepath.EvalSymlinks(filepath.Join(path, logicalRel)); err == nil && activeRoot == root {
			return true, nil
		}
		if empty[root] {
			return false, nil
		}
		if ancestors[root] {
			var err error
			found, err = firstStagedBody(entryPath, uid)
			if err == nil && found == "" {
				empty[root] = true
			}
			return found != "", err
		}
		ancestors[root] = true
		defer delete(ancestors, root)

		sawRegularOrCycle := false
		err = walkSpool(root, uid, func(p string, d fs.DirEntry) error {
			curRel := logicalRel
			if p != root {
				subRel, relErr := filepath.Rel(root, p)
				if relErr != nil {
					return relErr
				}
				curRel = filepath.Join(logicalRel, subRel)
			}
			if d.Type()&fs.ModeSymlink != 0 {
				nonEmpty, walkErr := walk(p, curRel)
				if walkErr != nil {
					return walkErr
				}
				if nonEmpty {
					sawRegularOrCycle = true
				}
			} else if d.Type().IsRegular() {
				sawRegularOrCycle = true
				if !sameStagedFile(filepath.Join(legacyPath, curRel), filepath.Join(path, curRel)) {
					found = p
				}
			}
			if found != "" {
				return fs.SkipAll
			}
			return nil
		})
		if err == nil && !sawRegularOrCycle {
			empty[root] = true
		}
		return sawRegularOrCycle, err
	}
	// walkSpool checks the entries it visits; the legacy path itself may be a link.
	info, err := os.Lstat(legacyPath)
	if err == nil && !foreignEntry(legacyPath, info, uid) {
		_, err = walk(legacyPath, "")
	}
	if err = spoolError(legacyPath, err, uid); err != nil {
		return fmt.Errorf("cannot check %s for bodies staged under the previous default [uploader] path: %w", legacyPath, err)
	}
	if found == "" {
		return nil
	}
	return fmt.Errorf("%s, the previous default [uploader] path, still holds staged bodies (%s), "+
		"the only copy of their messages until they are uploaded: set [uploader] path = %q until "+
		"`sora-admin uploader status` shows nothing pending, or stop sora and move that directory to %s",
		legacyPath, found, legacyPath, path)
}
