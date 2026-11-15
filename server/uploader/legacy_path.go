package uploader

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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

// firstStagedBody checks physical targets once each. It is used for a cyclic alias:
// an empty cycle strands nothing, but a nonempty one must not hide a body just because
// its target was already visited under a different account path.
func firstStagedBody(entryPath string) (string, error) {
	visited := make(map[string]bool)
	var walk func(string) (string, error)
	walk = func(entryPath string) (string, error) {
		root, err := filepath.EvalSymlinks(entryPath)
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		if err != nil || visited[root] {
			return "", err
		}
		visited[root] = true
		found := ""
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
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
// stages as the user it runs as. A caller that cannot tell which user the server runs as
// passes AnyOwner.
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
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil // A missing directory or dangling link holds no body.
		}
		if err != nil {
			return false, err
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
			found, err = firstStagedBody(entryPath)
			if err == nil && found == "" {
				empty[root] = true
			}
			return found != "", err
		}
		ancestors[root] = true
		defer delete(ancestors, root)

		sawRegularOrCycle := false
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
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
	_, err := walk(legacyPath, "")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
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
