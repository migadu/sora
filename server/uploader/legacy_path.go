package uploader

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
)

// CheckLegacyStaging refuses to start the uploader on path when path is the current
// default staging directory (newDefault) and legacyPath, the default of earlier releases,
// still holds staged bodies. A node upgraded without setting [uploader] path would look for
// those bodies under the new default, count every upload as missing its file and, once
// max_attempts is used up, have their messages reaped: the staged file is the only copy of
// a message until it reaches S3.
func CheckLegacyStaging(path, newDefault, legacyPath string) error {
	if filepath.Clean(path) != filepath.Clean(newDefault) {
		return nil
	}
	// The uploader follows symlinks in the root, account directories and body
	// paths. WalkDir does not: visit link targets explicitly, once each so a
	// cycle in an otherwise empty spool cannot keep startup stuck here.
	found := ""
	visited := make(map[string]bool)
	var walk func(string) error
	walk = func(path string) error {
		root, err := filepath.EvalSymlinks(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil // A missing directory or dangling link holds no body.
		}
		if err != nil {
			return err
		}
		if visited[root] {
			return nil
		}
		visited[root] = true
		return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type()&fs.ModeSymlink != 0 {
				if err := walk(p); err != nil {
					return err
				}
			} else if d.Type().IsRegular() {
				found = p
			}
			if found != "" {
				return fs.SkipAll
			}
			return nil
		})
	}
	err := walk(legacyPath)
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
