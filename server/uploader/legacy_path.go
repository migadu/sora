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
	// The uploader followed a symlinked directory (one way to have kept the /tmp default
	// on persistent storage), and WalkDir does not: walk its target.
	root, err := filepath.EvalSymlinks(legacyPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot check %s for bodies staged under the previous default [uploader] path: %w", legacyPath, err)
	}
	found := ""
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			found = p
			return fs.SkipAll
		}
		return nil
	})
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
