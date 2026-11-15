// Package sqlitefile builds the DSN that opens an SQLite database file by its path.
package sqlitefile

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

// DSN returns the modernc.org/sqlite DSN that opens the database file at path with the
// URI query params (empty for none): a file: URI of the absolute path. The driver cuts
// any other DSN at its first '?' and reads the rest as parameters, so a plain path with a
// '?' in it would open a different file. In the URI the path is percent-encoded and SQLite
// decodes it, so a '?', '#' or '%' in it stays part of the file name. A relative path is
// joined to the working directory, because it would be read as the URI authority, but the
// path is not cleaned (as filepath.Abs would): the OS and SQLite resolve a ".." that
// follows a symlink from the symlink's target, so the URI opens the file the caller's own
// os calls on path reach, not the one the lexically cleaned path names.
func DSN(path, params string) (string, error) {
	if !filepath.IsAbs(path) {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to resolve database path %s: %w", path, err)
		}
		path = wd + string(filepath.Separator) + path
	}
	return (&url.URL{Scheme: "file", Path: path, RawQuery: params}).String(), nil
}
