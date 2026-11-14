// Package sqlitefile builds the DSN that opens an SQLite database file by its path.
package sqlitefile

import (
	"fmt"
	"net/url"
	"path/filepath"
)

// DSN returns the modernc.org/sqlite DSN that opens the database file at path with the
// URI query params (empty for none): a file: URI of the absolute path. The driver cuts
// any other DSN at its first '?' and reads the rest as parameters, so a plain path with a
// '?' in it would open a different file. In the URI the path is percent-encoded and SQLite
// decodes it, so a '?', '#' or '%' in it stays part of the file name. The path is made
// absolute because a relative one would be read as the URI authority.
func DSN(path, params string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to resolve database path %s: %w", path, err)
	}
	return (&url.URL{Scheme: "file", Path: absPath, RawQuery: params}).String(), nil
}
