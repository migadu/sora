// Package sqlitefile resolves a configured SQLite database name to its file and builds
// the DSN that opens an SQLite database file by its path.
package sqlitefile

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// Parse reads a configured database name: a name that starts with "file:" is a URI, read
// by SQLite's rules (https://www.sqlite.org/uri.html, section 3), and any other name is
// the path of the database file. It returns the path of the file the name opens and the
// URI's query, still escaped, which holds SQLite's open parameters. The path is "" for a
// name that opens no file: an in-memory or temporary database (":memory:", a URI with an
// empty path, ":memory:" as its path, mode=memory or vfs=memdb). The caller prepares the
// file at path with its own os calls and opens DSN(path, query), so that the file it
// prepared is the one SQLite opens, however the name was spelled.
func Parse(name string) (path, query string, err error) {
	uri, isURI := strings.CutPrefix(name, "file:")
	if !isURI {
		if name == ":memory:" {
			return "", "", nil
		}
		return name, "", nil
	}
	uri, _, _ = strings.Cut(uri, "#") // the fragment is ignored
	uri, query, _ = strings.Cut(uri, "?")
	if rest, ok := strings.CutPrefix(uri, "//"); ok {
		// The authority may be empty or "localhost"; the path after it is absolute.
		authority, _, _ := strings.Cut(rest, "/")
		if authority != "" && authority != "localhost" {
			return "", "", fmt.Errorf("invalid authority %q in database URI %s", authority, name)
		}
		uri = rest[len(authority):]
	}
	path = unescape(uri)

	// SQLite validates access modes in order and uses the last accepted mode
	// and the last VFS. Validate before callers prepare the file or its directory.
	mode, _, err := parseMode(query)
	if err != nil {
		return "", "", err
	}
	vfs, _ := lastParameter(query, "vfs")
	if path == "" || path == ":memory:" || mode == "memory" || vfs == "memdb" {
		return "", "", nil
	}
	return path, query, nil
}

// CanCreate reports whether the final accepted URI mode permits creating a file,
// including percent-escaped keys and values. Validate before touching files.
func CanCreate(params string) (bool, error) {
	mode, present, err := parseMode(params)
	return !present || mode == "rwc", err
}

// Prepare secures the database and any existing journal files before SQLite
// opens them. New sidecars inherit the database's mode. A no-create URI mode
// must not be turned into creation by this permission preparation.
func Prepare(path, params string) error {
	create, err := CanCreate(params)
	if err != nil {
		return err
	}
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE
	}
	f, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return fmt.Errorf("failed to prepare database file: %w", err)
	}
	err = f.Chmod(0600)
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("failed to enforce 0600 permissions on database file: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("failed to close prepared database file: %w", closeErr)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err := os.Chmod(path+suffix, 0600); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to enforce 0600 permissions on database sidecar %s: %w", suffix, err)
		}
	}
	return nil
}

func lastParameter(query, name string) (value string, present bool) {
	for _, param := range strings.Split(query, "&") {
		key, v, _ := strings.Cut(param, "=")
		if unescape(key) == name {
			value, present = unescape(v), true
		}
	}
	return value, present
}

func parseMode(query string) (mode string, present bool, err error) {
	// Match sqlite3ParseUri's access-mode check against the current open
	// flags (READONLY=1, READWRITE=2, CREATE=4, MEMORY=128). For example,
	// rwc followed by rw is valid; ro followed by rwc is not.
	limit := 2 | 4
	for _, param := range strings.Split(query, "&") {
		key, value, _ := strings.Cut(param, "=")
		if unescape(key) != "mode" {
			continue
		}
		mode, present = unescape(value), true
		var flags int
		switch mode {
		case "ro":
			flags = 1
		case "rw":
			flags = 2
		case "rwc":
			flags = 2 | 4
		case "memory":
			flags = 128
		default:
			return mode, present, fmt.Errorf("invalid file database mode %q", mode)
		}
		if flags&^128 > limit {
			return mode, present, fmt.Errorf("file database mode not allowed: %s", mode)
		}
		limit = flags
	}
	return mode, present, nil
}

// unescape decodes the %HH escapes in one part of a URI (its path, or a parameter's name
// or value) as SQLite does: a '%' not followed by two hex digits is a literal '%', and a
// %00 ends the part.
func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if octet, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				if octet == 0 {
					break
				}
				b.WriteByte(byte(octet))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
