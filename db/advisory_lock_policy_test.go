package db

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sessionLevelAdvisoryCall matches every session-level advisory lock function, in any
// case and with any spacing before the parenthesis, and no transaction-level one
// (pg_advisory_xact_lock and friends have "xact_" where this expects "lock").
var sessionLevelAdvisoryCall = regexp.MustCompile(`(?i)\bpg_(?:try_)?advisory_(?:un)?lock(?:_shared|_all)?\s*\(`)

// Session-level advisory locks are banned from Sora's production code and schema.
// Through a transaction-pooling proxy (PgBouncer in transaction mode, which is how
// production reaches PostgreSQL) the lock and its unlock run on different backends, so
// the lock strands until the proxy retires that backend, and enough stranded locks fill
// the shared lock table — the 2026-09-06 outage ("out of shared memory", SQLSTATE
// 53200). Use AdvisoryLockTx, or pg_advisory_xact_lock inside a transaction that
// already exists. Non-test Go files and every SQL file (migrations, functions,
// triggers) are scanned; comments are not code and are ignored.
func TestNoSessionLevelAdvisoryLocksInProductionCode(t *testing.T) {
	root := moduleRoot(t)
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".claude", "vendor", "node_modules":
				return filepath.SkipDir
			}
			if path != root {
				// A nested module or a worktree checkout is not this tree.
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		var lineComment string
		switch {
		case strings.HasSuffix(path, "_test.go"):
			return nil
		case strings.HasSuffix(path, ".go"):
			lineComment = "//"
		case strings.HasSuffix(path, ".sql"):
			lineComment = "--"
		default:
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		found, err := scanForSessionLocks(path, lineComment)
		if err != nil {
			return err
		}
		for _, f := range found {
			offenders = append(offenders, rel+":"+f)
		}
		return nil
	})
	require.NoError(t, err)
	assert.Empty(t, offenders, "session-level advisory locks strand behind a transaction pooler; use AdvisoryLockTx")
}

// scanForSessionLocks returns "line: text" for every code line of the file that calls a
// session-level advisory lock function, skipping line and block comments.
func scanForSessionLocks(path, lineComment string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var found []string
	inBlock := false
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for n := 1; scanner.Scan(); n++ {
		code := scanner.Text()
		if inBlock {
			end := strings.Index(code, "*/")
			if end < 0 {
				continue
			}
			code = code[end+2:]
			inBlock = false
		}
		for {
			start := strings.Index(code, "/*")
			if start < 0 {
				break
			}
			end := strings.Index(code[start+2:], "*/")
			if end < 0 {
				code = code[:start]
				inBlock = true
				break
			}
			code = code[:start] + code[start+2+end+2:]
		}
		if i := strings.Index(code, lineComment); i >= 0 {
			code = code[:i]
		}
		if sessionLevelAdvisoryCall.MatchString(code) {
			found = append(found, fmt.Sprintf("%d: %s", n, strings.TrimSpace(code)))
		}
	}
	return found, scanner.Err()
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "go.mod not found above %s", dir)
		dir = parent
	}
}
