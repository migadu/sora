package db

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The hash-keyed messages_fts table is retired: the baseline schema does not have it.
// Application code that still names it would fail with "relation does not exist" -- on
// every delivery, MOVE, COPY or worker batch that reached it. This guard catches such a
// reference before it ships.
//
// scripts/ is excluded on purpose: operator scripts are not application code.
func TestNoApplicationCodeReferencesRetiredFTSTable(t *testing.T) {
	root := moduleRoot(t)
	v1 := regexp.MustCompile(`\bmessages_fts([^_a-zA-Z0-9]|$)`)

	var offenders []string
	for _, dir := range []string{"db", "server", "pkg", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for i, line := range strings.Split(string(content), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "--") {
					continue
				}
				if v1.MatchString(line) {
					rel, _ := filepath.Rel(root, path)
					offenders = append(offenders, rel+":"+itoa(i+1)+": "+trimmed)
				}
			}
			return nil
		})
		require.NoError(t, err)
	}

	assert.Empty(t, offenders,
		"the retired messages_fts table is referenced by application code; use messages_fts_v2:\n%s",
		strings.Join(offenders, "\n"))
}
