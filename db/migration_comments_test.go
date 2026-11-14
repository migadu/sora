package db

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Migration comments are operator instructions. A script they tell the operator to run
// must exist in the repository.
func TestMigrationCommentsReferenceExistingScripts(t *testing.T) {
	root := moduleRoot(t)
	scriptRef := regexp.MustCompile(`scripts/[A-Za-z0-9_.\-/]+[A-Za-z0-9_]`)

	files, err := filepath.Glob(filepath.Join(root, "db", "migrations", "*.sql"))
	require.NoError(t, err)
	require.NotEmpty(t, files)

	var missing []string
	for _, path := range files {
		f, err := os.Open(path)
		require.NoError(t, err)
		scanner := bufio.NewScanner(f)
		for n := 1; scanner.Scan(); n++ {
			line := scanner.Text()
			i := strings.Index(line, "--")
			if i < 0 {
				continue
			}
			for _, ref := range scriptRef.FindAllString(line[i:], -1) {
				if _, err := os.Stat(filepath.Join(root, ref)); err != nil {
					missing = append(missing, filepath.Base(path)+":"+strconv.Itoa(n)+": "+ref)
				}
			}
		}
		require.NoError(t, scanner.Err())
		f.Close()
	}
	require.Empty(t, missing, "migration comments name scripts that are not in the repository")
}
