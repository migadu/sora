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

// Migration files are operator instructions, and golang-migrate prints the whole text
// of a migration that fails, error message and comments together. A script, db
// function or sora-admin command named anywhere in a migration, in a comment or in an
// error message, must exist.
func TestMigrationsReferenceExistingTools(t *testing.T) {
	root := moduleRoot(t)
	scriptRef := regexp.MustCompile(`scripts/[A-Za-z0-9_.\-/]+[A-Za-z0-9_]|[A-Za-z0-9_.\-/]*[A-Za-z0-9_\-]\.sql\b`)
	dbFuncRef := regexp.MustCompile(`\bdb\.([A-Z][A-Za-z0-9_]*)`)
	adminCmdRef := regexp.MustCompile(`sora-admin ([a-z][a-z-]*)(?: ([a-z][a-z-]*))?`)

	dbSource := goSources(t, filepath.Join(root, "db"))
	adminSource := goSources(t, filepath.Join(root, "cmd", "sora-admin"))
	scriptExists := func(ref string) bool {
		for _, dir := range []string{"", "scripts", filepath.Join("db", "migrations")} {
			if _, err := os.Stat(filepath.Join(root, dir, ref)); err == nil {
				return true
			}
		}
		return false
	}

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
			where := filepath.Base(path) + ":" + strconv.Itoa(n) + ": "
			for _, ref := range scriptRef.FindAllString(line, -1) {
				if !scriptExists(ref) {
					missing = append(missing, where+ref)
				}
			}
			for _, m := range dbFuncRef.FindAllStringSubmatch(line, -1) {
				decl := regexp.MustCompile(`(?m)^func (\([^)]*\) )?` + m[1] + `\(`)
				if !decl.MatchString(dbSource) {
					missing = append(missing, where+m[0])
				}
			}
			for _, m := range adminCmdRef.FindAllStringSubmatch(line, -1) {
				for _, word := range m[1:] {
					if word != "" && !strings.Contains(adminSource, `case "`+word+`"`) {
						missing = append(missing, where+m[0])
						break
					}
				}
			}
		}
		require.NoError(t, scanner.Err())
		f.Close()
	}
	require.Empty(t, missing, "migrations name scripts, functions or commands that do not exist")
}

// goSources returns the non-test Go files of one package directory, concatenated.
func goSources(t *testing.T, dir string) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	var b strings.Builder
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		require.NoError(t, err)
		b.Write(src)
		b.WriteByte('\n')
	}
	return b.String()
}
