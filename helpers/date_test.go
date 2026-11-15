package helpers

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoIngressPathParsesDateWithNetMail: every path that stores a message parses its Date:
// header with ParseDateHeader. go-message's mail.Header.Date() is net/mail.ParseDate, which
// reads an alphabetic zone (PDT, EST, CET, ...) in the host's time zone, so the stored
// instant and offset would depend on the server's TZ.
func TestNoIngressPathParsesDateWithNetMail(t *testing.T) {
	netMailDate := regexp.MustCompile(`[hH]eader\.Date\(\)|\bmail\.ParseDate\(`)

	var offenders []string
	for _, dir := range []string{"server", "cmd", "db", "pkg"} {
		err := filepath.WalkDir(filepath.Join("..", dir), func(path string, d fs.DirEntry, err error) error {
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
				if trimmed := strings.TrimSpace(line); !strings.HasPrefix(trimmed, "//") && netMailDate.MatchString(line) {
					offenders = append(offenders, filepath.ToSlash(path)+":"+strconv.Itoa(i+1)+": "+trimmed)
				}
			}
			return nil
		})
		require.NoError(t, err)
	}

	assert.Empty(t, offenders, "Date: header parsed with net/mail; use helpers.ParseDateHeader:\n%s",
		strings.Join(offenders, "\n"))
}
