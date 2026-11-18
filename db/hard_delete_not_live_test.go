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

// A DELETE on messages takes the message's message_state row with it by cascade before
// either stats trigger runs, so neither can tell that a live message was unseen: a live
// message deleted directly stays in mailbox_stats.unseen_count (#2023). Application code
// therefore deletes only rows that are not live -- expunged, or in no mailbox -- and
// expunges first, under the mailbox lock, whatever it means to delete (hardDeleteMessages,
// notLiveInMailbox). This guard fails when a DELETE FROM messages in application code does
// not restrict itself to such rows.
func TestHardDeletesOfMessagesSkipLiveRows(t *testing.T) {
	root := moduleRoot(t)
	deleteFrom := regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+messages\b`)
	// The statement runs to the end of its WHERE clause: a RETURNING, or the end of the
	// Go string literal it is written in.
	statementEnd := regexp.MustCompile("(?i)\\bRETURNING\\b|`\\s*[,)]")
	notLive := regexp.MustCompile(`(?i)\bnotLiveInMailbox\b|\bexpunged_at\s+IS\s+NOT\s+NULL\b`)

	var checked int
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
			src := string(content)
			for _, loc := range deleteFrom.FindAllStringIndex(src, -1) {
				lineStart := strings.LastIndex(src[:loc[0]], "\n") + 1
				if trimmed := strings.TrimSpace(src[lineStart:loc[0]]); strings.HasPrefix(trimmed, "//") {
					continue
				}
				stmt := src[loc[0]:]
				if end := statementEnd.FindStringIndex(stmt); end != nil {
					stmt = stmt[:end[0]]
				}
				checked++
				if !notLive.MatchString(stmt) {
					rel, _ := filepath.Rel(root, path)
					line := strings.Count(src[:loc[0]], "\n") + 1
					offenders = append(offenders, rel+":"+itoa(line)+": "+strings.Join(strings.Fields(stmt), " "))
				}
			}
			return nil
		})
		require.NoError(t, err)
	}

	require.NotZero(t, checked, "found no DELETE FROM messages at all; the guard is not looking at the code")
	assert.Empty(t, offenders,
		"a DELETE FROM messages may remove a live message, which leaves it counted in unseen_count; "+
			"expunge it first and delete only rows matching notLiveInMailbox (see hardDeleteMessages):\n%s",
		strings.Join(offenders, "\n"))
}
