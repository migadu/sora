package db

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var updateMessagesStatement = regexp.MustCompile(`(?i)\bUPDATE\s+messages\b`)

// RenameMailbox must never write to the messages table.
//
// It used to re-sync the denormalized messages.mailbox_path for every message in the
// renamed subtree. Nothing indexes that column, but nothing makes those updates HOT
// either, so each row took a fresh entry in all ~30 indexes on messages (7 of them GIN):
// measured at 37s and 2.2 GB of WAL for a 105k-message mailbox — while holding the
// mailboxes row lock that every delivery needs, so APPEND and LMTP into the mailbox
// failed at lock_timeout for the duration.
//
// The column is now maintained where it actually matters: DeleteMailbox stamps it (live
// AND already-expunged rows) just before the mailbox row disappears, and RestoreMessages
// prefers the mailbox's current name via mailbox_id (see effectiveMailboxName).
//
// This is a source-level guard because the regression is invisible in behaviour: a
// re-added sync would keep every test passing and only show up as latency in production.
func TestRenameMailboxDoesNotTouchMessagesTable(t *testing.T) {
	root := moduleRoot(t)
	src, err := os.ReadFile(filepath.Join(root, "db", "mailbox.go"))
	require.NoError(t, err)

	body := functionBody(t, string(src), "func (db *Database) RenameMailbox(")
	require.NotEmpty(t, body, "RenameMailbox not found in db/mailbox.go")

	offenders := []string{}
	for i, line := range strings.Split(body, "\n") {
		code := line
		if idx := strings.Index(code, "//"); idx >= 0 {
			code = code[:idx] // prose about the old behaviour is not the old behaviour
		}
		if updateMessagesStatement.MatchString(code) {
			offenders = append(offenders, strings.TrimSpace(line)+" (RenameMailbox line "+strconv.Itoa(i+1)+")")
		}
	}
	require.Empty(t, offenders,
		"RenameMailbox must not write to messages — a rename is O(mailboxes), never O(messages):\n%s",
		strings.Join(offenders, "\n"))
}

// functionBody returns the source of the function whose declaration starts with decl,
// up to (not including) the next top-level declaration.
func functionBody(t *testing.T, src, decl string) string {
	t.Helper()
	start := strings.Index(src, decl)
	if start < 0 {
		return ""
	}
	rest := src[start+len(decl):]
	if end := strings.Index(rest, "\nfunc "); end >= 0 {
		return rest[:end]
	}
	return rest
}
