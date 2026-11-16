//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
)

// CHECK is valid only in the selected state: RFC 3501 §6.4 lists it with
// CLOSE, EXPUNGE, SEARCH, FETCH, STORE, COPY and UID, and §9 puts it in
// command-select, "Valid only when in Selected state". It was answered as a
// NOOP in every state, so "CHECK" with no mailbox selected got "OK CHECK
// completed". NOOP is a universal command and stays OK everywhere.
func TestIMAP_CheckOnlyInSelectedState(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()

	for i, step := range []struct{ state, command, want string }{
		{"not authenticated", "CHECK", "BAD"},
		{"not authenticated", "NOOP", "OK"},
		{"not authenticated", fmt.Sprintf("LOGIN %s %s", account.Email, account.Password), "OK"},
		{"authenticated", "CHECK", "BAD"},
		{"authenticated", "NOOP", "OK"},
		{"authenticated", "SELECT INBOX", "OK"},
		{"selected", "CHECK", "OK"},
		{"selected", "NOOP", "OK"},
		{"selected", "CLOSE", "OK"},
		{"authenticated after CLOSE", "CHECK", "BAD"},
		{"authenticated after CLOSE", "EXAMINE INBOX", "OK"},
		{"selected read-only", "CHECK", "OK"},
	} {
		tag := fmt.Sprintf("C%d", i)
		_, tagged := rc.cmd(tag, step.command)
		assert.True(t, strings.HasPrefix(tagged, tag+" "+step.want+" "),
			"%s in the %s state: got %q, want %s", strings.Fields(step.command)[0], step.state, tagged, step.want)
	}
}
