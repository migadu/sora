//go:build integration

package imap_test

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A sort key outside sort-key (RFC 5256 §5, extended by RFC 5957 §5 with
// DISPLAYFROM and DISPLAYTO) is "BAD - command unknown or arguments invalid"
// (RFC 5256 §3). It was answered "NO [SERVERBUG] Internal server error" and
// logged as a server failure (#1371).
func TestIMAP_SortUnknownKeyIsBAD(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)
	rc.append("P", "INBOX", "From: a@example.com\r\nSubject: sort keys\r\n\r\nbody\r\n")
	_, tagged := rc.cmd("S", "SELECT INBOX")
	require.True(t, strings.HasPrefix(tagged, "S OK"), "%s", tagged)

	for _, command := range []string{
		`SORT (FOO) UTF-8 ALL`,
		`SORT (REVERSE FOO) UTF-8 ALL`,
		`SORT (DATE FOO) UTF-8 ALL`,
		`UID SORT (FOO) UTF-8 ALL`,
		`SORT RETURN (ALL) (FOO) UTF-8 ALL`,
	} {
		untagged, tagged := rc.cmd("A", command)
		assert.True(t, strings.HasPrefix(tagged, "A BAD"), "%s: %s (untagged %q)", command, tagged, untagged)
		assert.Empty(t, untagged, "%s", command)
		_, tagged = rc.cmd("N", "NOOP")
		require.True(t, strings.HasPrefix(tagged, "N OK"), "NOOP after %s: %s", command, tagged)
	}

	// Every key in the grammar is served, SORT=DISPLAY's included.
	for _, key := range []string{"ARRIVAL", "CC", "DATE", "FROM", "SIZE", "SUBJECT", "TO", "DISPLAYFROM", "DISPLAYTO", "REVERSE DATE"} {
		command := "SORT (" + key + ") UTF-8 ALL"
		untagged, tagged := rc.cmd("G", command)
		require.True(t, strings.HasPrefix(tagged, "G OK"), "%s: %s", command, tagged)
		require.Contains(t, untagged, "* SORT 1", "%s", command)
	}
}
