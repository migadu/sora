//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

func TestIMAP_MultiSearchExplicitReadWithoutLookup(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	reader, password := createSecondUser(t, server, "example.com", "explicitreader")
	oc, or := esearchDialLogin(t, server, owner.Email, owner.Password)
	defer oc.Close()
	prefix := fmt.Sprintf("Shared/ExplicitRead-%d", common.GetTimestamp())
	readable, lookupOnly, hidden := prefix+"/Readable", prefix+"/Lookup", prefix+"/Hidden"
	for i, name := range []string{readable, lookupOnly, hidden} {
		esearchCreate(t, oc, or, fmt.Sprintf("c%d", i), name)
		esearchAppend(t, oc, or, fmt.Sprintf("a%d", i), name, "match")
	}
	esearchCmdOK(t, oc, or, "r1", "SETACL "+esearchQuote(readable)+" "+esearchQuote(reader)+" r")
	esearchCmdOK(t, oc, or, "r2", "SETACL "+esearchQuote(lookupOnly)+" "+esearchQuote(reader)+" l")
	conn, r := esearchDialLogin(t, server, reader, password)
	defer conn.Close()
	// Implicit traversal and LIST still require lookup rights.
	for i, command := range []string{`LIST "" ` + esearchQuote(readable), `ESEARCH IN (subtree ` + esearchQuote(prefix) + `) RETURN (ALL) ALL`} {
		lines := esearchCmdOK(t, conn, r, fmt.Sprintf("n%d", i), command)
		for _, line := range lines {
			require.False(t, strings.Contains(line, readable), "%s: %q", command, lines)
		}
	}
	// RFC 7377 §2.2 requires only r for explicitly named mailboxes. Insufficient
	// rights must be ignored without aborting a search of the permitted source.
	lines := esearchCmdOK(t, conn, r, "q1", `ESEARCH IN (mailboxes (`+esearchQuote(readable)+" "+esearchQuote(lookupOnly)+" "+esearchQuote(hidden)+`)) RETURN (ALL) ALL`)
	results := esearchMailboxes(t, lines)
	require.Len(t, results, 1, "%q", lines)
	require.Contains(t, results, readable)
	require.True(t, strings.HasSuffix(esearchLine(lines, readable), " UID ALL 1"), "%q", lines)
}
