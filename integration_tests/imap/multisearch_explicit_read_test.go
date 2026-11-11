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
	readable, lookupOnly, hidden, public := prefix+"/Readable", prefix+"/Lookup", prefix+"/Hidden", prefix+"/Public"
	for i, name := range []string{readable, lookupOnly, hidden, public} {
		esearchCreate(t, oc, or, fmt.Sprintf("c%d", i), name)
		esearchAppend(t, oc, or, fmt.Sprintf("a%d", i), name, "match")
	}
	esearchCmdOK(t, oc, or, "r1", "SETACL "+esearchQuote(readable)+" "+esearchQuote(reader)+" r")
	esearchCmdOK(t, oc, or, "r3", "SETACL "+esearchQuote(public)+" anyone r")
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
	lines := esearchCmdOK(t, conn, r, "q1", `ESEARCH IN (mailboxes (`+esearchQuote(readable)+" "+esearchQuote(lookupOnly)+" "+esearchQuote(hidden)+" "+esearchQuote(public)+`)) RETURN (ALL) ALL`)
	results := esearchMailboxes(t, lines)
	require.Len(t, results, 2, "%q", lines)
	require.Contains(t, results, readable)
	require.Contains(t, results, public)
	require.True(t, strings.HasSuffix(esearchLine(lines, readable), " UID ALL 1"), "%q", lines)
	// A normal namespace winner with l but no r must keep shadowing another
	// owner's r-only mailbox, rather than ESEARCH changing the meaning of a name.
	otherOwner, otherPassword := createSecondUser(t, server, "example.com", "lookupowner")
	lc, lr := esearchDialLogin(t, server, otherOwner, otherPassword)
	defer lc.Close()
	esearchCreate(t, lc, lr, "c1", readable)
	esearchAppend(t, lc, lr, "a1", readable, "shadow")
	esearchCmdOK(t, lc, lr, "r1", "SETACL "+esearchQuote(readable)+" "+esearchQuote(reader)+" l")
	require.Empty(t, esearchMailboxes(t, esearchCmdOK(t, conn, r, "q2", `ESEARCH IN (mailboxes `+esearchQuote(readable)+`) RETURN (ALL) ALL`)))

	foreign, foreignPassword := createSecondUser(t, server, "other.example", "foreignreader")
	fc, fr := esearchDialLogin(t, server, foreign, foreignPassword)
	defer fc.Close()
	require.Empty(t, esearchMailboxes(t, esearchCmdOK(t, fc, fr, "q3", `ESEARCH IN (mailboxes `+esearchQuote(public)+`) RETURN (ALL) ALL`)), "anyone read grants remain domain-scoped")

}
