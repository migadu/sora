//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIMAP_SharedNameViewsMatchSelectedMailbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, viewer := common.SetupIMAPServer(t)
	defer server.Close()
	name := fmt.Sprintf("Shared/Dup-%d", common.GetTimestamp())
	for i := range 2 {
		email, password := createSecondUser(t, server, "example.com", fmt.Sprintf("nameowner%d", i))
		conn, r := esearchDialLogin(t, server, email, password)
		defer conn.Close()
		esearchCreate(t, conn, r, "a1", name)
		for j := 0; j <= i; j++ {
			esearchAppend(t, conn, r, fmt.Sprintf("a2%d", j), name, "body")
		}
		esearchCmdOK(t, conn, r, "a3", "SETACL "+esearchQuote(name)+" "+esearchQuote(viewer.Email)+" lr")
	}
	conn, r := esearchDialLogin(t, server, viewer.Email, viewer.Password)
	defer conn.Close()
	selected := esearchCmdOK(t, conn, r, "v1", "SELECT "+esearchQuote(name))
	require.Contains(t, selected, "* 1 EXISTS", "oldest direct grant is the addressable mailbox")
	var uidValidity string
	for _, line := range selected {
		if _, rest, ok := strings.Cut(line, "[UIDVALIDITY "); ok {
			uidValidity, _, _ = strings.Cut(rest, "]")
		}
	}
	require.NotEmpty(t, uidValidity)
	esearchCmdOK(t, conn, r, "v2", "SUBSCRIBE "+esearchQuote(name))
	for i, command := range []string{
		`LIST "" ` + esearchQuote(name) + ` RETURN (STATUS (MESSAGES UIDVALIDITY))`,
		`LSUB "" ` + esearchQuote(name),
	} {
		lines := esearchCmdOK(t, conn, r, fmt.Sprintf("l%d", i), command)
		var listings []string
		for _, line := range lines {
			if strings.HasPrefix(line, "* LIST ") || strings.HasPrefix(line, "* LSUB ") {
				listings = append(listings, line)
			}
			if strings.HasPrefix(line, "* STATUS ") {
				assert.Contains(t, line, "MESSAGES 1")
				assert.Contains(t, line, "UIDVALIDITY "+uidValidity)
			}
		}
		assert.Len(t, listings, 1, "%s: %q", command, lines)
	}
	for i, source := range []string{"mailboxes " + esearchQuote(name), "subtree " + esearchQuote(name), "selected"} {
		lines := esearchCmdOK(t, conn, r, fmt.Sprintf("q%d", i), "ESEARCH IN ("+source+") RETURN (ALL) ALL")
		var results []string
		for _, line := range lines {
			if strings.HasPrefix(line, "* ESEARCH ") {
				results = append(results, line)
				assert.Contains(t, line, "UIDVALIDITY "+uidValidity)
				assert.True(t, strings.HasSuffix(line, " UID ALL 1"), "%s", line)
			}
		}
		assert.Len(t, results, 1, "ESEARCH IN (%s): %q", source, lines)
	}
}
