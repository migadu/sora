//go:build integration

package imap_test

import (
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIMAP_EnvelopeSourceRoute: the second field of an ENVELOPE address is addr-adl, the
// "at-domain-list (source route and obs-route ABNF production from [RFC5322])" (RFC 9051
// §7.5.2, RFC 3501 §7.4.2). An address written "<@hop1,@hop2:user@domain>" reports its
// route there, in the message's own ENVELOPE and in the ENVELOPE of an attached
// message/rfc822 in BODYSTRUCTURE, in the form Dovecot gives it: each hop as "@" domain,
// joined by ",", without comments or white space (#2119). Other addresses keep NIL.
func TestIMAP_EnvelopeSourceRoute(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)

	rc.append("a", "INBOX", "From: Sender <@route:sender@example.com>\r\n"+
		"To: <@first (hop) , @second:to@example.com>, plain@example.com\r\n"+
		"Cc: team: <@route:member@example.com>;\r\n"+
		"Subject: outer\r\nDate: Thu, 18 Jul 1996 00:00:00 +0000\r\n"+
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n"+
		"--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"+
		"--b\r\nContent-Type: message/rfc822\r\n\r\n"+
		"From: <@inner:user@example.org>\r\n"+
		"To: <@one,@two:rcpt@example.org>, other@example.org\r\n"+
		"Subject: attached\r\nDate: Wed, 17 Jul 1996 02:23:25 +0000\r\n\r\nbody\r\n"+
		"--b--\r\n")

	_, tagged := rc.cmd("s", "SELECT INBOX")
	require.Contains(t, tagged, "OK")

	untagged, tagged := rc.cmd("e", "FETCH 1 (ENVELOPE)")
	require.Contains(t, tagged, "OK")
	require.Len(t, untagged, 1, "one FETCH response: %v", untagged)
	envelope := untagged[0]
	// From, and Sender and Reply-To, which default to it.
	from := `(("Sender" "@route" "sender" "example.com"))`
	assert.Contains(t, envelope, `"outer" `+from+` `+from+` `+from+` `, "From with its route, copied to Sender and Reply-To: %s", envelope)
	assert.Contains(t, envelope, `((NIL "@first,@second" "to" "example.com")(NIL NIL "plain" "example.com"))`, "To: the route stays with its own address: %s", envelope)
	assert.Contains(t, envelope, `((NIL NIL "team" NIL)(NIL "@route" "member" "example.com")(NIL NIL NIL NIL))`, "Cc: a routed group member: %s", envelope)

	untagged, tagged = rc.cmd("b", "FETCH 1 (BODYSTRUCTURE)")
	require.Contains(t, tagged, "OK")
	require.Len(t, untagged, 1, "one FETCH response: %v", untagged)
	attached := untagged[0]
	inner := `((NIL "@inner" "user" "example.org"))`
	assert.Contains(t, attached, `"attached" `+inner+` `+inner+` `+inner+` `, "attached From with its route: %s", attached)
	assert.Contains(t, attached, `((NIL "@one,@two" "rcpt" "example.org")(NIL NIL "other" "example.org"))`, "attached To: %s", attached)

	// The route is not part of the address: SEARCH matches the address, not the hops.
	for _, tc := range []struct {
		criteria string
		want     string
	}{
		{`FROM "sender@example.com"`, "* SEARCH 1"},
		{`TO "to@example.com"`, "* SEARCH 1"},
		{`FROM "@route"`, "* SEARCH"},
		{`TO "@first"`, "* SEARCH"},
	} {
		untagged, tagged = rc.cmd("q", "SEARCH "+tc.criteria)
		require.Contains(t, tagged, "OK")
		require.Len(t, untagged, 1, "SEARCH %s: %v", tc.criteria, untagged)
		assert.Equal(t, tc.want, untagged[0], "SEARCH %s", tc.criteria)
	}
}
