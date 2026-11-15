//go:build integration

package imap_test

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// TestIMAP_EnvelopeAbsentMessageIDIsNIL: a message without a Message-ID header is stored
// with a synthetic ID for duplicate detection, but its ENVELOPE must still report the
// header as absent. RFC 9051 section 7.5.2: "If the Date, Subject, In-Reply-To, and
// Message-ID header fields are absent in the [RFC5322] header, the corresponding member
// of the envelope is NIL". The go-imap client cannot parse the doubled brackets the
// synthetic ID used to come out with, so the response is checked on the wire.
func TestIMAP_EnvelopeAbsentMessageIDIsNIL(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)

	rc.append("a1", "INBOX", "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: no id\r\n\r\nbody\r\n")
	rc.append("a2", "INBOX", "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: with id\r\nMessage-ID: <present-851@example.com>\r\n\r\nbody\r\n")
	_, tagged := rc.cmd("s", "SELECT INBOX")
	require.Contains(t, tagged, "OK")

	untagged, tagged := rc.cmd("f", "FETCH 1:2 (ENVELOPE)")
	require.Contains(t, tagged, "OK")
	require.Len(t, untagged, 2, "one FETCH response per message: %v", untagged)

	absent, present := untagged[0], untagged[1]
	require.True(t, strings.HasSuffix(absent, " NIL NIL NIL NIL))"),
		"in-reply-to and message-id must be NIL for a message without them: %s", absent)
	require.NotContains(t, absent, "<", "no synthetic Message-ID may leak into the envelope: %s", absent)
	require.True(t, strings.HasSuffix(present, ` NIL "<present-851@example.com>"))`),
		"a real Message-ID is reported once bracketed: %s", present)
}
