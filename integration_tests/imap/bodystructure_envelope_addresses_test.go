//go:build integration

package imap_test

import (
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIMAP_BodyStructureAttachedEnvelopeAddresses: the ENVELOPE of an attached message/rfc822
// part in BODYSTRUCTURE is built by go-imap's ExtractEnvelope when the message is stored. Its
// address lists must follow RFC 3501 section 7.4.2 like the message's own ENVELOPE:
//
//   - a group is a start record (mailbox = group name, host NIL), its members and an end
//     record (all NIL); an empty group is its start and end (migadu/go-imap#372);
//   - the mailbox/host split is at the last '@', so a quoted local part "a@b" stays the
//     mailbox (migadu/go-imap#375);
//   - every instance of a repeated address header contributes (migadu/go-imap#376).
//
// The address headers are message 4 of imaptest's fetch-envelope.mbox plus a quoted local
// part and a second To: field.
func TestIMAP_BodyStructureAttachedEnvelopeAddresses(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)

	rc.append("a", "INBOX", "From: alice@example.com\r\nTo: bob@example.com\r\n"+
		"Subject: fwd\r\nDate: Thu, 18 Jul 1996 00:00:00 +0000\r\n"+
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n"+
		"--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"+
		"--b\r\nContent-Type: message/rfc822\r\n\r\n"+
		"From: \"a@b\"@example.com\r\n"+
		"To: group: g1@d1.org, g2@d2.org;, group2: g3@d3.org;\r\n"+
		"Cc: group:;\r\n"+
		"To: second@example.net\r\n"+
		"Subject: attached\r\nDate: Wed, 17 Jul 1996 02:23:25 +0000\r\n\r\nbody\r\n"+
		"--b--\r\n")

	_, tagged := rc.cmd("s", "SELECT INBOX")
	require.Contains(t, tagged, "OK")
	untagged, tagged := rc.cmd("f", "FETCH 1 (BODYSTRUCTURE)")
	require.Contains(t, tagged, "OK")
	require.Len(t, untagged, 1, "one FETCH response: %v", untagged)
	// RFC 3501's env-to is "(" 1*address ")", with no SP between addresses; go-imap writes
	// them unspaced since migadu/go-imap#378, so the response is compared as sent.
	resp := untagged[0]
	require.Contains(t, resp, `"attached"`, "embedded envelope present: %s", resp)

	t.Run("groups", func(t *testing.T) {
		assert.Contains(t, resp,
			`(NIL NIL "group" NIL)(NIL NIL "g1" "d1.org")(NIL NIL "g2" "d2.org")(NIL NIL NIL NIL)`+
				`(NIL NIL "group2" NIL)(NIL NIL "g3" "d3.org")(NIL NIL NIL NIL)`,
			"To: groups must keep their start and end markers: %s", resp)
		assert.Contains(t, resp, `) ((NIL NIL "group" NIL)(NIL NIL NIL NIL)) NIL `,
			"Cc: an empty group is its start and end marker, not NIL: %s", resp)
	})
	t.Run("last_at", func(t *testing.T) {
		assert.Contains(t, resp, `((NIL NIL "a@b" "example.com"))`,
			`From: "a@b"@example.com splits at the last @: %s`, resp)
	})
	t.Run("repeated_to", func(t *testing.T) {
		assert.Contains(t, resp,
			`(NIL NIL "g3" "d3.org")(NIL NIL NIL NIL)(NIL NIL "second" "example.net")) `,
			"both To: fields must be in the envelope: %s", resp)
	})
}
