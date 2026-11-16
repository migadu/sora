//go:build integration

package imap_test

import (
	"fmt"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIMAP_BodyStructureAttachedEnvelopeDateObsoleteZone: the envelope of an attached
// message/rfc822 part in BODYSTRUCTURE reads an alphabetic Date: zone at the offset RFC 5322
// section 4.3 gives it, as the message's own ENVELOPE does (TestIMAP_EnvelopeDateObsoleteZone).
// The body structure is built at APPEND and was given net/mail's reading of the zone in the
// server's time.Local: PDT came out as +0000 on a server in UTC, and a lower-case zone as NIL.
// At most one of PDT and EST can be the server's in July.
//
// A zone that is malformed or not defined keeps the date and time as written with the zone
// "-0000", through the stored body structure (RFC 5256 section 2.2: "If the time zone is
// invalid, the date and time SHOULD be treated as UTC"). Before, Z was written "+0000" and
// GMT+1 was NIL.
func TestIMAP_BodyStructureAttachedEnvelopeDateObsoleteZone(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)

	dates := []struct{ header, envelope string }{
		{"Wed, 17 Jul 1996 02:23:25 PDT", `"Wed, 17 Jul 1996 02:23:25 -0700"`},
		{"Wed, 17 Jul 1996 02:23:25 EST", `"Wed, 17 Jul 1996 02:23:25 -0500"`},
		{"Wed, 17 Jul 1996 02:23:25 pdt", `"Wed, 17 Jul 1996 02:23:25 -0700"`},
		{"Wed, 17 Jul 1996 02:23:25 Z", `"Wed, 17 Jul 1996 02:23:25 -0000"`},
		{"Wed, 17 Jul 1996 02:23:25 GMT+1", `"Wed, 17 Jul 1996 02:23:25 -0000"`},
		{"Wed, 17 Jul 1996 02:23:25 +01", `"Wed, 17 Jul 1996 02:23:25 -0000"`},
		{"Wed, 17 Jul 1996 02:23:25 +0000", `"Wed, 17 Jul 1996 02:23:25 +0000"`},
	}
	for i, d := range dates {
		rc.append(fmt.Sprintf("a%d", i), "INBOX", "From: alice@example.com\r\nTo: bob@example.com\r\n"+
			"Subject: fwd\r\nDate: Thu, 18 Jul 1996 00:00:00 +0000\r\n"+
			"Content-Type: multipart/mixed; boundary=b\r\n\r\n"+
			"--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"+
			"--b\r\nContent-Type: message/rfc822\r\n\r\n"+
			fmt.Sprintf("From: carol@example.org\r\nSubject: attached %d\r\nDate: %s\r\n\r\nbody\r\n", i, d.header)+
			"--b--\r\n")
	}
	_, tagged := rc.cmd("s", "SELECT INBOX")
	require.Contains(t, tagged, "OK")
	untagged, tagged := rc.cmd("f", "FETCH 1:* (BODYSTRUCTURE)")
	require.Contains(t, tagged, "OK")
	require.Len(t, untagged, len(dates), "one FETCH response per message: %v", untagged)
	for i, d := range dates {
		assert.Contains(t, untagged[i], fmt.Sprintf(`(%s "attached %d" `, d.envelope, i),
			"attached Date: %s must be read at its RFC 5322 offset: %s", d.header, untagged[i])
	}
}
