//go:build integration

package imap_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_SelectEmptyOrRepeatedParamGroupIsBAD: the SELECT/EXAMINE parameter
// list holds at least one parameter (RFC 4466 §3), and the QRESYNC parameter
// and its seq-match-data are fixed groups (RFC 7162 §7):
//
//	select-params       =  SP "(" select-param *(SP select-param) ")"
//	select-param        =/  "QRESYNC" SP "(" uidvalidity SP
//	                    mod-sequence-value [SP known-uids]
//	                    [SP seq-match-data] ")"
//	seq-match-data      =  "(" known-sequence-set SP known-uid-set ")"
//
// "SELECT INBOX ()" and "EXAMINE INBOX ()" were answered OK, "(QRESYNC ())" as a
// plain SELECT with no VANISHED, an empty seq-match-data was dropped, and a
// repeated group replaced the first (#1370). RFC 7162 §3.2.5: "If any parameter
// is not syntactically valid, the server returns the tagged BAD response, and
// the mailbox remains unselected."
func TestIMAP_SelectEmptyOrRepeatedParamGroupIsBAD(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	t.Cleanup(server.Close)

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
	msg := "From: a@example.com\r\nTo: b@example.com\r\nSubject: select params\r\n\r\nhello\r\n"
	u1 := c.appendMsg("INBOX", msg)
	u2 := c.appendMsg("INBOX", msg)
	u3 := c.appendMsg("INBOX", msg)
	selected, _ := c.do("SELECT INBOX")
	m := regexp.MustCompile(`\[UIDVALIDITY (\d+)\]`).FindStringSubmatch(strings.Join(selected, "\n"))
	if m == nil {
		t.Fatalf("SELECT INBOX: no UIDVALIDITY in:\n%s", strings.Join(selected, "\n"))
	}
	uv := m[1]
	c.do(fmt.Sprintf(`UID STORE %d +FLAGS.SILENT (\Deleted)`, u2))
	c.do("CLOSE") // expunges u2 and leaves no mailbox selected

	refused := func(cmd string) {
		t.Helper()
		tag := c.send(cmd)
		untagged, tagged := c.read(tag, cmd)
		if !strings.HasPrefix(tagged, tag+" BAD ") || len(untagged) != 0 {
			t.Errorf("%s: want a tagged BAD and no mailbox data, got:\n%s", cmd, strings.Join(append(untagged, tagged), "\n"))
		}
		// The mailbox remains unselected (RFC 7162 §3.2.5).
		if status := c.status("CLOSE"); strings.HasPrefix(status, "OK") {
			t.Errorf("CLOSE after %s = %q, want no mailbox selected", cmd, status)
		}
	}

	refused("SELECT INBOX ()")
	refused("EXAMINE INBOX ()")

	c.do("ENABLE QRESYNC")
	known := fmt.Sprintf("%d:%d", u1, u3)
	for _, cmd := range []string{
		"SELECT INBOX ()",
		"SELECT INBOX (QRESYNC ())",
		"EXAMINE INBOX (QRESYNC ())",
		"SELECT INBOX (QRESYNC (" + uv + " 1 ()))",
		"SELECT INBOX (QRESYNC (" + uv + " 1 " + known + " ()))",
		"SELECT INBOX (QRESYNC (" + uv + " 1 " + known + " (1 1 2 2)))",
		"SELECT INBOX (QRESYNC (" + uv + " 1 " + known + " (1 1) " + uv + " 1))",
	} {
		refused(cmd)
	}

	// The valid forms resynchronize: they report the expunged UID.
	want := fmt.Sprintf("* VANISHED (EARLIER) %d", u2)
	for _, cmd := range []string{
		"SELECT INBOX (QRESYNC (" + uv + " 1 " + known + "))",
		"EXAMINE INBOX (QRESYNC (" + uv + " 1 " + known + " (1 " + fmt.Sprint(u1) + ")))",
	} {
		untagged, _ := c.do(cmd)
		found := false
		for _, line := range untagged {
			if line == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: want %q, got:\n%s", cmd, want, strings.Join(untagged, "\n"))
		}
	}
}
