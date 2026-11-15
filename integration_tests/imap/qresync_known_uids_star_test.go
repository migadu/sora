//go:build integration

package imap_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_QResyncSelectRefusesZeroUIDValidityAndStar: RFC 7162 §7 has
//
//	uidvalidity         =  nz-number
//	known-uids          =  sequence-set
//	                    ;; Sequence of UIDs; "*" is not allowed.
//	known-sequence-set  =  sequence-set
//	                    ;; ... * is not allowed.
//	known-uid-set       =  sequence-set
//	                    ;; ... * is not allowed.
//
// and §3.2.5: "If any parameter is not syntactically valid, the server returns
// the tagged BAD response, and the mailbox remains unselected." A known-uids of
// "*" reached the backend as UID 0 and came back as "VANISHED (EARLIER) *", and
// "1:*" reported no expunges at all; uidvalidity 0 selected the mailbox with the
// parameter ignored (#1263).
func TestIMAP_QResyncSelectRefusesZeroUIDValidityAndStar(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	t.Cleanup(server.Close)

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
	msg := "From: a@example.com\r\nTo: b@example.com\r\nSubject: qresync\r\n\r\nhello\r\n"
	u1 := c.appendMsg("INBOX", msg)
	u2 := c.appendMsg("INBOX", msg)
	u3 := c.appendMsg("INBOX", msg)
	c.do("ENABLE QRESYNC")
	selected, _ := c.do("SELECT INBOX")
	m := regexp.MustCompile(`\[UIDVALIDITY (\d+)\]`).FindStringSubmatch(strings.Join(selected, "\n"))
	if m == nil {
		t.Fatalf("SELECT INBOX: no UIDVALIDITY in:\n%s", strings.Join(selected, "\n"))
	}
	uv := m[1]
	c.do(fmt.Sprintf(`UID STORE %d +FLAGS.SILENT (\Deleted)`, u2))
	c.do("CLOSE") // expunges u2 and leaves no mailbox selected

	known := fmt.Sprintf("%d:%d", u1, u3)
	for _, params := range []string{
		"(QRESYNC (0 1))",
		"(QRESYNC (0 1 " + known + "))",
		"(QRESYNC (" + uv + " 1 *))",
		"(QRESYNC (" + uv + " 1 1:*))",
		"(QRESYNC (" + uv + " 1 " + known + " (1:* 1:*)))",
		"(QRESYNC (" + uv + " 1 " + known + " (1:* " + known + ")))",
		"(QRESYNC (" + uv + " 1 " + known + " (1:2 1:*)))",
	} {
		cmd := "SELECT INBOX " + params
		tag := c.send(cmd)
		untagged, tagged := c.read(tag, cmd)
		resp := strings.Join(append(untagged, tagged), "\n")
		if !strings.HasPrefix(tagged, tag+" BAD ") || len(untagged) != 0 {
			t.Errorf("%s: want a tagged BAD and no mailbox data, got:\n%s", cmd, resp)
		}
		// The mailbox remains unselected (RFC 7162 §3.2.5).
		if status := c.status("CLOSE"); strings.HasPrefix(status, "OK") {
			t.Errorf("CLOSE after %s = %q, want no mailbox selected", cmd, status)
		}
	}

	// The valid form still reports the expunged UID.
	cmd := "SELECT INBOX (QRESYNC (" + uv + " 1 " + known + "))"
	untagged, _ := c.do(cmd)
	want := fmt.Sprintf("* VANISHED (EARLIER) %d", u2)
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
