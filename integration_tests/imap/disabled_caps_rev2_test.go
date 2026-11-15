//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	imapserver "github.com/migadu/sora/server/imap"
)

// TestIMAP_DisabledCapsRemovesRev2ImpliedCapabilities: disabled_caps naming a
// capability that IMAP4rev2 implies (RFC 9051) must remove it from CAPABILITY
// and refuse its commands, as client_filters already did. The server kept
// IMAP4rev2, through which go-imap still advertised and accepted IDLE and
// ESEARCH (#330).
func TestIMAP_DisabledCapsRemovesRev2ImpliedCapabilities(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account, _ := common.SetupIMAPServerWithRealS3Options(t, func(o *imapserver.IMAPServerOptions) {
		o.DisabledCaps = []string{"IDLE", "ESEARCH"}
	})
	t.Cleanup(server.Close)

	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("read greeting failed: %v", err)
	}
	tagN := 0
	do := func(cmd string) string {
		t.Helper()
		tagN++
		tag := fmt.Sprintf("d%d", tagN)
		if _, err := fmt.Fprintf(conn, "%s %s\r\n", tag, cmd); err != nil {
			t.Fatalf("write %q failed: %v", cmd, err)
		}
		return h3ReadTagged(t, r, tag)
	}

	if resp := do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password)); !strings.Contains(resp, " OK ") {
		t.Fatalf("LOGIN not OK:\n%s", resp)
	}
	resp := do("CAPABILITY")
	capLine, _, _ := strings.Cut(resp, "\r\n")
	caps := strings.Fields(capLine)
	for _, c := range []string{"IMAP4rev2", "IDLE", "ESEARCH"} {
		for _, got := range caps {
			if got == c {
				t.Errorf("CAPABILITY still offers %s:\n%s", c, capLine)
			}
		}
	}
	for _, c := range []string{"IMAP4rev1", "MOVE", "UIDPLUS", "LIST-EXTENDED"} {
		found := false
		for _, got := range caps {
			if got == c {
				found = true
			}
		}
		if !found {
			t.Errorf("CAPABILITY lost %s:\n%s", c, capLine)
		}
	}

	if resp := do("SELECT INBOX"); !strings.Contains(resp, " OK ") {
		t.Fatalf("SELECT not OK:\n%s", resp)
	}
	if resp := do("SEARCH RETURN (MIN) ALL"); !strings.Contains(resp, " BAD ") {
		t.Errorf("SEARCH RETURN (MIN) with ESEARCH disabled: want BAD, got:\n%s", resp)
	}
	// An accepted IDLE answers with a continuation and waits for DONE.
	tagN++
	tag := fmt.Sprintf("d%d", tagN)
	if _, err := fmt.Fprintf(conn, "%s IDLE\r\n", tag); err != nil {
		t.Fatalf("write IDLE failed: %v", err)
	}
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read IDLE response failed: %v", err)
	}
	if strings.HasPrefix(line, "+") {
		fmt.Fprintf(conn, "DONE\r\n")
		h3ReadTagged(t, r, tag)
		t.Errorf("IDLE with IDLE disabled was accepted: %q", line)
	} else if !strings.HasPrefix(line, tag+" BAD ") && !strings.HasPrefix(line, tag+" NO ") {
		t.Errorf("IDLE with IDLE disabled: want it refused, got %q", line)
	}
}
