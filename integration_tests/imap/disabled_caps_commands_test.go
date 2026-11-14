//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	imapserver "github.com/migadu/sora/server/imap"
)

// TestIMAP_DisabledCapsRefusesCommands: a capability withdrawn by disabled_caps
// or client_filters must not only leave CAPABILITY but also refuse its commands,
// as IDLE and ESEARCH already were. MOVE, NAMESPACE, STATUS=SIZE, METADATA and
// SORT kept working, and SORT=DISPLAY and ESORT stayed advertised without SORT
// (#508).
func TestIMAP_DisabledCapsRefusesCommands(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	disabled := []string{"MOVE", "NAMESPACE", "STATUS=SIZE", "METADATA", "SORT"}

	for _, tc := range []struct {
		name      string
		configure func(*imapserver.IMAPServerOptions)
		identify  bool
	}{
		{"disabled_caps", func(o *imapserver.IMAPServerOptions) { o.DisabledCaps = disabled }, false},
		{"client_filters", func(o *imapserver.IMAPServerOptions) {
			o.CapabilityFilters = []config.ClientCapabilityFilter{{ClientName: "^buggy$", DisableCaps: disabled}}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, account, _ := common.SetupIMAPServerWithRealS3Options(t, tc.configure)
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
				tag := fmt.Sprintf("x%d", tagN)
				if _, err := fmt.Fprintf(conn, "%s %s\r\n", tag, cmd); err != nil {
					t.Fatalf("write %q failed: %v", cmd, err)
				}
				return h3ReadTagged(t, r, tag)
			}
			mustOK := func(cmd string) string {
				t.Helper()
				resp := do(cmd)
				if !strings.Contains(resp, " OK ") {
					t.Fatalf("%s not OK:\n%s", cmd, resp)
				}
				return resp
			}
			wantBad := func(cmd string) {
				t.Helper()
				resp := do(cmd)
				if lines := strings.Split(strings.TrimSpace(resp), "\r\n"); !strings.Contains(lines[len(lines)-1], " BAD ") {
					t.Errorf("%s: want BAD, got:\n%s", cmd, resp)
				}
			}

			mustOK(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
			if tc.identify {
				mustOK(`ID ("name" "buggy")`)
			}

			capLine, _, _ := strings.Cut(do("CAPABILITY"), "\r\n")
			caps := strings.Fields(capLine)
			for _, c := range []string{"IMAP4rev2", "MOVE", "NAMESPACE", "STATUS=SIZE", "METADATA", "SORT", "SORT=DISPLAY", "ESORT"} {
				if slices.Contains(caps, c) {
					t.Errorf("CAPABILITY still offers %s:\n%s", c, capLine)
				}
			}
			for _, c := range []string{"IMAP4rev1", "LIST-STATUS", "UIDPLUS"} {
				if !slices.Contains(caps, c) {
					t.Errorf("CAPABILITY lost %s:\n%s", c, capLine)
				}
			}

			msg := "From: a@example.com\r\nTo: b@example.com\r\nSubject: disabled caps\r\n\r\nbody\r\n"
			if _, err := fmt.Fprintf(conn, "a1 APPEND INBOX {%d+}\r\n%s\r\n", len(msg), msg); err != nil {
				t.Fatalf("write APPEND failed: %v", err)
			}
			if resp := h3ReadTagged(t, r, "a1"); !strings.Contains(resp, "a1 OK ") {
				t.Fatalf("APPEND not OK:\n%s", resp)
			}
			mustOK("CREATE Moved")

			wantBad("NAMESPACE")
			wantBad("STATUS INBOX (SIZE)")
			wantBad(`LIST "" "INBOX" RETURN (STATUS (MESSAGES SIZE))`)
			wantBad(`GETMETADATA "" /shared/comment`)
			wantBad(`SETMETADATA "" (/private/comment "x")`)
			if resp := mustOK("STATUS INBOX (MESSAGES)"); !strings.Contains(resp, "MESSAGES 1") {
				t.Errorf("STATUS INBOX (MESSAGES): want MESSAGES 1, got:\n%s", resp)
			}

			mustOK("SELECT INBOX")
			wantBad("SORT (DATE) UTF-8 ALL")
			wantBad("UID SORT (DATE) UTF-8 ALL")
			wantBad("SORT RETURN (ALL) (DATE) UTF-8 ALL")
			wantBad("MOVE 1 Moved")
			wantBad("UID MOVE 1:* Moved")
			mustOK("UNSELECT")

			if resp := mustOK("STATUS Moved (MESSAGES)"); !strings.Contains(resp, "MESSAGES 0") {
				t.Errorf("a refused MOVE moved a message:\n%s", resp)
			}
		})
	}
}
