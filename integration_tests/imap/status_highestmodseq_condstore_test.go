//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_StatusHighestModSeqEnablesCondStore checks that STATUS (HIGHESTMODSEQ)
// makes the client CONDSTORE-aware. RFC 7162 §3.1 lists "a STATUS (HIGHESTMODSEQ)
// command" among the CONDSTORE enabling commands: "Once a client issues a
// CONDSTORE enabling command, it has announced itself as a "CONDSTORE-aware
// client". The server MUST then include mod-sequence data in all subsequent
// untagged FETCH responses (until the connection is closed), whether they were
// caused by a regular STORE, a STORE with an UNCHANGEDSINCE modifier, or an
// external agent."
//
// LIST ... RETURN (STATUS (HIGHESTMODSEQ)) (RFC 5819) asks for the same STATUS
// data item and counts as well. STATUS without HIGHESTMODSEQ is the control.
// A late client filter must preserve enabled CONDSTORE (#1071), while STATUS
// must not implicitly enable QRESYNC or permit its VANISHED modifier (#1187).
func TestIMAP_StatusHighestModSeqEnablesCondStore(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Subtest names become account local parts, so they avoid parentheses.
	for _, tt := range []struct {
		name       string
		cmd        string
		wantStatus string
		wantModSeq bool
	}{
		{
			name:       "status_highestmodseq",
			cmd:        "STATUS INBOX (HIGHESTMODSEQ)",
			wantStatus: "* STATUS INBOX (HIGHESTMODSEQ ",
			wantModSeq: true,
		},
		{
			name:       "list_return_status_highestmodseq",
			cmd:        `LIST "" INBOX RETURN (STATUS (HIGHESTMODSEQ))`,
			wantStatus: "* STATUS INBOX (HIGHESTMODSEQ ",
			wantModSeq: true,
		},
		{
			name:       "status_messages",
			cmd:        "STATUS INBOX (MESSAGES)",
			wantStatus: "* STATUS INBOX (MESSAGES 1)",
			wantModSeq: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server, account := setupIMAPServerWithCapabilityFilters(t, []config.ClientCapabilityFilter{{
				ClientName:    "late-filter",
				ClientVersion: ".*",
				DisableCaps:   []string{"CONDSTORE", "QRESYNC"},
			}})
			defer server.Close()

			seedMessage(t, server, account)

			c := dialRawIMAP(t, server.Address)
			c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))

			untagged, _ := c.do(tt.cmd)
			if !hasLinePrefix(untagged, tt.wantStatus) {
				t.Fatalf("%s: want a %q response, got %q", tt.cmd, tt.wantStatus, untagged)
			}

			c.do("SELECT INBOX")
			if tt.wantModSeq {
				if status := c.status("UID FETCH 1:* (FLAGS) (CHANGEDSINCE 1 VANISHED)"); !strings.HasPrefix(status, "BAD ") {
					t.Fatalf("STATUS must not enable QRESYNC: VANISHED without ENABLE returned %s", status)
				}
			}
			c.do(`ID ("name" "late-filter" "version" "1")`)
			caps, _ := c.do("CAPABILITY")
			capList := " " + strings.Join(caps, " ") + " "
			if got := strings.Contains(capList, " CONDSTORE "); got != tt.wantModSeq {
				t.Fatalf("after %s and late ID, CONDSTORE advertised = %v, want %v: %q", tt.cmd, got, tt.wantModSeq, caps)
			}
			if strings.Contains(capList, " QRESYNC ") {
				t.Fatalf("late ID must withdraw unenabled QRESYNC: %q", caps)
			}

			// A FETCH caused by this session's own STORE.
			untagged, _ = c.do(`STORE 1 +FLAGS (\Seen)`)
			fetchLine := findUnsolicitedFetch(untagged)
			if fetchLine == "" {
				t.Fatalf("STORE: no FETCH response with FLAGS, got %q", untagged)
			}
			if got := strings.Contains(fetchLine, "MODSEQ ("); got != tt.wantModSeq {
				t.Errorf("after %s, STORE FETCH = %q: MODSEQ present = %v, want %v", tt.cmd, fetchLine, got, tt.wantModSeq)
			}

			// A FETCH caused by an external agent (another session).
			other := dialRawIMAP(t, server.Address)
			other.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
			other.do("SELECT INBOX")
			other.do(`STORE 1 +FLAGS.SILENT (\Flagged)`)
			other.do("LOGOUT")

			untagged, _ = c.do("NOOP")
			fetchLine = findUnsolicitedFetch(untagged)
			if fetchLine == "" {
				t.Fatalf("NOOP: no unsolicited FETCH for the other session's flag change, got %q", untagged)
			}
			if got := strings.Contains(fetchLine, "MODSEQ ("); got != tt.wantModSeq {
				t.Errorf("after %s, unsolicited FETCH = %q: MODSEQ present = %v, want %v", tt.cmd, fetchLine, got, tt.wantModSeq)
			}
		})
	}
}

func hasLinePrefix(lines []string, prefix string) bool {
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}
