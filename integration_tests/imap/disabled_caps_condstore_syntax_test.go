//go:build integration

package imap_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	imapserver "github.com/migadu/sora/server/imap"
)

// TestIMAP_DisabledCondStoreSyntax: besides FETCH and STORE, CONDSTORE "adds a
// new MODSEQ search criterion", "defines an additional CONDSTORE parameter to
// SELECT/EXAMINE commands" and "adds the HIGHESTMODSEQ status data item to the
// STATUS command" (RFC 7162 §3.1 e, h, i). With CONDSTORE disabled they were
// accepted (#1017): the MODSEQ key was dropped, so SEARCH MODSEQ matched every
// message whatever the mod-sequence, SELECT (CONDSTORE) was answered OK and
// STATUS (HIGHESTMODSEQ) was answered "HIGHESTMODSEQ 0". RFC 4466 §2.1: "Any
// parameter not defined by extensions that the server supports must be
// rejected with a BAD response", and SELECT, STATUS and SEARCH answer invalid
// arguments with "BAD - command unknown or arguments invalid" (RFC 9051
// §6.3.2, §6.3.11, §6.4.4). LIST-STATUS reads the same status items (RFC 5819).
func TestIMAP_DisabledCondStoreSyntax(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// The largest mod-sequence (RFC 7162 §7: mod-sequence-valzer is at most
	// 9223372036854775807): the message's is far below it, so none of the
	// searches may match it.
	const top = "9223372036854775807"
	// Sent in the authenticated state.
	authCmds := []string{
		"STATUS INBOX (HIGHESTMODSEQ)",
		"STATUS INBOX (MESSAGES HIGHESTMODSEQ)",
		`LIST "" "INBOX" RETURN (STATUS (MESSAGES HIGHESTMODSEQ))`,
		"SELECT INBOX (CONDSTORE)",
		"EXAMINE INBOX (CONDSTORE)",
	}
	// Sent with INBOX selected.
	selectedCmds := []string{
		"SEARCH MODSEQ " + top,
		"UID SEARCH MODSEQ " + top,
		`SEARCH MODSEQ "/flags/\\Seen" all ` + top,
		"SEARCH OR MODSEQ " + top + " SEEN",
		"SEARCH RETURN (COUNT) MODSEQ " + top,
		"SORT (ARRIVAL) UTF-8 MODSEQ " + top,
		"THREAD REFERENCES UTF-8 MODSEQ " + top,
	}
	for _, tc := range []struct {
		name      string
		configure func(*imapserver.IMAPServerOptions)
		identify  bool // send ID so that the client filter applies
		condstore bool // the session offers CONDSTORE
	}{
		{"CONDSTORE offered", nil, false, true},
		{"disabled_caps CONDSTORE", func(o *imapserver.IMAPServerOptions) {
			o.DisabledCaps = []string{"CONDSTORE"}
		}, false, false},
		{"client_filters CONDSTORE", func(o *imapserver.IMAPServerOptions) {
			o.CapabilityFilters = []config.ClientCapabilityFilter{{ClientName: "^buggy$", DisableCaps: []string{"CONDSTORE"}}}
		}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, account, _ := common.SetupIMAPServerWithRealS3Options(t, tc.configure)
			t.Cleanup(server.Close)

			c := dialRawIMAP(t, server.Address)
			c.do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
			if tc.identify {
				c.do(`ID ("name" "buggy")`)
			}
			capLines, _ := c.do("CAPABILITY")
			caps := strings.Fields(strings.Join(capLines, " "))
			if slices.Contains(caps, "CONDSTORE") != tc.condstore || (!tc.condstore && slices.Contains(caps, "QRESYNC")) {
				t.Fatalf("CAPABILITY: want CONDSTORE = %v, and no QRESYNC without it, got:\n%s", tc.condstore, strings.Join(capLines, "\n"))
			}
			c.appendMsg("INBOX", "From: a@example.com\r\nTo: b@example.com\r\nSubject: condstore\r\n\r\nhello\r\n")

			check := func(cmd string, served func(untagged []string) bool) {
				t.Helper()
				untagged, tagged := c.read(c.send(cmd), cmd)
				resp := strings.Join(append(untagged, tagged), "\n")
				_, status, _ := strings.Cut(tagged, " ")
				if !tc.condstore {
					// Refused before the backend sees it: nothing but the
					// tagged BAD, and no mailbox selected by SELECT/EXAMINE.
					if !strings.HasPrefix(status, "BAD ") || len(untagged) > 0 {
						t.Errorf("%s: want only a tagged BAD, got:\n%s", cmd, resp)
					}
					return
				}
				if !strings.HasPrefix(status, "OK ") || !served(untagged) {
					t.Errorf("%s: want it answered, got:\n%s", cmd, resp)
				}
			}

			for _, cmd := range authCmds {
				check(cmd, func(untagged []string) bool {
					return slices.ContainsFunc(untagged, func(l string) bool { return strings.Contains(l, "HIGHESTMODSEQ ") })
				})
			}

			c.do("SELECT INBOX")
			for _, cmd := range selectedCmds {
				check(cmd, func(untagged []string) bool {
					for _, l := range untagged {
						for _, prefix := range []string{"* SEARCH", "* SORT", "* THREAD"} {
							if rest, ok := strings.CutPrefix(l, prefix); ok && strings.TrimSpace(rest) != "" {
								return false // matched the message
							}
						}
						if strings.HasPrefix(l, "* ESEARCH") && !strings.HasSuffix(l, " COUNT 0") {
							return false
						}
					}
					return true
				})
			}
			c.do("NOOP")
		})
	}
}
