//go:build integration

package imap_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	imapserver "github.com/migadu/sora/server/imap"
)

// TestIMAP_DisabledCondStoreFetchItems: the MODSEQ FETCH data item and the
// CHANGEDSINCE FETCH modifier are CONDSTORE's (RFC 7162 §3.1.4). With CONDSTORE
// disabled they were parsed and dropped (#892): a lone MODSEQ was answered
// "* 1 FETCH ()", which msg-att does not allow (RFC 9051 §9: at least one
// item), and CHANGEDSINCE returned every message. RFC 4466 §2.4: "Any
// modifiers not defined by extensions that the server supports must be
// rejected with a BAD response", and FETCH answers invalid arguments with
// "BAD - command unknown or arguments invalid" (RFC 9051 §6.4.5). NOTIFY's
// MessageNew fetch-atts are parsed the same way (RFC 5465 §5.2).
func TestIMAP_DisabledCondStoreFetchItems(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	cmds := []string{
		"FETCH 1 (MODSEQ)",
		"FETCH 1 MODSEQ",
		"FETCH 1 (FLAGS MODSEQ)",
		"UID FETCH 1:* (MODSEQ)",
		"FETCH 1 (FLAGS) (CHANGEDSINCE 1)",
		"UID FETCH 1:* (FLAGS) (CHANGEDSINCE 1)",
		"NOTIFY SET (SELECTED (MessageNew (UID MODSEQ) MessageExpunge))",
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
			c.do("SELECT INBOX")

			for _, cmd := range cmds {
				untagged, tagged := c.read(c.send(cmd), cmd)
				resp := strings.Join(append(untagged, tagged), "\n")
				_, status, _ := strings.Cut(tagged, " ")
				var fetches []string
				for _, line := range untagged {
					if strings.Contains(line, " FETCH ") {
						fetches = append(fetches, line)
					}
				}
				if !tc.condstore {
					if !strings.HasPrefix(status, "BAD ") || len(fetches) > 0 {
						t.Errorf("%s: want BAD and no FETCH response, got:\n%s", cmd, resp)
					}
					continue
				}
				if !strings.HasPrefix(status, "OK ") {
					t.Errorf("%s: want OK, got:\n%s", cmd, resp)
					continue
				}
				// CHANGEDSINCE implicitly adds MODSEQ (RFC 7162 §3.1.4.1).
				if strings.HasPrefix(cmd, "NOTIFY") {
					continue
				}
				if strings.Contains(cmd, "MODSEQ") && len(fetches) == 0 {
					t.Errorf("%s: want a FETCH response, got:\n%s", cmd, resp)
				}
				for _, line := range fetches {
					if !strings.Contains(line, "MODSEQ (") {
						t.Errorf("%s: want MODSEQ in every FETCH response, got:\n%s", cmd, resp)
					}
				}
			}
			c.do("NOOP")
		})
	}
}

// TestIMAP_ClientFilterAfterNotifyLeavesOutModSeq: a NOTIFY watch whose
// MessageNew fetch-atts name MODSEQ, set while the session offered CONDSTORE,
// keeps asking for it after an ID-matched client filter withdraws CONDSTORE.
// Fetch writes MODSEQ whenever it is asked for, since the parser refuses it
// without CONDSTORE, and relies on the writer to leave it out here: MODSEQ is
// CONDSTORE's data item (RFC 7162 §3.1.4.2), and a session whose CAPABILITY
// lacks CONDSTORE does not offer the extension (RFC 7162 §3.1.1). The new
// message's FETCH still carries its UID, so it is never empty (RFC 9051 §9
// msg-att).
func TestIMAP_ClientFilterAfterNotifyLeavesOutModSeq(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account, _ := common.SetupIMAPServerWithRealS3Options(t, func(o *imapserver.IMAPServerOptions) {
		o.CapabilityFilters = []config.ClientCapabilityFilter{{ClientName: "^buggy$", DisableCaps: []string{"CONDSTORE"}}}
	})
	t.Cleanup(server.Close)
	login := fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password)

	watcher := dialRawIMAP(t, server.Address)
	watcher.do(login)
	watcher.do("SELECT INBOX")
	watcher.do("NOTIFY SET (SELECTED (MessageNew (UID MODSEQ) MessageExpunge))")
	watcher.do(`ID ("name" "buggy")`)
	capLines, _ := watcher.do("CAPABILITY")
	if caps := strings.Fields(strings.Join(capLines, " ")); slices.Contains(caps, "CONDSTORE") {
		t.Fatalf("CAPABILITY after ID: want no CONDSTORE, got:\n%s", strings.Join(capLines, "\n"))
	}

	other := dialRawIMAP(t, server.Address)
	other.do(login)
	other.appendMsg("INBOX", "From: a@example.com\r\nTo: b@example.com\r\nSubject: condstore\r\n\r\nhello\r\n")

	if err := watcher.conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var fetch string
	for fetch == "" {
		line, err := watcher.r.ReadString('\n')
		if err != nil {
			t.Fatalf("waiting for the MessageNew FETCH: %v", err)
		}
		if strings.Contains(line, " FETCH ") {
			fetch = strings.TrimRight(line, "\r\n")
		}
	}
	if !strings.Contains(fetch, "UID ") || strings.Contains(fetch, "MODSEQ") {
		t.Errorf("MessageNew FETCH: want UID and no MODSEQ, got: %s", fetch)
	}
}
