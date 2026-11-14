//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	imapserver "github.com/migadu/sora/server/imap"
)

// TestIMAP_DisabledBinaryFetchItems: RFC 9051 Appendix B, "IMAP4rev2
// incorporates a subset of functionality provided by the BINARY extension
// [RFC3516]; in particular, it includes additional FETCH items (BINARY,
// BINARY.PEEK, and BINARY.SIZE) but not extensions to the APPEND command."
// Disabling BINARY keeps IMAP4rev2, so FETCH must keep answering the items;
// it dropped them and could answer "* 1 FETCH ()" (#606). Once neither BINARY
// nor IMAP4rev2 is offered, the items are refused with BAD.
func TestIMAP_DisabledBinaryFetchItems(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	for _, tc := range []struct {
		name      string
		configure func(*imapserver.IMAPServerOptions)
		identify  bool // send ID so that the client filter applies
		enable    bool // ENABLE IMAP4rev2 before SELECT
		rev2      bool // the session still offers IMAP4rev2
	}{
		{"disabled_caps BINARY ENABLE IMAP4rev2", func(o *imapserver.IMAPServerOptions) {
			o.DisabledCaps = []string{"BINARY"}
		}, false, true, true},
		{"disabled_caps BINARY IMAP4rev1 client", func(o *imapserver.IMAPServerOptions) {
			o.DisabledCaps = []string{"BINARY"}
		}, false, false, true},
		{"client_filters BINARY ENABLE IMAP4rev2", func(o *imapserver.IMAPServerOptions) {
			o.CapabilityFilters = []config.ClientCapabilityFilter{{ClientName: "^buggy$", DisableCaps: []string{"BINARY"}}}
		}, true, true, true},
		{"disabled_caps BINARY IMAP4rev2", func(o *imapserver.IMAPServerOptions) {
			o.DisabledCaps = []string{"BINARY", "IMAP4rev2"}
		}, false, false, false},
		{"client_filters BINARY IMAP4rev2", func(o *imapserver.IMAPServerOptions) {
			o.CapabilityFilters = []config.ClientCapabilityFilter{{ClientName: "^buggy$", DisableCaps: []string{"BINARY", "IMAP4rev2"}}}
		}, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, account, _ := common.SetupIMAPServerWithRealS3Options(t, tc.configure)
			t.Cleanup(server.Close)

			conn, err := net.Dial("tcp", server.Address)
			if err != nil {
				t.Fatalf("dial failed: %v", err)
			}
			t.Cleanup(func() { conn.Close() })
			if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatalf("set connection deadline: %v", err)
			}
			r := bufio.NewReader(conn)
			if _, err := r.ReadString('\n'); err != nil {
				t.Fatalf("read greeting failed: %v", err)
			}
			tagN := 0
			do := func(cmd string) string {
				t.Helper()
				tagN++
				tag := fmt.Sprintf("b%d", tagN)
				if _, err := fmt.Fprintf(conn, "%s %s\r\n", tag, cmd); err != nil {
					t.Fatalf("write %q failed: %v", cmd, err)
				}
				return h3ReadTagged(t, r, tag)
			}
			status := func(resp string) string {
				lines := strings.Split(strings.TrimSpace(resp), "\r\n")
				_, s, _ := strings.Cut(lines[len(lines)-1], " ")
				return s
			}
			mustOK := func(cmd string) string {
				t.Helper()
				resp := do(cmd)
				if !strings.HasPrefix(status(resp), "OK ") {
					t.Fatalf("%s not OK:\n%s", cmd, resp)
				}
				return resp
			}

			mustOK(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
			if tc.identify {
				mustOK(`ID ("name" "buggy")`)
			}
			capLine, _, _ := strings.Cut(do("CAPABILITY"), "\r\n")
			caps := strings.Fields(capLine)
			if slices.Contains(caps, "BINARY") {
				t.Errorf("CAPABILITY still offers BINARY:\n%s", capLine)
			}
			if slices.Contains(caps, "IMAP4rev2") != tc.rev2 {
				t.Fatalf("CAPABILITY offers IMAP4rev2 = %v, want %v:\n%s", !tc.rev2, tc.rev2, capLine)
			}
			if tc.enable {
				if resp := mustOK("ENABLE IMAP4rev2"); !strings.Contains(resp, "* ENABLED IMAP4rev2") {
					t.Fatalf("ENABLE IMAP4rev2 did not enable it:\n%s", resp)
				}
			}

			// IMAP4rev2 includes only BINARY's FETCH side. Refuse a
			// synchronizing literal8 APPEND before requesting its bytes.
			if resp := do("APPEND INBOX ~{4}"); !strings.HasPrefix(status(resp), "BAD ") {
				t.Fatalf("literal8 APPEND with BINARY disabled: want BAD, got:\n%s", resp)
			}

			// "hello world" in base64, so BINARY answers differ from BODY's.
			msg := "From: a@example.com\r\nTo: b@example.com\r\nSubject: binary\r\n" +
				"MIME-Version: 1.0\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n" +
				"\r\naGVsbG8gd29ybGQ=\r\n"
			if _, err := fmt.Fprintf(conn, "a1 APPEND INBOX {%d+}\r\n%s\r\n", len(msg), msg); err != nil {
				t.Fatalf("write APPEND failed: %v", err)
			}
			if resp := h3ReadTagged(t, r, "a1"); !strings.Contains(resp, "a1 OK ") {
				t.Fatalf("APPEND not OK:\n%s", resp)
			}
			mustOK("SELECT INBOX")

			if tc.rev2 {
				for _, cmd := range []string{"FETCH 1 (BINARY.PEEK[1] BINARY.SIZE[1])", "UID FETCH 1:* (BINARY.PEEK[1] BINARY.SIZE[1])"} {
					resp := mustOK(cmd)
					if !strings.Contains(resp, "BINARY[1] ") || !strings.Contains(resp, "hello world") {
						t.Errorf("%s: want the decoded BINARY[1], got:\n%s", cmd, resp)
					}
					if !strings.Contains(resp, "BINARY.SIZE[1] 11") {
						t.Errorf("%s: want BINARY.SIZE[1] 11, got:\n%s", cmd, resp)
					}
				}
				// Decoding must preserve NUL and non-ASCII octets through a
				// literal8, with SIZE and partial offsets measured after decoding
				// (RFC 9051 sections 6.4.5 and 7.5.2).
				binaryMsg := "From: a@example.com\r\nTo: b@example.com\r\n" +
					"MIME-Version: 1.0\r\nContent-Type: application/octet-stream\r\n" +
					"Content-Transfer-Encoding: base64\r\n\r\nAAH/YQ==\r\n"
				mustOK(fmt.Sprintf("APPEND INBOX {%d+}\r\n%s", len(binaryMsg), binaryMsg))
				resp := mustOK("FETCH 2 (BINARY.PEEK[1] BINARY.SIZE[1])")
				if !strings.Contains(resp, "BINARY[1] ~{4}\r\n\x00\x01\xffa") || !strings.Contains(resp, "BINARY.SIZE[1] 4") {
					t.Errorf("decoded binary octets or size mismatch: %q", resp)
				}
				resp = mustOK("UID FETCH 2 (BINARY.PEEK[1]<1.2>)")
				if !strings.Contains(resp, "BINARY[1]<1> ~{2}\r\n\x01\xff") {
					t.Errorf("decoded partial offset/bytes mismatch: %q", resp)
				}
			} else {
				for _, cmd := range []string{"FETCH 1 (BINARY.PEEK[1])", "FETCH 1 (BINARY.SIZE[1])", "FETCH 1 (FLAGS BINARY.PEEK[1])", "UID FETCH 1:* (BINARY[1])"} {
					if resp := do(cmd); !strings.HasPrefix(status(resp), "BAD ") {
						t.Errorf("%s: want BAD, got:\n%s", cmd, resp)
					}
				}
			}
			if resp := mustOK("FETCH 1 (FLAGS)"); strings.Contains(resp, `\Seen`) {
				t.Errorf("a refused or peeked BINARY set \\Seen:\n%s", resp)
			}
		})
	}
}
