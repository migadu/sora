//go:build integration

package pop3_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// TestPOP3UTF8ModeChangesNothing pins that the UTF8 command (RFC 6856) does
// not change what the backend accepts or sends (issue #1911):
//
//   - a UTF-8 password is accepted with and without UTF8, and
//   - RETR and TOP return a message with raw UTF-8 headers (RFC 6532) and an
//     8bit body byte for byte, with and without UTF8, before or after login.
//
// Sora sends stored messages as they are in every mode, and its own reply texts
// are ASCII. It does not refuse such a message with -ERR [UTF8] or build a
// surrogate (RFC 6856 §2.1) for a client that did not send UTF8: the POP3 proxy
// hides UTF8 from CAPA by default (remote_use_utf8, for classic Outlook), so
// most clients never enable it and would lose those messages; see EnableUTF8.
func TestPOP3UTF8ModeChangesNothing(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := SetupPOP3ServerWithUploader(t)
	defer server.Close()

	const password = "pässwörd-日本"
	hash, err := db.GenerateBcryptHash(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	if err := server.TestServer.ResilientDB.UpdatePasswordWithRetry(context.Background(), account.Email, hash); err != nil {
		t.Fatalf("Failed to update password: %v", err)
	}

	const headers = "From: José Müller <jose@example.com>\r\n" +
		"To: bob@example.com\r\n" +
		"Subject: Grüße aus Zürich, 日本語\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n" +
		"\r\n"
	const msg = headers + "Hallo, schöne Grüße.\r\nこんにちは\r\n"
	tddAppendMessage(t, server, account.Email, msg)

	cases := []struct {
		name       string
		utf8Before bool // send UTF8 in the AUTHORIZATION state
		utf8After  bool // send UTF8 in the TRANSACTION state (classic Outlook)
	}{
		{name: "without UTF8"},
		{name: "UTF8 before login", utf8Before: true},
		{name: "UTF8 after login", utf8After: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", server.TestServer.Address)
			if err != nil {
				t.Fatalf("Failed to connect: %v", err)
			}
			defer conn.Close()
			r := bufio.NewReader(conn)

			cmd := func(line string) string {
				t.Helper()
				if _, err := fmt.Fprintf(conn, "%s\r\n", line); err != nil {
					t.Fatalf("Failed to send %q: %v", line, err)
				}
				resp, err := r.ReadString('\n')
				if err != nil {
					t.Fatalf("Failed to read reply to %q: %v", line, err)
				}
				return resp
			}
			mustOK := func(line string) {
				t.Helper()
				if resp := cmd(line); !strings.HasPrefix(resp, "+OK") {
					t.Fatalf("%s: got %q, want +OK", strings.Fields(line)[0], resp)
				}
			}

			if greeting, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(greeting, "+OK") {
				t.Fatalf("Bad greeting %q: %v", greeting, err)
			}
			if tc.utf8Before {
				mustOK("UTF8")
			}
			mustOK("USER " + account.Email)
			mustOK("PASS " + password)
			if tc.utf8After {
				mustOK("UTF8")
			}

			mustOK("RETR 1")
			if got := readEntireMultilineResponse(t, r); got != msg+".\r\n" {
				t.Errorf("RETR 1 changed the message:\n got %q\nwant %q", got, msg+".\r\n")
			}
			mustOK("TOP 1 0")
			if got := readEntireMultilineResponse(t, r); got != headers+".\r\n" {
				t.Errorf("TOP 1 0 changed the headers:\n got %q\nwant %q", got, headers+".\r\n")
			}
			mustOK("QUIT")
		})
	}
}
