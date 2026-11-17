//go:build integration

package managesieve

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestManageSieve_InvalidQuotedEscapeRefused: in a quoted string a backslash may only
// escape DQUOTE or another backslash. RFC 5804 section 4:
//
//	quoted          = DQUOTE *1024QUOTED-CHAR DQUOTE
//	QUOTED-CHAR     = SAFE-UTF8-CHAR / "\" QUOTED-SPECIALS
//	QUOTED-SPECIALS = DQUOTE / "\"
//
// "a\b" is no quoted string, so every command with one is refused as a syntax error
// and does not run (#1807). Before the fix the backslash was dropped and the command
// ran on "ab": PUTSCRIPT "a\b" stored a script named "ab" and GETSCRIPT "a\b"
// returned it. When the refused line ends with a non-synchronizing literal, its body
// is already on the wire and the connection is closed instead of reading that body as
// the next command.
func TestManageSieve_InvalidQuotedEscapeRefused(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	plain := base64.StdEncoding.EncodeToString([]byte("\x00" + account.Email + "\x00" + account.Password))
	// A literal body that is a command, run if the body is misread as one.
	const smuggled = `DELETESCRIPT "ab"`
	cases := []struct {
		name   string
		auth   bool   // log in first
		send   string // sent as is
		closes bool   // the refused line committed a {N+} literal body
	}{
		{"PUTSCRIPT name", true, "PUTSCRIPT \"a\\b\" \"keep;\"\r\n", false},
		{"PUTSCRIPT content", true, "PUTSCRIPT \"new\" \"kee\\p;\"\r\n", false},
		{"CHECKSCRIPT", true, "CHECKSCRIPT \"kee\\p;\"\r\n", false},
		{"GETSCRIPT", true, "GETSCRIPT \"a\\b\"\r\n", false},
		{"SETACTIVE", true, "SETACTIVE \"a\\b\"\r\n", false},
		{"DELETESCRIPT", true, "DELETESCRIPT \"a\\b\"\r\n", false},
		{"RENAMESCRIPT old name", true, "RENAMESCRIPT \"a\\b\" \"new\"\r\n", false},
		{"RENAMESCRIPT new name", true, "RENAMESCRIPT \"ab\" \"ne\\w\"\r\n", false},
		{"HAVESPACE", true, "HAVESPACE \"a\\b\" 10\r\n", false},
		{"NOOP tag", true, "NOOP \"ta\\g\"\r\n", false},
		{"after a literal argument", true, "RENAMESCRIPT {2+}\r\nab \"ne\\w\"\r\n", false},
		{"AUTHENTICATE mechanism", false, "AUTHENTICATE \"PL\\AIN\" \"" + plain + "\"\r\n", false},
		{"AUTHENTICATE initial response", false, "AUTHENTICATE \"PLAIN\" \"" + plain[:4] + "\\" + plain[4:] + "\"\r\n", false},
		{"LOGIN", false, fmt.Sprintf("LOGIN \"%s\" \"\\%s\"\r\n", account.Email, account.Password), false},
		{"PUTSCRIPT name, non-sync literal content", true, fmt.Sprintf("PUTSCRIPT \"a\\b\" {%d+}\r\n%s\r\n", len(smuggled), smuggled), true},
		{"AUTHENTICATE mechanism, literal response", false, fmt.Sprintf("AUTHENTICATE \"PL\\AIN\" {%d+}\r\n%s\r\n", len(plain), plain), true},
	}

	dial := func(t *testing.T) (net.Conn, *bufio.Reader) {
		t.Helper()
		conn, err := net.Dial("tcp", server.Address)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		return conn, bufio.NewReader(conn)
	}
	// reply reads up to the status line and returns it with the data lines before it.
	reply := func(t *testing.T, r *bufio.Reader) (string, []string) {
		t.Helper()
		var data []string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("read: %v (data so far %q)", err, data)
			}
			line = strings.TrimRight(line, "\r\n")
			if strings.HasPrefix(line, "OK") || strings.HasPrefix(line, "NO") || strings.HasPrefix(line, "BYE") {
				return line, data
			}
			data = append(data, line)
		}
	}
	send := func(t *testing.T, conn net.Conn, s string) {
		t.Helper()
		if _, err := conn.Write([]byte(s)); err != nil {
			t.Fatalf("send %q: %v", s, err)
		}
	}
	login := func(t *testing.T, conn net.Conn, r *bufio.Reader) {
		t.Helper()
		send(t, conn, `AUTHENTICATE "PLAIN" "`+plain+"\"\r\n")
		if got, _ := reply(t, r); !strings.HasPrefix(got, "OK") {
			t.Fatalf("AUTHENTICATE: %q", got)
		}
	}
	listScripts := func(t *testing.T, conn net.Conn, r *bufio.Reader) string {
		t.Helper()
		send(t, conn, "LISTSCRIPTS\r\n")
		got, data := reply(t, r)
		if got != "OK" {
			t.Fatalf("LISTSCRIPTS: %q", got)
		}
		return strings.Join(data, "\n")
	}

	// The script the refused commands would have read, activated, renamed or deleted.
	conn, r := dial(t)
	reply(t, r)
	login(t, conn, r)
	send(t, conn, "PUTSCRIPT \"ab\" \"keep;\"\r\n")
	if got, _ := reply(t, r); !strings.HasPrefix(got, "OK") {
		t.Fatalf("PUTSCRIPT \"ab\": %q", got)
	}
	want := listScripts(t, conn, r)
	conn.Close()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, r := dial(t)
			if greeting, _ := reply(t, r); !strings.HasPrefix(greeting, "OK") {
				t.Fatalf("greeting: %q", greeting)
			}
			if tc.auth {
				login(t, conn, r)
			}

			send(t, conn, tc.send)
			got, data := reply(t, r)
			if !strings.HasPrefix(got, `NO "Invalid command syntax:`) || len(data) > 0 {
				t.Fatalf("%q: reply %q (data %q), want NO \"Invalid command syntax: ...\"", tc.send, got, data)
			}

			switch {
			case tc.closes:
				if line, err := r.ReadString('\n'); err == nil {
					t.Fatalf("%q: connection still open after the refusal, got %q", tc.send, line)
				}
				conn, r = dial(t)
				reply(t, r)
				login(t, conn, r)
			case !tc.auth:
				// Still not logged in: the same credentials log in on this connection.
				login(t, conn, r)
			}

			// Nothing was stored, renamed, activated or deleted.
			if got := listScripts(t, conn, r); got != want {
				t.Fatalf("LISTSCRIPTS after %q: %q, want %q", tc.send, got, want)
			}
		})
	}
}
