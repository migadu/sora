//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_MalformedCommandIsBad pins the classification of a command the grammar
// refuses: it is the client's syntax, so the answer is BAD [CLIENTBUG], not
// NO [SERVERBUG] (which tells the client the server is broken and logs a server
// fault). Both cases used to leak out of the go-imap decoder as plain errors.
func TestIMAP_MalformedCommandIsBad(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("greeting: %v", err)
	}

	// tagged sends a command and returns its tagged completion line.
	tagged := func(tag, command string) string {
		t.Helper()
		fmt.Fprintf(conn, "%s %s\r\n", tag, command)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("reading response for %s: %v", tag, err)
			}
			if strings.HasPrefix(line, tag+" ") {
				return strings.TrimSpace(line)
			}
		}
	}

	if got := tagged("A001", fmt.Sprintf("LOGIN %s %s", account.Email, account.Password)); !strings.HasPrefix(got, "A001 OK") {
		t.Fatalf("login: %q", got)
	}
	if got := tagged("A002", "SELECT INBOX"); !strings.HasPrefix(got, "A002 OK") {
		t.Fatalf("select: %q", got)
	}

	for _, tc := range []struct {
		name string
		tag  string
		cmd  string
	}{
		// An unquoted argument containing a space: "test" is read as the next
		// search key and fails to parse as a sequence-set.
		{"unquoted search term", "A003", `SEARCH HEADER Subject fileinto test`},
		// Not modified UTF-7.
		{"invalid mailbox name", "A004", `SELECT "&"`},
		// A literal size beyond the decoder's sanity bound, refused before any
		// continuation request.
		{"oversized literal announcement", "A005", `SELECT {99999999999}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tagged(tc.tag, tc.cmd)
			if !strings.HasPrefix(got, tc.tag+" BAD ") || !strings.Contains(got, "[CLIENTBUG]") {
				t.Errorf("want %s BAD [CLIENTBUG] ..., got %q", tc.tag, got)
			}
			if strings.Contains(got, "SERVERBUG") {
				t.Errorf("malformed command reported as a server fault: %q", got)
			}
		})
	}

	// Control: the well-formed spelling of the same search is accepted.
	if got := tagged("A006", `SEARCH HEADER Subject "fileinto test"`); !strings.HasPrefix(got, "A006 OK") {
		t.Errorf("well-formed search: want A006 OK, got %q", got)
	}
}
