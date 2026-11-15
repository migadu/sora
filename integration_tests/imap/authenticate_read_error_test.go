//go:build integration

package imap_test

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// startAuthenticatePlain sends AUTHENTICATE PLAIN without an initial response,
// waits for the continuation request and writes partial, which has no line
// ending.
func startAuthenticatePlain(t *testing.T, conn net.Conn, reader *bufio.Reader, partial string) {
	t.Helper()
	if _, err := fmt.Fprint(conn, "A1 AUTHENTICATE PLAIN\r\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "+ \r\n" {
		t.Fatalf("continuation request = %q, %v", line, err)
	}
	if _, err := fmt.Fprint(conn, partial); err != nil {
		t.Fatal(err)
	}
}

// readAllUntilClosed returns every line the server sends until it closes the
// connection, failing the test if the connection is still open at the
// deadline.
func readAllUntilClosed(t *testing.T, conn net.Conn, reader *bufio.Reader, deadline time.Duration) []string {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(deadline)); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatalf("connection still open after %v; read %q", deadline, lines)
			}
			return lines
		}
		lines = append(lines, strings.TrimRight(line, "\r\n"))
	}
}

// A client that closes its side after the AUTHENTICATE continuation request
// has not caused a server failure: the connection ends without a tagged
// NO [SERVERBUG]. Octets it sent before closing are not a response, which is
// "a single line" (RFC 9051 §6.2.2), so even valid credentials without the
// line ending do not authenticate.
func TestIMAP_AuthenticateResponseCutOffByClose(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	creds := base64.StdEncoding.EncodeToString([]byte("\x00" + account.Email + "\x00" + account.Password))
	for _, tc := range []struct{ name, partial string }{
		{name: "nothing sent", partial: ""},
		{name: "credentials without line ending", partial: creds},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, reader := dialAuthenticate(t, server.Address)
			startAuthenticatePlain(t, conn, reader, tc.partial)
			if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if lines := readAllUntilClosed(t, conn, reader, 5*time.Second); len(lines) != 0 {
				t.Fatalf("after the client closed got %q, want the connection closed without a response", lines)
			}
		})
	}
}

// A client that goes silent mid-exchange is timed out with an untagged BYE
// and the connection closes; the credentials it sent without a line ending are
// not authenticated against.
func TestIMAP_AuthenticateResponseCutOffByTimeout(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	conn, reader := dialAuthenticate(t, server.Address)
	creds := base64.StdEncoding.EncodeToString([]byte("\x00" + account.Email + "\x00" + account.Password))
	startAuthenticatePlain(t, conn, reader, creds)

	lines := readAllUntilClosed(t, conn, reader, 40*time.Second)
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "* BYE ") {
		t.Fatalf("after the read timeout got %q, want one untagged BYE and the connection closed", lines)
	}
}
