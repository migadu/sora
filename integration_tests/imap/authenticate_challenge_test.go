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

// dialAuthenticate connects to the server and reads the greeting.
func dialAuthenticate(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "* OK") {
		t.Fatalf("greeting = %q, %v", line, err)
	}
	return conn, reader
}

// readTagged reads lines until the tagged completion for tag and returns it.
func readTagged(t *testing.T, reader *bufio.Reader, tag string) string {
	t.Helper()
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading response to %s: %v (partial %q)", tag, err, line)
		}
		if strings.HasPrefix(line, tag+" ") {
			return strings.TrimRight(line, "\r\n")
		}
	}
}

// The PLAIN mechanism's first challenge is empty. A challenge is base64
// (RFC 9051 §6.2.2) and BASE64("") = "" (RFC 4648 §10), so the continuation
// request is "+" SP and nothing else, as in the RFC 9051 §6.2.2 PLAIN
// example. "=" marks a zero-length initial response only.
func TestIMAP_AuthenticatePlainEmptyChallenge(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	conn, reader := dialAuthenticate(t, server.Address)

	fmt.Fprintf(conn, "A1 AUTHENTICATE PLAIN\r\n")
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading continuation request: %v (partial %q)", err, line)
	}
	if line != "+ \r\n" {
		t.Fatalf("continuation request for the empty PLAIN challenge = %q, want %q", line, "+ \r\n")
	}

	creds := base64.StdEncoding.EncodeToString([]byte("\x00" + account.Email + "\x00" + account.Password))
	fmt.Fprintf(conn, "%s\r\n", creds)
	if got := readTagged(t, reader, "A1"); !strings.HasPrefix(got, "A1 OK") {
		t.Fatalf("AUTHENTICATE PLAIN = %q, want A1 OK", got)
	}
}

// A client response line too long for the server is a client error: the
// exchange is refused with a tagged BAD, not NO [SERVERBUG], and the rest of
// the line is skipped, so the connection stays usable.
func TestIMAP_AuthenticateOverlongResponse(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	conn, reader := dialAuthenticate(t, server.Address)

	fmt.Fprintf(conn, "A1 AUTHENTICATE PLAIN\r\n")
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+") {
		t.Fatalf("continuation request = %q, %v", line, err)
	}
	fmt.Fprintf(conn, "%s\r\n", strings.Repeat("A", 5000))
	got := readTagged(t, reader, "A1")
	if !strings.HasPrefix(got, "A1 BAD") || strings.Contains(got, "SERVERBUG") {
		t.Fatalf("over-long SASL response = %q, want A1 BAD without SERVERBUG", got)
	}

	fmt.Fprintf(conn, "A2 LOGIN %q %q\r\n", account.Email, account.Password)
	if got := readTagged(t, reader, "A2"); !strings.HasPrefix(got, "A2 OK") {
		t.Fatalf("LOGIN after the refused AUTHENTICATE = %q, want A2 OK", got)
	}
}

// A timeout cannot supply the missing line boundary of an oversized SASL
// response. The connection closes when that response cannot be drained.
func TestIMAP_AuthenticateUnterminatedOverlongResponseCloses(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, _ := common.SetupIMAPServer(t)
	defer server.Close()
	conn, reader := dialAuthenticate(t, server.Address)
	if err := conn.SetDeadline(time.Now().Add(40 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprint(conn, "A1 AUTHENTICATE PLAIN\r\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "+ \r\n" {
		t.Fatalf("continuation request = %q, %v", line, err)
	}
	if _, err := fmt.Fprint(conn, strings.Repeat("A", 5000)); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "* BYE ") {
		t.Fatalf("incomplete response = %q, %v; want BYE", line, err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	line, err := reader.ReadString('\n')
	if err == nil || line != "" {
		t.Fatalf("after BYE = %q, %v; want closed connection", line, err)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("connection remained open after BYE: %v", err)
	}
}

// "=" is a zero-length response only as the AUTHENTICATE initial response
// (RFC 9051 §9: initial-resp = (base64 / "=")). A reply to a continuation
// request is base64 (authenticate = ... *(CRLF base64)), where a zero-length
// response is an empty line and a lone pad character is invalid base64, which
// the server MUST reject with a tagged BAD (RFC 9051 §6.2.2). The IMAP proxy
// answers the same (TestPreAuthMalformedLoginAndAuthenticateAnswerBAD).
func TestIMAP_AuthenticateLonePadOnlyInInitialResponse(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	for _, tc := range []struct {
		name    string
		cmd     string
		replies []string // lines sent after each continuation request
		want    string
	}{
		// A zero-length PLAIN message reaches the mechanism and is refused there.
		{name: "pad as initial response", cmd: "A1 AUTHENTICATE PLAIN =", want: "A1 NO Invalid SASL PLAIN response"},
		{name: "empty continuation reply", cmd: "A1 AUTHENTICATE PLAIN", replies: []string{""}, want: "A1 NO Invalid SASL PLAIN response"},
		{name: "pad as continuation reply", cmd: "A1 AUTHENTICATE PLAIN", replies: []string{"="}, want: "A1 BAD Malformed SASL response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, reader := dialAuthenticate(t, server.Address)

			fmt.Fprintf(conn, "%s\r\n", tc.cmd)
			for _, reply := range tc.replies {
				if line, err := reader.ReadString('\n'); err != nil || line != "+ \r\n" {
					t.Fatalf("continuation request = %q, %v", line, err)
				}
				fmt.Fprintf(conn, "%s\r\n", reply)
			}
			if got := readTagged(t, reader, "A1"); got != tc.want {
				t.Fatalf("%s: got %q, want %q", tc.name, got, tc.want)
			}

			// Only the command was refused, not the connection.
			fmt.Fprintf(conn, "A2 LOGIN %q %q\r\n", account.Email, account.Password)
			if got := readTagged(t, reader, "A2"); !strings.HasPrefix(got, "A2 OK") {
				t.Fatalf("LOGIN after the refused AUTHENTICATE = %q, want A2 OK", got)
			}
		})
	}
}

// A reply to a continuation request is a base64 line (RFC 9051 §9:
// authenticate = ... *(CRLF base64), base64-char = ALPHA / DIGIT / "+" / "/").
// A CR inside it is outside the base64 alphabet, which the server MUST reject
// with a tagged BAD (RFC 9051 §6.2.2). Valid credentials with a CR spliced in
// must not log the client in.
func TestIMAP_AuthenticateReplyWithBareCRIsBad(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	creds := base64.StdEncoding.EncodeToString([]byte("\x00" + account.Email + "\x00" + account.Password))
	for _, tc := range []struct {
		name, reply string
	}{
		{name: "CR inside", reply: creds[:4] + "\r" + creds[4:]},
		{name: "CR before the CRLF", reply: creds + "\r"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, reader := dialAuthenticate(t, server.Address)

			fmt.Fprintf(conn, "A1 AUTHENTICATE PLAIN\r\n")
			if line, err := reader.ReadString('\n'); err != nil || line != "+ \r\n" {
				t.Fatalf("continuation request = %q, %v", line, err)
			}
			fmt.Fprintf(conn, "%s\r\n", tc.reply)
			if got, want := readTagged(t, reader, "A1"), "A1 BAD Malformed SASL response"; got != want {
				t.Fatalf("%s: got %q, want %q", tc.name, got, want)
			}

			// Still not authenticated: the same credentials, sent cleanly,
			// log in on the same connection.
			fmt.Fprintf(conn, "A2 AUTHENTICATE PLAIN %s\r\n", creds)
			if got := readTagged(t, reader, "A2"); !strings.HasPrefix(got, "A2 OK") {
				t.Fatalf("AUTHENTICATE after the refused one = %q, want A2 OK", got)
			}
		})
	}
}
