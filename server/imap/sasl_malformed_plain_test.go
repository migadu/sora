package imap

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// A PLAIN message that is not three NUL-separated fields (RFC 4616 §2) is the
// client's error. It is refused like the IMAP proxy refuses it (NO Invalid SASL
// PLAIN response), not answered NO [SERVERBUG] and logged as a server failure,
// whether it came as the initial response or as the reply to the continuation
// request, and the connection stays usable. It is refused before the
// credentials are looked at, so no database is needed.
func TestAuthenticateMalformedPlainIsNotServerBug(t *testing.T) {
	srv, addr := newReloadTestServer(t, IMAPServerOptions{})
	serveReloadTestServer(t, srv, addr)

	cases := []struct {
		name string
		// initial is the initial response, sent on the command line; reply,
		// when initial is empty, answers the continuation request.
		initial, reply string
	}{
		{name: "initial response without NULs", initial: "dXNlcg=="}, // "user"
		{name: "zero-length initial response", initial: "="},
		{name: "empty reply", reply: ""},
		{name: "reply with four fields", reply: "AAAA"}, // "\x00\x00\x00"
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			r := bufio.NewReader(c)
			readTagged(t, r, "* OK")

			if tc.initial != "" {
				c.Write([]byte("a AUTHENTICATE PLAIN " + tc.initial + "\r\n"))
			} else {
				c.Write([]byte("a AUTHENTICATE PLAIN\r\n"))
				readTagged(t, r, "+")
				c.Write([]byte(tc.reply + "\r\n"))
			}
			if line := strings.TrimRight(readTagged(t, r, "a "), "\r\n"); !strings.HasPrefix(line, "a NO ") || strings.Contains(line, "SERVERBUG") {
				t.Fatalf("malformed PLAIN message = %q, want a NO without SERVERBUG", line)
			}

			c.Write([]byte("b NOOP\r\n"))
			if line := readTagged(t, r, "b "); !strings.HasPrefix(line, "b OK") {
				t.Fatalf("NOOP after the refused AUTHENTICATE = %q, want b OK", line)
			}
		})
	}
}

// "=" is a zero-length response only as the initial response (RFC 9051 §9:
// initial-resp = (base64 / "=")). A reply to a continuation request is base64
// (authenticate = ... *(CRLF base64)), where a lone pad character is invalid
// and the server MUST answer a tagged BAD (RFC 9051 §6.2.2), as the IMAP proxy
// does (TestPreAuthMalformedLoginAndAuthenticateAnswerBAD). It must not reach
// PLAIN as a zero-length message and be answered NO. No database is needed.
func TestAuthenticateLonePadReplyIsBad(t *testing.T) {
	srv, addr := newReloadTestServer(t, IMAPServerOptions{})
	serveReloadTestServer(t, srv, addr)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	readTagged(t, r, "* OK")

	c.Write([]byte("a AUTHENTICATE PLAIN\r\n"))
	readTagged(t, r, "+")
	c.Write([]byte("=\r\n"))
	if line := strings.TrimRight(readTagged(t, r, "a "), "\r\n"); line != "a BAD Malformed SASL response" {
		t.Fatalf(`"=" as a continuation reply = %q, want "a BAD Malformed SASL response"`, line)
	}

	c.Write([]byte("b NOOP\r\n"))
	if line := readTagged(t, r, "b "); !strings.HasPrefix(line, "b OK") {
		t.Fatalf("NOOP after the refused AUTHENTICATE = %q, want b OK", line)
	}
}

// A reply to a continuation request is a base64 line (RFC 9051 §9:
// authenticate = ... *(CRLF base64), base64-char = ALPHA / DIGIT / "+" / "/").
// A CR inside it is outside the base64 alphabet, so the server MUST answer a
// tagged BAD (RFC 9051 §6.2.2), not strip the CR and hand the rest to PLAIN.
// Each reply decodes, CRs dropped, to a PLAIN message PLAIN itself refuses
// before any credential is looked at, so no database is needed.
func TestAuthenticateReplyWithBareCRIsBad(t *testing.T) {
	srv, addr := newReloadTestServer(t, IMAPServerOptions{})
	serveReloadTestServer(t, srv, addr)

	for _, tc := range []struct {
		name, reply string
	}{
		{name: "lone CR", reply: "\r"},                // "" without the CR
		{name: "CR inside", reply: "AA\rAA"},          // "\x00\x00\x00" without the CR
		{name: "CR before the CRLF", reply: "AAAA\r"}, // "\x00\x00\x00" without the CR
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			r := bufio.NewReader(c)
			readTagged(t, r, "* OK")

			c.Write([]byte("a AUTHENTICATE PLAIN\r\n"))
			readTagged(t, r, "+")
			c.Write([]byte(tc.reply + "\r\n"))
			if line := strings.TrimRight(readTagged(t, r, "a "), "\r\n"); line != "a BAD Malformed SASL response" {
				t.Fatalf("continuation reply %q = %q, want \"a BAD Malformed SASL response\"", tc.reply, line)
			}

			c.Write([]byte("b NOOP\r\n"))
			if line := readTagged(t, r, "b "); !strings.HasPrefix(line, "b OK") {
				t.Fatalf("NOOP after the refused AUTHENTICATE = %q, want b OK", line)
			}
		})
	}
}
