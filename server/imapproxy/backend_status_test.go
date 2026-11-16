package imapproxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// fakeStatusBackend serves one plaintext connection: greeting, then replies[command](tag)
// to each command the proxy sends, and nothing to a command it has no reply for.
func fakeStatusBackend(t *testing.T, greeting string, replies map[string]func(tag string) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(conn, greeting)
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			tag, rest, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
			command, _, _ := strings.Cut(rest, " ")
			if reply, ok := replies[command]; ok {
				io.WriteString(conn, reply(tag))
			}
		}
	}()
	return ln.Addr().String()
}

// The backend greeting is usable when it is an untagged OK in any case: RFC 9051
// section 9, greeting = "*" SP (resp-cond-auth / resp-cond-bye) CRLF, resp-cond-auth =
// ("OK" / "PREAUTH") SP resp-text, and "Implementations MUST accept these strings in a
// case-insensitive fashion". OKAY, or OK run into its text, is not an OK greeting.
func TestConnectToBackendGreetingStatus(t *testing.T) {
	for _, tc := range []struct {
		greeting string
		ok       bool
	}{
		{"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ready", true},
		{"* ok ready", true},
		{"* oK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ready", true},
		{"* OKAY ready", false},
		{"* OK[CAPABILITY IMAP4rev1 AUTH=PLAIN] ready", false},
		{"* PREAUTH ready", false},
		{"* BYE too many connections", false},
	} {
		t.Run(tc.greeting, func(t *testing.T) {
			addr := fakeStatusBackend(t, tc.greeting+"\r\n", nil)
			_, err := connectToTestBackend(t, addr, proxy.BackendSettings{})
			if tc.ok {
				if err != nil {
					t.Fatalf("connectToBackend: %v", err)
				}
				return
			}
			if err == nil || !strings.HasSuffix(err.Error(), "unexpected backend greeting: "+tc.greeting) {
				t.Fatalf("connectToBackend = %v, want the greeting refused", err)
			}
		})
	}
}

// The tagged reply to the forwarded ID ends the exchange, OK in any case as success and
// any other status as a refusal: RFC 9051 section 9, response-tagged = tag SP
// resp-cond-state CRLF, resp-cond-state = ("OK" / "NO" / "BAD") SP resp-text,
// case-insensitive. A lower-case status must not leave the proxy reading on until the
// read deadline, and OKAY, or OK run into its text, is not an OK.
func TestSendForwardingParametersIDReplyStatus(t *testing.T) {
	for _, tc := range []struct {
		reply string
		ok    bool
	}{
		{"OK ID completed", true},
		{"ok ID completed", true},
		{"oK [XTEST] ID completed", true},
		{"OKAY ID completed", false},
		{"OK[XTEST] ID completed", false},
		{"NO ID refused", false},
		{"no ID refused", false},
		{"bad unknown command", false},
	} {
		t.Run(tc.reply, func(t *testing.T) {
			addr := fakeStatusBackend(t, "* OK ready\r\n", map[string]func(string) string{
				"ID": func(tag string) string { return "* ID (\"name\" \"fake\")\r\n" + tag + " " + tc.reply + "\r\n" },
			})
			sess, err := connectToTestBackend(t, addr, proxy.BackendSettings{})
			if err != nil {
				t.Fatalf("connectToBackend: %v", err)
			}
			err = sess.sendForwardingParametersToBackend()
			if tc.ok {
				if err != nil {
					t.Fatalf("sendForwardingParametersToBackend: %v", err)
				}
				return
			}
			if err == nil || !strings.HasPrefix(err.Error(), "backend rejected ID command: ") || !strings.HasSuffix(err.Error(), " "+tc.reply) {
				t.Fatalf("sendForwardingParametersToBackend = %v, want the ID refused with %q", err, tc.reply)
			}
		})
	}
}

// The ID response is read with a bound, like every other backend reply: RFC 2971 section
// 3.3 caps a well-formed one (at most 30 field-value pairs, fields of at most 30 octets
// and values of at most 1024), so a longer line is a misbehaving backend. The proxy
// skips such a line without holding it and reads on to the tagged ID reply: the login
// goes on to AUTHENTICATE after the ID, which must not take the ID's reply for its own.
func TestSendForwardingParametersBoundsIDResponseLine(t *testing.T) {
	const lineSize = 16 << 20
	// Built before the measurement below, and written in pieces, so that the backend
	// side allocates nothing while the proxy reads.
	oversized := []byte("* ID (\"name\" \"" + strings.Repeat("x", lineSize) + "\")\r\n")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(conn, "* OK ready\r\n")
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			tag, rest, _ := strings.Cut(line, " ")
			switch command, _, _ := strings.Cut(rest, " "); command {
			case "ID":
				for b := oversized; len(b) > 0; b = b[min(len(b), 64<<10):] {
					conn.Write(b[:min(len(b), 64<<10)])
				}
				io.WriteString(conn, tag+" OK ID completed\r\n")
			case "AUTHENTICATE":
				io.WriteString(conn, tag+" OK Logged in\r\n")
			}
		}
	}()
	sess, err := connectToTestBackend(t, ln.Addr().String(), proxy.BackendSettings{})
	if err != nil {
		t.Fatalf("connectToBackend: %v", err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err = sess.sendForwardingParametersToBackend()
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("sendForwardingParametersToBackend: %v", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= lineSize {
		t.Errorf("reading the ID response allocated %d bytes for a %d-byte line, want it bounded", allocated, lineSize)
	}
	if _, err := sess.authenticateToBackend(); err != nil {
		t.Fatalf("authenticateToBackend after the oversized ID line: %v", err)
	}
}

// The tagged reply to AUTHENTICATE logs the user in when its status is OK in any case,
// as for ID. OKAY, or OK run into its text, is the backend failing the proxy's login.
func TestAuthenticateToBackendReplyStatus(t *testing.T) {
	for _, tc := range []struct {
		reply string
		ok    bool
	}{
		{"OK [CAPABILITY IMAP4rev1] Logged in", true},
		{"ok Logged in", true},
		{"oK [CAPABILITY IMAP4rev1] Logged in", true},
		{"OKAY Logged in", false},
		{"OK[CAPABILITY IMAP4rev1] Logged in", false},
		{"NO [AUTHENTICATIONFAILED] Authentication failed", false},
	} {
		t.Run(tc.reply, func(t *testing.T) {
			addr := fakeStatusBackend(t, "* OK ready\r\n", map[string]func(string) string{
				"AUTHENTICATE": func(tag string) string { return tag + " " + tc.reply + "\r\n" },
			})
			sess, err := connectToTestBackend(t, addr, proxy.BackendSettings{})
			if err != nil {
				t.Fatalf("connectToBackend: %v", err)
			}
			response, err := sess.authenticateToBackend()
			if tc.ok {
				if err != nil {
					t.Fatalf("authenticateToBackend: %v", err)
				}
				if !strings.HasSuffix(response, " "+tc.reply) {
					t.Errorf("authenticateToBackend returned %q, want the backend's %q", response, tc.reply)
				}
				return
			}
			if !errors.Is(err, server.ErrBackendAuthFailed) || !strings.HasSuffix(err.Error(), " "+tc.reply) {
				t.Fatalf("authenticateToBackend = %v, want a backend login failure carrying %q", err, tc.reply)
			}
		})
	}
}
