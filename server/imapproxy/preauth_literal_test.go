package imapproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// literalPayload is the content of the literals in these tests. It is a valid
// command line, so a proxy that reads it back as one answers it as "x2".
const literalPayload = "x2 FOO bar"

// TestPreAuthNonSyncLiteralOfAnsweredCommandIsRead verifies that a pre-auth
// command the proxy answers without reading its arguments still has its
// trailing non-synchronizing literal, and the line after it, read as part of
// the command. RFC 7888 §3: the server "MUST treat the specified number of
// following octets and the following line ... as part of the same command".
// The client sends them without waiting; left unread, they were parsed as the
// next command, answered on their own and charged to the error budget.
func TestPreAuthNonSyncLiteralOfAnsweredCommandIsRead(t *testing.T) {
	lit := fmt.Sprintf("{%d+}", len(literalPayload))
	tests := []struct {
		name         string
		insecureAuth bool
		first        string // first line of the command, ending in lit
		rest         string // rest of the command after the literal
		want         []string
	}{
		{name: "wrong-state command", first: "a1 APPEND INBOX " + lit,
			want: []string{"a1 BAD [CLIENTBUG] This command is only valid in the authenticated state"}},
		{name: "unknown command", first: "a1 FOO " + lit,
			want: []string{"a1 BAD Unknown command"}},
		{name: "unparseable line", first: `a1 FOO "bar ` + lit,
			want: []string{"a1 BAD unclosed quote in command arguments"}},
		{name: "tag only", first: lit,
			want: []string{lit + " BAD Command is missing"}},
		{name: "STARTTLS with an argument", first: "a1 STARTTLS " + lit,
			want: []string{"a1 BAD STARTTLS not available"}},
		{name: "NOOP with an argument", first: "a1 NOOP " + lit,
			want: []string{"a1 OK NOOP completed"}},
		{name: "CAPABILITY with an argument", first: "a1 CAPABILITY " + lit,
			want: []string{"* CAPABILITY " + PreAuthCapabilities, "a1 OK CAPABILITY completed"}},
		{name: "LOGIN refused without TLS", first: "a1 LOGIN " + lit, rest: " pass",
			want: []string{"a1 NO [PRIVACYREQUIRED] Authentication requires TLS connection"}},
		{name: "AUTHENTICATE refused without TLS", first: "a1 AUTHENTICATE PLAIN " + lit,
			want: []string{"a1 NO [PRIVACYREQUIRED] Authentication requires TLS connection"}},
		// The response is not base64; only its single tagged reply matters here.
		{name: "AUTHENTICATE with a literal argument", insecureAuth: true, first: "a1 AUTHENTICATE PLAIN " + lit,
			want: []string{"a1 "}},
		// ID reads its literals itself; a literal straight after the
		// parenthesis is the last token of the line too.
		{name: "ID literal after a parenthesis", first: "a1 ID (" + lit, rest: " NIL)",
			want: []string{"* ID (", "a1 OK ID completed"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, reader := startPreAuthLiteralSession(t, tc.insecureAuth)
			input := tc.first + "\r\n" + literalPayload + tc.rest + "\r\na3 NOOP\r\n"
			if _, err := io.WriteString(client, input); err != nil {
				t.Fatalf("write: %v", err)
			}
			want := append(append([]string{}, tc.want...), "a3 OK NOOP completed")
			assertReplies(t, input, readReplies(t, reader, "a3 "), want)
		})
	}
}

// TestPreAuthChainedNonSyncLiteralsAreRead verifies that the line after a
// literal is read for another literal at its end, as many times as the client
// chains them (RFC 7888 §3 applies to "every received line").
func TestPreAuthChainedNonSyncLiteralsAreRead(t *testing.T) {
	client, reader := startPreAuthLiteralSession(t, false)
	input := "a1 FOO {3+}\r\nabc {10+}\r\n" + literalPayload + " {10+}\r\n" + literalPayload + "\r\na3 NOOP\r\n"
	if _, err := io.WriteString(client, input); err != nil {
		t.Fatalf("write: %v", err)
	}
	assertReplies(t, input, readReplies(t, reader, "a3 "), []string{"a1 BAD Unknown command", "a3 OK NOOP completed"})
}

// TestPreAuthSyncLiteralOfRejectedCommandGetsNoContinuation verifies that a
// synchronizing literal ending a command the proxy rejects is not invited: no
// continuation request, so the client sends nothing more of the command (RFC
// 9051 §2.2.1), and the next line is the next command.
func TestPreAuthSyncLiteralOfRejectedCommandGetsNoContinuation(t *testing.T) {
	for _, first := range []string{"a1 FOO {10}", "a1 LOGIN {9000}", "a1 LOGIN user {9000}"} {
		t.Run(first, func(t *testing.T) {
			client, reader := startPreAuthLiteralSession(t, true)
			input := first + "\r\na3 NOOP\r\n"
			if _, err := io.WriteString(client, input); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := readReplies(t, reader, "a3 ")
			if len(got) != 2 || !strings.HasPrefix(got[0], "a1 BAD ") || got[1] != "a3 OK NOOP completed" {
				t.Errorf("input %q: got %q, want a1 BAD then a3 OK and no continuation request", input, got)
			}
		})
	}
}

// TestPreAuthOversizedNonSyncLiteralEndsSession verifies that a
// non-synchronizing literal over the pre-auth bound ends the session with BYE
// [TOOBIG] instead of being read as commands. The proxy advertises LITERAL-:
// such a literal must not exceed 4096 octets, and a server that receives a
// larger one either reads it and rejects the command or sends BYE and closes
// the connection (RFC 7888 §4, §5: a BYE "SHOULD include the TOOBIG response
// code"). Before authentication the proxy does not read it.
func TestPreAuthOversizedNonSyncLiteralEndsSession(t *testing.T) {
	// 1000 command lines, 9000 octets: what a proxy that does not read the
	// literal goes on to execute.
	payload := strings.Repeat("x2 NOOP\r\n", 1000)
	lit := fmt.Sprintf("{%d+}", len(payload))
	tests := []struct {
		name         string
		insecureAuth bool
		first        string
	}{
		{name: "unknown command", first: "a1 FOO " + lit},
		{name: "LOGIN refused without TLS", first: "a1 LOGIN " + lit},
		{name: "LOGIN user name", insecureAuth: true, first: "a1 LOGIN " + lit},
		{name: "LOGIN password", insecureAuth: true, first: "a1 LOGIN user " + lit},
		{name: "LOGIN password and white space", insecureAuth: true, first: "a1 LOGIN user " + lit + " "},
		{name: "LOGIN password after a user name literal", insecureAuth: true, first: "a1 LOGIN {4+}\r\nuser " + lit},
		{name: "ID", first: `a1 ID ("name" ` + lit},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, reader := startPreAuthLiteralSession(t, tc.insecureAuth)
			// The proxy closes the connection without reading all of it.
			go func() { _, _ = io.WriteString(client, tc.first+"\r\n"+payload+"\r\na3 NOOP\r\n") }()

			var got []string
			for len(got) < 5 {
				line, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				got = append(got, strings.TrimRight(line, "\r\n"))
			}
			want := []string{"* BYE [TOOBIG] Non-synchronizing literal too big"}
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("%q: got %q, want %q and the connection closed", tc.first, got, want)
			}
		})
	}
}

// readReplies reads response lines until the first one starting with last.
func readReplies(t *testing.T, reader *bufio.Reader, last string) []string {
	t.Helper()
	var got []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return got
		}
		line = strings.TrimRight(line, "\r\n")
		got = append(got, line)
		if strings.HasPrefix(line, last) || len(got) > 10 {
			return got
		}
	}
}

// assertReplies checks that each reply starts with the wanted line.
func assertReplies(t *testing.T, input string, got, want []string) {
	t.Helper()
	ok := len(got) == len(want)
	for i := 0; ok && i < len(want); i++ {
		ok = strings.HasPrefix(got[i], want[i])
	}
	if !ok {
		t.Errorf("input %q:\ngot  %q\nwant %q", input, got, want)
	}
}

// startPreAuthLiteralSession starts a proxy session on an in-memory
// connection, consumes the greeting, and returns the client end.
func startPreAuthLiteralSession(t *testing.T, insecureAuth bool) (net.Conn, *bufio.Reader) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv := &Server{
		name:           "test",
		hostname:       "test-host",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
		connManager:    newTestConnManager(t, "127.0.0.1:1"),
		authLimiter:    &fakeAuthLimiter{},
		insecureAuth:   insecureAuth,
	}
	srv.settings.Store(&reloadableSettings{maxAuthErrors: 3, authIdleTimeout: 5 * time.Second})

	serverEnd, client := net.Pipe()
	sess := newSession(srv, serverEnd)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.handleConnection()
	}()
	t.Cleanup(func() {
		client.Close()
		<-done
	})

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(client)
	if greeting, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("greeting: %q, %v", greeting, err)
	}
	return client, reader
}
