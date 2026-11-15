package imapproxy

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestPreAuthUnknownAndWrongStateCommandsAnswerBAD verifies that, before
// authentication, the proxy answers an unknown command and a command that is
// not valid in the not-authenticated state with a tagged BAD, in the backend's
// wording, not with NO. RFC 9051 §7.1.3: a tagged BAD "reports a protocol-level
// error in the client's command"; §7.1.2: a tagged NO "indicates unsuccessful
// completion of the associated command". The proxy chooses BAD to match the
// backend's status; §3 also permits NO for a command in the wrong state.
func TestPreAuthUnknownAndWrongStateCommandsAnswerBAD(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"a1 SELECT INBOX", "a1 BAD [CLIENTBUG] This command is only valid in the authenticated state"},
		{"a1 examine INBOX", "a1 BAD [CLIENTBUG] This command is only valid in the authenticated state"},
		{"a1 LIST \"\" *", "a1 BAD [CLIENTBUG] This command is only valid in the authenticated state"},
		{"a1 ENABLE CONDSTORE", "a1 BAD [CLIENTBUG] This command is only valid in the authenticated state"},
		{"a1 CHECK", "a1 BAD [CLIENTBUG] This command is only valid in the selected state"},
		{"a1 CLOSE", "a1 BAD [CLIENTBUG] This command is only valid in the selected state"},
		{"a1 FETCH 1 FLAGS", "a1 BAD [CLIENTBUG] This command is only valid in the selected state"},
		{"a1 UID FETCH 1:* FLAGS", "a1 BAD [CLIENTBUG] This command is only valid in the selected state"},
		{"a1 uid expunge 1", "a1 BAD [CLIENTBUG] This command is only valid in the selected state"},
		{"a1 FOO", "a1 BAD Unknown command"},
		{"a1 UID FOO 1", "a1 BAD Unknown command"},
		{"a1 UID", "a1 BAD Unknown command"},
		// Look-alikes are not command names: ASCII case folding only (RFC 5234
		// §2.3), as the backend matches them (#1511). U+017F (long s) is not
		// an S, and U+0131 (dotless i) is not an I.
		{"a1 ſELECT INBOX", "a1 BAD Unknown command"},
		{"a1 UıD FETCH 1:* FLAGS", "a1 BAD Unknown command"},
		{"a1 UID ſEARCH ALL", "a1 BAD Unknown command"},
		{"a1 uid ſtore 1 +FLAGS (\\Seen)", "a1 BAD Unknown command"},
	}

	for _, tc := range tests {
		t.Run(tc.line, func(t *testing.T) {
			client, reader := startPreAuthTestSession(t, 3)
			if _, err := client.Write([]byte(tc.line + "\r\n")); err != nil {
				t.Fatalf("write: %v", err)
			}
			resp, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if got := strings.TrimRight(resp, "\r\n"); got != tc.want {
				t.Errorf("%q: got %q, want %q", tc.line, got, tc.want)
			}
		})
	}
}

// TestPreAuthBADStillCountsAgainstErrorBudget verifies that the BAD answers
// keep counting against max_auth_errors: the budget is the proxy's guard
// against a peer that is not speaking IMAP (cross-protocol attacks).
func TestPreAuthBADStillCountsAgainstErrorBudget(t *testing.T) {
	client, reader := startPreAuthTestSession(t, 2)

	if _, err := client.Write([]byte("a1 FOO\r\na2 SELECT INBOX\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	var lines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break // proxy closed the connection
		}
		lines = append(lines, strings.TrimRight(line, "\r\n"))
	}
	want := []string{
		"a1 BAD Unknown command",
		"a2 BAD [CLIENTBUG] This command is only valid in the authenticated state",
		"* BYE Too many invalid commands",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("got %q, want %q", lines, want)
	}
}

// startPreAuthTestSession starts a proxy session on an in-memory connection,
// consumes the greeting, and returns the client end.
func startPreAuthTestSession(t *testing.T, maxAuthErrors int) (net.Conn, *bufio.Reader) {
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
	}
	srv.settings.Store(&reloadableSettings{maxAuthErrors: maxAuthErrors, authIdleTimeout: 5 * time.Second})

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
