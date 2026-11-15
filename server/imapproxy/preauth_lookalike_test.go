package imapproxy

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// Before authentication the proxy matches command names and the AUTHENTICATE
// mechanism itself. Both are case-insensitive over US-ASCII only (RFC 5234
// §2.3; RFC 4422 §3.1 names SASL mechanisms with ASCII upper-case letters,
// digits, "-" and "_"). strings.ToUpper maps U+0131 (LATIN SMALL LETTER
// DOTLESS I) to "I", so "CAPABıLITY" was answered as CAPABILITY and "PLAıN"
// was taken for PLAIN (#1511).
func TestPreAuthKeywordLookalikesAreNotKeywords(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := &Server{
		name:           "test",
		hostname:       "test-host",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
		connManager:    newTestConnManager(t, "127.0.0.1:1"),
		authLimiter:    &fakeAuthLimiter{},
		insecureAuth:   true,
	}
	srv.settings.Store(&reloadableSettings{maxAuthErrors: 10, authIdleTimeout: 5 * time.Second})

	client, remote := net.Pipe()
	defer remote.Close()

	sess := newSession(srv, client)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.handleConnection()
	}()

	reader := bufio.NewReader(remote)
	_ = remote.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("failed to read greeting: %v", err)
	}

	send := func(cmd string) {
		t.Helper()
		if _, err := remote.Write([]byte(cmd + "\r\n")); err != nil {
			t.Fatalf("write %q: %v", cmd, err)
		}
	}
	readLine := func() string {
		t.Helper()
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return strings.TrimRight(line, "\r\n")
	}
	// readUntilTagged returns the lines up to and including the tagged one.
	readUntilTagged := func(tag string) []string {
		t.Helper()
		var lines []string
		for {
			line := readLine()
			lines = append(lines, line)
			if strings.HasPrefix(line, tag+" ") {
				return lines
			}
		}
	}

	// ASCII in any case is the command.
	send("c capability")
	if lines := readUntilTagged("c"); len(lines) != 2 || !strings.HasPrefix(lines[0], "* CAPABILITY ") || !strings.HasPrefix(lines[1], "c OK ") {
		t.Fatalf("capability: got %q, want the CAPABILITY response and c OK", lines)
	}

	// A look-alike gets what an unknown command gets.
	send("u XYZZY")
	unknown := readUntilTagged("u")
	send("p CAPAB\u0131LITY")
	if lines := readUntilTagged("p"); len(lines) != 1 || len(unknown) != 1 || strings.TrimPrefix(lines[0], "p ") != strings.TrimPrefix(unknown[0], "u ") {
		t.Errorf("CAPAB\u0131LITY: got %q, want what an unknown command gets: %q", lines, unknown)
	}

	// A look-alike mechanism gets what an unsupported one gets. Read one line
	// only: a mechanism taken for PLAIN gets a continuation request.
	send("m AUTHENTICATE CRAM-MD5")
	unsupported := strings.TrimPrefix(readLine(), "m ")
	send("a AUTHENTICATE PLA\u0131N")
	if resp := readLine(); !strings.HasPrefix(unsupported, "NO ") || strings.TrimPrefix(resp, "a ") != unsupported {
		t.Errorf("AUTHENTICATE PLA\u0131N: got %q, want what an unsupported mechanism gets: %q", resp, unsupported)
	}

	remote.Close()
	<-done
}
