package imapproxy

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// TestPreAuthMalformedLoginAndAuthenticateAnswerBAD verifies that the proxy
// answers a LOGIN or AUTHENTICATE whose arguments are invalid with a tagged
// BAD, and keeps NO for a rejected credential or an unsupported mechanism.
//
// RFC 9051 §6.2.3 (LOGIN): "NO - login failure: user name or password
// rejected", "BAD - command unknown or arguments invalid"; a missing argument
// is the second case. RFC 9051 §6.2.2 (AUTHENTICATE): "if it receives an
// invalid base64 string (e.g., characters outside the base64 alphabet or
// non-terminal "="), it MUST reject the AUTHENTICATE command by sending a
// tagged BAD response", and "To send a zero-length initial response, the
// client MUST send a single pad character ("=")".
func TestPreAuthMalformedLoginAndAuthenticateAnswerBAD(t *testing.T) {
	type step struct {
		send string // client line, without CRLF
		want string // proxy reply line, without CRLF
	}
	tests := []struct {
		name  string
		steps []step
	}{
		// LOGIN with a missing argument: arguments invalid.
		{"LOGIN without arguments", []step{
			{"a1 LOGIN", "a1 BAD LOGIN requires username and password"},
		}},
		{"LOGIN without password", []step{
			{"a1 LOGIN user@example.com", "a1 BAD LOGIN requires username and password"},
		}},
		{"LOGIN literal user name without password", []step{
			{"a1 LOGIN {16}", "+ "},
			{"user@example.com", "a1 BAD LOGIN requires username and password"},
		}},
		// AUTHENTICATE with invalid base64: MUST be BAD.
		{"AUTHENTICATE PLAIN initial response outside the alphabet", []step{
			{"a2 AUTHENTICATE PLAIN !!!!", "a2 BAD Invalid base64 encoding"},
		}},
		{"AUTHENTICATE PLAIN initial response with non-terminal pad", []step{
			{"a2 AUTHENTICATE PLAIN =AAA", "a2 BAD Invalid base64 encoding"},
		}},
		{"AUTHENTICATE PLAIN initial response with a pad inside", []step{
			// RFC 9051 §6.2.2: "=AAA" and "AAA=BBB" are not allowed.
			{"a2 AUTHENTICATE PLAIN AAA=BBB", "a2 BAD Invalid base64 encoding"},
		}},
		{"AUTHENTICATE PLAIN continuation response outside the alphabet", []step{
			{"a2 AUTHENTICATE PLAIN", "+ "},
			{"!!!!", "a2 BAD Invalid base64 encoding"},
		}},
		{"AUTHENTICATE PLAIN continuation response of a single pad", []step{
			// "=" is the zero-length INITIAL response only (RFC 9051 §9:
			// initial-resp = (base64 / "=")); a continuation reply is base64,
			// which a lone pad is not. A zero-length reply is an empty line.
			{"a2 AUTHENTICATE PLAIN", "+ "},
			{"=", "a2 BAD Invalid base64 encoding"},
		}},
		// AUTHENTICATE without a mechanism: arguments invalid.
		{"AUTHENTICATE without mechanism", []step{
			{"a3 AUTHENTICATE", "a3 BAD AUTHENTICATE requires a mechanism name"},
		}},
		// AUTHENTICATE with extra arguments, quoted/literal mechanism, quoted
		// SASL responses, initial "*", or embedded/extra CR: MUST be BAD.
		// AGZvbwBiYXI= is base64("\x00foo\x00bar").
		{"AUTHENTICATE PLAIN with an extra argument", []step{
			{"a3 AUTHENTICATE PLAIN AGZvbwBiYXI= extra", "a3 BAD Invalid AUTHENTICATE arguments"},
		}},
		{"AUTHENTICATE with a quoted mechanism", []step{
			{`a3 AUTHENTICATE "PLAIN"`, "a3 BAD Invalid AUTHENTICATE arguments"},
		}},
		{"AUTHENTICATE with a synchronizing literal mechanism", []step{
			{"a3 AUTHENTICATE {5}", "a3 BAD Invalid AUTHENTICATE arguments"},
		}},
		{"AUTHENTICATE PLAIN quoted empty initial response", []step{
			{`a3 AUTHENTICATE PLAIN ""`, "a3 BAD Invalid base64 encoding"},
		}},
		{"AUTHENTICATE PLAIN quoted pad initial response", []step{
			{`a3 AUTHENTICATE PLAIN "="`, "a3 BAD Invalid base64 encoding"},
		}},
		{"AUTHENTICATE PLAIN quoted base64 initial response", []step{
			{`a3 AUTHENTICATE PLAIN "AGZvbwBiYXI="`, "a3 BAD Invalid base64 encoding"},
		}},
		{"AUTHENTICATE PLAIN quoted empty continuation response", []step{
			{"a3 AUTHENTICATE PLAIN", "+ "},
			{`""`, "a3 BAD Invalid base64 encoding"},
		}},
		{"AUTHENTICATE PLAIN quoted base64 continuation response", []step{
			{"a3 AUTHENTICATE PLAIN", "+ "},
			{`"AGZvbwBiYXI="`, "a3 BAD Invalid base64 encoding"},
		}},
		{"AUTHENTICATE PLAIN quoted asterisk continuation response", []step{
			{"a3 AUTHENTICATE PLAIN", "+ "},
			{`"*"`, "a3 BAD Invalid base64 encoding"},
		}},
		{"AUTHENTICATE PLAIN asterisk initial response", []step{
			{"a3 AUTHENTICATE PLAIN *", "a3 BAD Invalid base64 encoding"},
		}},
		{"AUTHENTICATE PLAIN initial response with embedded CR", []step{
			{"a3 AUTHENTICATE PLAIN AGZvbw\rBiYXI=", "a3 BAD Invalid base64 encoding"},
		}},
		{"AUTHENTICATE PLAIN continuation response with embedded CR", []step{
			{"a3 AUTHENTICATE PLAIN", "+ "},
			{"AGZvbw\rBiYXI=", "a3 BAD Invalid base64 encoding"},
		}},
		{"AUTHENTICATE PLAIN continuation response with extra trailing CR", []step{
			{"a3 AUTHENTICATE PLAIN", "+ "},
			{"AGZvbwBiYXI=\r", "a3 BAD Invalid base64 encoding"},
		}},

		// Still NO: the command is well formed and fails.
		{"LOGIN with empty quoted credentials", []step{
			{`a4 LOGIN "" ""`, "a4 NO LOGIN requires username and password"},
		}},
		{"AUTHENTICATE with an unsupported mechanism", []step{
			{"a5 AUTHENTICATE CRAM-MD5", "a5 NO AUTHENTICATE PLAIN is the only supported mechanism"},
		}},
		{"AUTHENTICATE PLAIN with a zero-length initial response", []step{
			{"a6 AUTHENTICATE PLAIN =", "a6 NO Invalid SASL PLAIN response"},
		}},
		{"AUTHENTICATE PLAIN with a zero-length continuation response", []step{
			{"a6 AUTHENTICATE PLAIN", "+ "},
			{"", "a6 NO Invalid SASL PLAIN response"},
		}},
		{"AUTHENTICATE PLAIN with a message of the wrong shape", []step{
			// base64("\x00foo"): two fields, PLAIN needs three.
			{"a7 AUTHENTICATE PLAIN AGZvbw==", "a7 NO Invalid SASL PLAIN response"},
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, reader := startCleartextAuthTestSession(t, 3)
			for _, st := range tc.steps {
				if _, err := client.Write([]byte(st.send + "\r\n")); err != nil {
					t.Fatalf("write %q: %v", st.send, err)
				}
				resp, err := reader.ReadString('\n')
				if err != nil {
					t.Fatalf("read reply to %q: %v", st.send, err)
				}
				if got := strings.TrimRight(resp, "\r\n"); got != st.want {
					t.Fatalf("after %q: got %q, want %q", st.send, got, st.want)
				}
			}
		})
	}
}

// TestPreAuthMalformedAuthStillCountsAgainstErrorBudget verifies that the BAD
// answers to malformed LOGIN/AUTHENTICATE keep counting against
// max_auth_errors.
func TestPreAuthMalformedAuthStillCountsAgainstErrorBudget(t *testing.T) {
	client, reader := startCleartextAuthTestSession(t, 3)

	if _, err := client.Write([]byte("a1 LOGIN\r\na2 AUTHENTICATE\r\na3 AUTHENTICATE PLAIN !!!!\r\n")); err != nil {
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
		"a1 BAD LOGIN requires username and password",
		"a2 BAD AUTHENTICATE requires a mechanism name",
		"a3 BAD Invalid base64 encoding",
		"* BYE Too many invalid commands",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("got %q, want %q", lines, want)
	}
}

// TestPreAuthAuthenticateCancellationVsInitialAsterisk verifies that "*"
// cancels an AUTHENTICATE exchange only when sent in reply to a server
// continuation request ("+ "), without counting against max_auth_errors, while
// "*" sent as initial-resp on the AUTHENTICATE command line is rejected as
// invalid base64 and counts against max_auth_errors.
func TestPreAuthAuthenticateCancellationVsInitialAsterisk(t *testing.T) {
	t.Run("continuation asterisk cancels without burning error budget", func(t *testing.T) {
		client, reader := startCleartextAuthTestSession(t, 2)
		for _, tag := range []string{"a1", "a2", "a3"} {
			if _, err := client.Write([]byte(tag + " AUTHENTICATE PLAIN\r\n")); err != nil {
				t.Fatalf("write %s AUTHENTICATE: %v", tag, err)
			}
			cont, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read continuation for %s: %v", tag, err)
			}
			if got := strings.TrimRight(cont, "\r\n"); got != "+ " {
				t.Fatalf("%s continuation: got %q, want %q", tag, got, "+ ")
			}
			if _, err := client.Write([]byte("*\r\n")); err != nil {
				t.Fatalf("write cancel for %s: %v", tag, err)
			}
			resp, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read cancel reply for %s: %v", tag, err)
			}
			want := tag + " BAD Authentication cancelled"
			if got := strings.TrimRight(resp, "\r\n"); got != want {
				t.Fatalf("%s cancel reply: got %q, want %q", tag, got, want)
			}
		}
		if _, err := client.Write([]byte("a4 NOOP\r\n")); err != nil {
			t.Fatalf("write NOOP: %v", err)
		}
		resp, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read NOOP reply: %v", err)
		}
		if got := strings.TrimRight(resp, "\r\n"); got != "a4 OK NOOP completed" {
			t.Fatalf("after 3 cancellations: got %q, want %q", got, "a4 OK NOOP completed")
		}
	})

	t.Run("initial asterisk is invalid base64 and counts against error budget", func(t *testing.T) {
		client, reader := startCleartextAuthTestSession(t, 2)
		if _, err := client.Write([]byte("a1 AUTHENTICATE PLAIN *\r\na2 AUTHENTICATE PLAIN *\r\na3 NOOP\r\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
		var lines []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			trimmed := strings.TrimRight(line, "\r\n")
			lines = append(lines, trimmed)
			if strings.HasPrefix(trimmed, "a3 ") {
				break
			}
		}
		want := []string{
			"a1 BAD Invalid base64 encoding",
			"a2 BAD Invalid base64 encoding",
			"* BYE Too many invalid commands",
		}
		if strings.Join(lines, "\n") != strings.Join(want, "\n") {
			t.Fatalf("got %q, want %q", lines, want)
		}
	})
}

// TestPreAuthExtraAuthenticateLiteralDrained verifies that an extra trailing
// non-synchronizing literal on AUTHENTICATE has its octets drained without
// executing them as a command and rejects AUTHENTICATE with BAD instead of
// authenticating with the preceding initial-resp.
func TestPreAuthExtraAuthenticateLiteralDrained(t *testing.T) {
	client, reader := startCleartextAuthTestSession(t, 3)
	input := "a1 AUTHENTICATE PLAIN AGZvbwBiYXI= {10+}\r\nx2 FOO bar\r\na3 NOOP\r\n"
	if _, err := client.Write([]byte(input)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := readReplies(t, reader, "a3 ")
	want := []string{
		"a1 BAD Invalid AUTHENTICATE arguments",
		"a3 OK NOOP completed",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// startCleartextAuthTestSession is startPreAuthTestSession with insecure_auth
// enabled, so LOGIN and AUTHENTICATE reach their argument handling on the
// in-memory (non-TLS) connection.
func startCleartextAuthTestSession(t *testing.T, maxAuthErrors int) (net.Conn, *bufio.Reader) {
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
		authLimiter:    &fakeAuthLimiter{canErr: errors.New("test auth refusal")},
		insecureAuth:   true,
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
