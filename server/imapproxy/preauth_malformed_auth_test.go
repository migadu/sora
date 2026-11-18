package imapproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/lookupcache"
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
		{"AUTHENTICATE PLAIN initial response with extra trailing CR", []step{
			{"a3 AUTHENTICATE PLAIN AGZvbwBiYXI=\r", "a3 BAD Invalid AUTHENTICATE arguments"},
		}},
		{"AUTHENTICATE PLAIN initial response with leading CR", []step{
			{"a3 AUTHENTICATE PLAIN \rAGZvbwBiYXI=", "a3 BAD Invalid AUTHENTICATE arguments"},
		}},
		{"AUTHENTICATE PLAIN zero-length initial response with extra trailing CR", []step{
			{"a3 AUTHENTICATE PLAIN =\r", "a3 BAD Invalid AUTHENTICATE arguments"},
		}},
		{"AUTHENTICATE PLAIN without initial response with extra trailing CR", []step{
			{"a3 AUTHENTICATE PLAIN\r", "a3 BAD Invalid AUTHENTICATE arguments"},
		}},
		{"AUTHENTICATE unsupported mechanism with extra trailing CR", []step{
			{"a3 AUTHENTICATE CRAM-MD5\r", "a3 BAD Invalid AUTHENTICATE arguments"},
		}},
		{"LOGIN with extra trailing CR", []step{
			{"a3 LOGIN user@example.com secret\r", "a3 BAD Invalid LOGIN arguments"},
		}},
		{"LOGIN with embedded CR between arguments", []step{
			{"a3 LOGIN user@example.com \rsecret", "a3 BAD Invalid LOGIN arguments"},
		}},

		// Still NO: the command is well formed and fails, like any failed login (#2068).
		{"LOGIN with empty quoted credentials", []step{
			{`a4 LOGIN "" ""`, "a4 NO Authentication failed"},
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

// TestPreAuthMalformedLoginAndAuthenticateFramingNeverAuthenticates verifies
// that valid credentials wrapped in malformed RFC 9051 §9 framing are rejected
// with BAD instead of authenticating and connecting to the backend:
//  1. Trailing whitespace or extra CR after a final LOGIN password literal.
//  2. Missing SP, extra spaces/tabs, trailing whitespace, or embedded/extra CR
//     on the continuation line after a LOGIN username literal (still draining
//     any trailing non-synchronizing literal).
//  3. Bare CR (\r) on the initial LOGIN or AUTHENTICATE command line.
func TestPreAuthMalformedLoginAndAuthenticateFramingNeverAuthenticates(t *testing.T) {
	// Sanity-check that well-formed LOGIN (including literals and quoted spaces)
	// and AUTHENTICATE PLAIN with the exact same cached credentials DO succeed.
	for _, tc := range []struct {
		name  string
		input string
	}{
		{"plain LOGIN", "a1 LOGIN user@example.com secret\r\n"},
		{"username literal and quoted space password", "a1 LOGIN {18+}\r\nspaced@example.com \"my secret\"\r\n"},
		{"username and password literals", "a1 LOGIN {16+}\r\nuser@example.com {6+}\r\nsecret\r\n"},
		{"AUTHENTICATE PLAIN initial response", "a1 AUTHENTICATE PLAIN AGZvbwBiYXI=\r\n"},
	} {
		t.Run("valid/"+tc.name, func(t *testing.T) {
			client, reader, backendConns := startCachedAuthFramingTestSession(t)
			if _, err := io.WriteString(client, tc.input+"a2 LOGOUT\r\n"); err != nil {
				t.Fatalf("write: %v", err)
			}
			reply, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read login reply: %v", err)
			}
			if got := strings.TrimRight(reply, "\r\n"); got != "a1 OK Logged in" {
				t.Fatalf("valid %s: got %q, want %q", tc.name, got, "a1 OK Logged in")
			}
			if backendConns.Load() != 1 {
				t.Fatalf("valid %s: backend connections = %d, want 1", tc.name, backendConns.Load())
			}
		})
	}

	loginBAD := "a1 BAD Invalid LOGIN arguments"
	authBAD := "a1 BAD Invalid AUTHENTICATE arguments"

	tests := []struct {
		name  string
		input string
		want  string
	}{
		// 1. After a final password literal (finishLoginLiteral).
		{
			name:  "extra CR after password literal",
			input: "a1 LOGIN user@example.com {6+}\r\nsecret\r\r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "trailing space after password literal",
			input: "a1 LOGIN user@example.com {6+}\r\nsecret \r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "trailing tab after password literal",
			input: "a1 LOGIN user@example.com {6+}\r\nsecret\t\r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "extra CR after chained username and password literals",
			input: "a1 LOGIN {16+}\r\nuser@example.com {6+}\r\nsecret\r\r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "trailing space after chained username and password literals",
			input: "a1 LOGIN {16+}\r\nuser@example.com {6+}\r\nsecret \r\na2 NOOP\r\n",
			want:  loginBAD,
		},

		// 2. Continuation line after a username literal.
		{
			name:  "missing SP before atom password after username literal",
			input: "a1 LOGIN {16+}\r\nuser@example.comsecret\r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "missing SP before quoted password after username literal",
			input: "a1 LOGIN {16+}\r\nuser@example.com\"secret\"\r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "missing SP before password literal after username literal drains literal",
			input: "a1 LOGIN {16+}\r\nuser@example.com{6+}\r\nsecret\r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "tab instead of SP after username literal",
			input: "a1 LOGIN {16+}\r\nuser@example.com\tsecret\r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "double SP before password after username literal",
			input: "a1 LOGIN {16+}\r\nuser@example.com  secret\r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "SP then tab before password after username literal",
			input: "a1 LOGIN {16+}\r\nuser@example.com \tsecret\r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "lone SP without password after username literal",
			input: "a1 LOGIN {16+}\r\nuser@example.com \r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "trailing space after atom password following username literal",
			input: "a1 LOGIN {16+}\r\nuser@example.com secret \r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "trailing space after quoted password following username literal",
			input: "a1 LOGIN {18+}\r\nspaced@example.com \"my secret\" \r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "embedded CR before SP after username literal",
			input: "a1 LOGIN {16+}\r\nuser@example.com\r secret\r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "embedded CR after SP following username literal",
			input: "a1 LOGIN {16+}\r\nuser@example.com \rsecret\r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "extra trailing CR after password following username literal",
			input: "a1 LOGIN {16+}\r\nuser@example.com secret\r\r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "embedded CR before password literal after username literal drains literal",
			input: "a1 LOGIN {16+}\r\nuser@example.com\r {10+}\r\nx2 FOO bar\r\na2 NOOP\r\n",
			want:  loginBAD,
		},

		// 3. Bare CR on the initial LOGIN or AUTHENTICATE command line.
		{
			name:  "LOGIN extra trailing CR",
			input: "a1 LOGIN user@example.com secret\r\r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "LOGIN embedded CR after quoted username",
			input: "a1 LOGIN \"user@example.com\"\r secret\r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "LOGIN embedded CR before password",
			input: "a1 LOGIN user@example.com \rsecret\r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "LOGIN embedded CR before username literal drains literal",
			input: "a1 LOGIN \r{16+}\r\nuser@example.com secret\r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "LOGIN embedded CR before password literal drains literal",
			input: "a1 LOGIN \"user@example.com\"\r {6+}\r\nsecret\r\na2 NOOP\r\n",
			want:  loginBAD,
		},
		{
			name:  "AUTHENTICATE PLAIN initial response extra trailing CR",
			input: "a1 AUTHENTICATE PLAIN AGZvbwBiYXI=\r\r\na2 NOOP\r\n",
			want:  authBAD,
		},
		{
			name:  "AUTHENTICATE PLAIN initial response leading CR",
			input: "a1 AUTHENTICATE PLAIN \rAGZvbwBiYXI=\r\na2 NOOP\r\n",
			want:  authBAD,
		},
		{
			name:  "AUTHENTICATE PLAIN without initial response extra trailing CR",
			input: "a1 AUTHENTICATE PLAIN\r\r\na2 NOOP\r\n",
			want:  authBAD,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, reader, backendConns := startCachedAuthFramingTestSession(t)
			if _, err := io.WriteString(client, tc.input); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := readReplies(t, reader, "a2 ")
			want := []string{tc.want, "a2 OK NOOP completed"}
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Fatalf("input %q:\ngot  %q\nwant %q", tc.input, got, want)
			}
			if backendConns.Load() != 0 {
				t.Fatalf("input %q: backend dialed %d times, want 0", tc.input, backendConns.Load())
			}
		})
	}
}

// startCachedAuthFramingTestSession starts a cleartext proxy TCP session with a
// fake IMAP backend and positive lookup-cache entries ("user@example.com" /
// "secret", "spaced@example.com" / "my secret", and "foo" / "bar") so
// well-formed credentials succeed end-to-end if pre-auth framing erroneously
// accepts the command.
func startCachedAuthFramingTestSession(t *testing.T) (net.Conn, *bufio.Reader, *atomic.Int32) {
	t.Helper()

	var backendConns atomic.Int32
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backendLn.Close() })
	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			backendConns.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.WriteString(c, "* OK backend ready\r\n")
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					tag, rest, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
					cmd, _, _ := strings.Cut(rest, " ")
					switch strings.ToUpper(cmd) {
					case "AUTHENTICATE", "LOGIN":
						_, _ = io.WriteString(c, tag+" OK Logged in\r\n")
					case "LOGOUT":
						_, _ = io.WriteString(c, "* BYE Logging out\r\n"+tag+" OK LOGOUT completed\r\n")
						return
					default:
						_, _ = io.WriteString(c, tag+" OK completed\r\n")
					}
				}
			}(conn)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	cache := newTestLookupCache(t)
	cache.Set("test", "user@example.com", &lookupcache.CacheEntry{
		AccountID:      1,
		PasswordDigest: lookupcache.NewPasswordDigest("secret"),
		Result:         lookupcache.AuthSuccess,
	})
	cache.Set("test", "spaced@example.com", &lookupcache.CacheEntry{
		AccountID:      2,
		PasswordDigest: lookupcache.NewPasswordDigest("my secret"),
		Result:         lookupcache.AuthSuccess,
	})
	cache.Set("test", "foo", &lookupcache.CacheEntry{
		AccountID:      3,
		PasswordDigest: lookupcache.NewPasswordDigest("bar"),
		Result:         lookupcache.AuthSuccess,
	})

	srv := &Server{
		name:                       "test",
		hostname:                   "test-host",
		ctx:                        ctx,
		cancel:                     cancel,
		activeSessions:             make(map[*Session]struct{}),
		connManager:                newTestConnManager(t, backendLn.Addr().String()),
		lookupCache:                cache,
		authLimiter:                &fakeAuthLimiter{},
		insecureAuth:               true,
		positiveRevalidationWindow: 30 * time.Second,
	}
	srv.settings.Store(&reloadableSettings{maxAuthErrors: 3, authIdleTimeout: 5 * time.Second})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		serverConn, err := ln.Accept()
		if err != nil {
			return
		}
		newSession(srv, serverConn).handleConnection()
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("session did not stop")
		}
	})

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(client)
	if greeting, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("greeting: %q, %v", greeting, err)
	}
	return client, reader, &backendConns
}

// EOF before LF cannot complete an authentication line, even after valid literal
// octets. A half-close preserves the response direction for this real TCP probe.
func TestPreAuthIncompleteAuthenticationLinesNeverAuthenticate(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		challenge   bool
	}{
		{"initial login", "a1 LOGIN user@example.com secret\r", false},
		{"after username literal", "a1 LOGIN {16+}\r\nuser@example.com secret\r", false},
		{"after password literal", "a1 LOGIN user@example.com {6+}\r\nsecret\r", false},
		{"authenticate response", "a1 AUTHENTICATE PLAIN AGZvbwBiYXI=\r", false},
		{"authenticate continuation", "AGZvbwBiYXI=\r", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, r, backend := startCachedAuthFramingTestSession(t)
			if tc.challenge {
				if _, err := io.WriteString(c, "a1 AUTHENTICATE PLAIN\r\n"); err != nil {
					t.Fatal(err)
				}
				if reply, err := r.ReadString('\n'); err != nil || reply != "+ \r\n" {
					t.Fatalf("continuation: %q, %v", reply, err)
				}
			}
			_, err := io.WriteString(c, tc.input)
			if err != nil {
				t.Fatal(err)
			}
			tcp, ok := c.(*net.TCPConn)
			if !ok {
				t.Fatal("expected real TCP")
			}
			if err := tcp.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			line, err := r.ReadString('\n')
			if strings.Contains(line, " OK ") || backend.Load() != 0 {
				t.Fatalf("incomplete command authenticated: reply=%q err=%v backend=%d", line, err, backend.Load())
			}
			if err == nil && !strings.Contains(line, " BAD ") {
				t.Fatalf("unexpected reply=%q", line)
			}
		})
	}
}
