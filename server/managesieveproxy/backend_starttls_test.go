package managesieveproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

const fakeSieveCapabilities = "\"IMPLEMENTATION\" \"fake\"\r\n\"SASL\" \"PLAIN\"\r\nOK \"ready\"\r\n"

// fakeSieveBackend scripts one backend connection for the STARTTLS tests.
type fakeSieveBackend struct {
	implicitTLS   bool   // the listener speaks TLS from the first byte
	startTLSReply string // reply to STARTTLS; "" refuses it with NO
	afterTLSCaps  string // sent in one write with the capabilities that follow the handshake
	greeting      string // sent on connect in place of fakeSieveCapabilities
	tlsGreeting   string // sent after the handshake in place of fakeSieveCapabilities
	authReply     string // reply to every other command (the AUTHENTICATE); "" answers OK
}

// start serves one connection and returns its address and a function that waits for
// the connection to end and returns the commands the proxy sent, in order.
func (b fakeSieveBackend) start(t *testing.T) (addr string, commands func() []string) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("../../testdata/sora.crt", "../../testdata/sora.key")
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	reply := b.startTLSReply
	if reply == "" {
		reply = "NO \"STARTTLS not available\"\r\n"
	}
	authReply := b.authReply
	if authReply == "" {
		authReply = "OK\r\n"
	}
	greeting, tlsGreeting := b.greeting, b.tlsGreeting
	if greeting == "" {
		greeting = fakeSieveCapabilities
	}
	if tlsGreeting == "" {
		tlsGreeting = fakeSieveCapabilities
	}
	var mu sync.Mutex
	var got []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(10 * time.Second))
		var conn net.Conn = raw
		if b.implicitTLS {
			conn = tls.Server(raw, tlsConfig)
		}
		r := bufio.NewReader(conn)
		io.WriteString(conn, greeting)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			mu.Lock()
			got = append(got, line)
			mu.Unlock()
			if !strings.EqualFold(line, "STARTTLS") {
				io.WriteString(conn, authReply)
				continue
			}
			io.WriteString(conn, reply)
			// Any reply starting with the letters OK goes on to the handshake, so a proxy
			// that takes it for an OK gets as far as authenticating.
			if len(reply) < 2 || !strings.EqualFold(reply[:2], "OK") {
				continue
			}
			secure := tls.Server(conn, tlsConfig)
			if secure.Handshake() != nil {
				return
			}
			conn, r = secure, bufio.NewReader(secure)
			io.WriteString(conn, tlsGreeting+b.afterTLSCaps)
		}
	}()
	return ln.Addr().String(), func() []string {
		t.Helper()
		select {
		case <-done:
		case <-time.After(12 * time.Second):
			t.Fatal("the fake backend connection did not end")
		}
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

// connectSieveBackend runs connectToBackendAndAuth against addr on a proxy whose own
// backend settings are settings, for a user routed by route (nil: no remote lookup route).
func connectSieveBackend(t *testing.T, addr string, settings proxy.BackendSettings, route *proxy.UserRoutingInfo) (*Session, error) {
	t.Helper()
	cm, err := proxy.NewConnectionManagerFromOptions(proxy.ManagerOptions{
		RemoteAddrs:        []string{addr},
		RemotePort:         4190,
		Settings:           settings,
		ConnectTimeout:     2 * time.Second,
		ServerName:         "test",
		DisableHealthCheck: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	clientA, clientB := net.Pipe()
	t.Cleanup(func() { clientA.Close(); clientB.Close() })
	sess := &Session{
		server:                &Server{name: "test", hostname: "test-host", connManager: cm},
		clientConn:            clientA,
		listenerConn:          clientA,
		ctx:                   context.Background(),
		username:              "user@example.com",
		routingInfo:           route,
		isRemoteLookupAccount: route != nil,
	}
	err = sess.connectToBackendAndAuth()
	return sess, err
}

func sentSTARTTLS(commands []string) bool {
	for _, c := range commands {
		if strings.EqualFold(c, "STARTTLS") {
			return true
		}
	}
	return false
}

// The upgrade still happens where the proxy's own settings ask for it.
func TestConnectToBackendUpgradesWithSTARTTLS(t *testing.T) {
	addr, commands := fakeSieveBackend{startTLSReply: "OK \"Begin TLS negotiation now.\"\r\n"}.start(t)
	sess, err := connectSieveBackend(t, addr, proxy.BackendSettings{TLS: true, TLSUseStartTLS: true}, nil)
	if err != nil {
		t.Fatalf("connectToBackendAndAuth: %v", err)
	}
	if _, ok := sess.backendConn.(*tls.Conn); !ok {
		t.Errorf("backendConn after STARTTLS is %T, want *tls.Conn", sess.backendConn)
	}
	sess.backendConn.Close()
	got := commands()
	if len(got) != 2 || got[0] != "STARTTLS" || !strings.HasPrefix(got[1], "AUTHENTICATE \"PLAIN\" ") {
		t.Errorf("backend received %q, want STARTTLS, AUTHENTICATE", got)
	}
}

// A remote lookup route to a host carries its own remote_tls settings and ConnectWithProxy
// dials by them. The session must follow the same settings: it may not send STARTTLS
// because the proxy server's own settings ask for it, nor when the route's remote_tls is
// off (the dial was plaintext and stays so, as on the IMAP and POP3 proxies).
func TestConnectToBackendFollowsLookupRouteTLSSettings(t *testing.T) {
	startTLSServer := proxy.BackendSettings{TLS: true, TLSUseStartTLS: true}
	for _, tc := range []struct {
		name        string
		server      proxy.BackendSettings
		route       proxy.UserRoutingInfo
		implicitTLS bool
	}{
		{"plaintext route on a STARTTLS server", startTLSServer, proxy.UserRoutingInfo{}, false},
		{"implicit TLS route on a STARTTLS server", startTLSServer, proxy.UserRoutingInfo{RemoteTLS: true}, true},
		{"route with remote_tls_use_starttls but no remote_tls", proxy.BackendSettings{}, proxy.UserRoutingInfo{RemoteTLSUseStartTLS: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, commands := fakeSieveBackend{implicitTLS: tc.implicitTLS}.start(t)
			route := tc.route
			route.ServerAddress = addr
			route.IsRemoteLookupAccount = true
			sess, err := connectSieveBackend(t, addr, tc.server, &route)
			if err != nil {
				t.Errorf("connectToBackendAndAuth: %v", err)
			}
			if sess.backendConn != nil {
				sess.backendConn.Close()
			}
			if got := commands(); sentSTARTTLS(got) {
				t.Errorf("the proxy sent STARTTLS on a leg ConnectWithProxy dialed without it: %q", got)
			}
		})
	}
}

// Bytes that follow the STARTTLS OK in the same read came in plaintext, where anyone
// on the path could have put them: the connection fails rather than dropping them.
func TestConnectToBackendRefusesDataAfterSTARTTLSResponse(t *testing.T) {
	addr, _ := fakeSieveBackend{startTLSReply: "OK \"Begin TLS negotiation now.\"\r\nOK \"injected\"\r\n"}.start(t)
	_, err := connectSieveBackend(t, addr, proxy.BackendSettings{TLS: true, TLSUseStartTLS: true}, nil)
	if err == nil || !strings.Contains(err.Error(), "sent data after its STARTTLS response") {
		t.Fatalf("connectToBackendAndAuth = %v, want the refusal of data after OK", err)
	}
	if !server.IsBackendError(err) {
		t.Errorf("connectToBackendAndAuth = %v, want a backend error", err)
	}
}

// The reply to STARTTLS is OK when its first atom is OK in any case: RFC 5804 section 4,
// response-starttls = (response-ok response-capability) / response-nobye, response-ok =
// "OK" [SP "(" resp-code ")"] [SP string] CRLF, and "Implementations MUST accept these
// strings in a case-insensitive fashion". OKAY, or OK run into its string, is not an OK:
// the proxy must not go on to the handshake after it.
func TestConnectToBackendSTARTTLSReplyStatus(t *testing.T) {
	for _, tc := range []struct {
		reply string
		ok    bool
	}{
		{"OK \"Begin TLS negotiation now.\"\r\n", true},
		{"ok \"Begin TLS negotiation now.\"\r\n", true},
		{"Ok\r\n", true},
		{"oK (XTEST) \"Begin TLS negotiation now.\"\r\n", true},
		{"OKAY \"Begin TLS negotiation now.\"\r\n", false},
		{"OK\"Begin TLS negotiation now.\"\r\n", false},
	} {
		t.Run(strings.TrimSpace(tc.reply), func(t *testing.T) {
			addr, commands := fakeSieveBackend{startTLSReply: tc.reply}.start(t)
			sess, err := connectSieveBackend(t, addr, proxy.BackendSettings{TLS: true, TLSUseStartTLS: true}, nil)
			_, upgraded := sess.backendConn.(*tls.Conn)
			if sess.backendConn != nil {
				sess.backendConn.Close()
			}
			got := commands()
			if tc.ok {
				if err != nil {
					t.Fatalf("connectToBackendAndAuth: %v", err)
				}
				if !upgraded {
					t.Errorf("backendConn after STARTTLS is %T, want *tls.Conn", sess.backendConn)
				}
				if len(got) != 2 || got[0] != "STARTTLS" || !strings.HasPrefix(got[1], "AUTHENTICATE \"PLAIN\" ") {
					t.Errorf("backend received %q, want STARTTLS, AUTHENTICATE", got)
				}
				return
			}
			if !errors.Is(err, server.ErrBackendConnectionFailed) || !strings.HasSuffix(err.Error(), "backend STARTTLS failed: "+strings.TrimSpace(tc.reply)) {
				t.Errorf("connectToBackendAndAuth = %v, want a backend connection failure carrying %q", err, strings.TrimSpace(tc.reply))
			}
			if !slices.Equal(got, []string{"STARTTLS"}) {
				t.Errorf("backend received %q, want STARTTLS alone", got)
			}
		})
	}
}

// The reply to AUTHENTICATE is matched the same way: RFC 5804 section 4,
// response-authenticate = *(string CRLF) ((response-ok [response-capability]) /
// response-nobye), case-insensitive. A lower-case ok logs the user in; OKAY, or OK run
// into its string, is the backend failing the proxy's login.
func TestConnectToBackendAuthenticateReplyStatus(t *testing.T) {
	for _, tc := range []struct {
		reply string
		ok    bool
	}{
		{"OK \"Logged in.\"\r\n", true},
		{"ok \"Logged in.\"\r\n", true},
		{"Ok\r\n", true},
		{"oK (XTEST) \"Logged in.\"\r\n", true},
		{"OKAY \"Logged in.\"\r\n", false},
		{"OK\"Logged in.\"\r\n", false},
	} {
		t.Run(strings.TrimSpace(tc.reply), func(t *testing.T) {
			addr, commands := fakeSieveBackend{authReply: tc.reply}.start(t)
			sess, err := connectSieveBackend(t, addr, proxy.BackendSettings{}, nil)
			if sess.backendConn != nil {
				sess.backendConn.Close()
			}
			if got := commands(); len(got) != 1 || !strings.HasPrefix(got[0], "AUTHENTICATE \"PLAIN\" ") {
				t.Errorf("backend received %q, want AUTHENTICATE", got)
			}
			if tc.ok {
				if err != nil {
					t.Fatalf("connectToBackendAndAuth: %v", err)
				}
				return
			}
			if !errors.Is(err, server.ErrBackendAuthFailed) || !strings.HasSuffix(err.Error(), ": "+strings.TrimSpace(tc.reply)) {
				t.Errorf("connectToBackendAndAuth = %v, want a backend login failure carrying %q", err, strings.TrimSpace(tc.reply))
			}
		})
	}
}

// A capability list ends with OK, NO or BYE (RFC 5804 section 4: response-capability =
// *(single-capability) response-oknobye), matched case-insensitively. A backend refusing
// the connection (a sora backend over its max_connections_per_ip answers
// NO (TRYLATER) "Too many connections") must end the greeting at once with the backend's
// line, not be read on as a capability line until EOF or the read deadline. The fake
// backend keeps the connection open after its refusal.
func TestConnectToBackendReportsRefusingGreeting(t *testing.T) {
	const tooMany = `NO (TRYLATER) "Too many connections"`
	startTLS := proxy.BackendSettings{TLS: true, TLSUseStartTLS: true}
	for _, tc := range []struct {
		name     string
		backend  fakeSieveBackend
		settings proxy.BackendSettings
		refusal  string
		commands []string // what the backend receives before the proxy hangs up
	}{
		{"NO greeting", fakeSieveBackend{greeting: tooMany + "\r\n"}, proxy.BackendSettings{}, tooMany, nil},
		{"BYE after capabilities", fakeSieveBackend{greeting: "\"IMPLEMENTATION\" \"fake\"\r\nBYE \"Server shutting down\"\r\n"},
			proxy.BackendSettings{}, `BYE "Server shutting down"`, nil},
		{"lower-case bye", fakeSieveBackend{greeting: "bye\r\n"}, proxy.BackendSettings{}, "bye", nil},
		{"NO after STARTTLS", fakeSieveBackend{startTLSReply: "OK\r\n", tlsGreeting: tooMany + "\r\n"}, startTLS, tooMany, []string{"STARTTLS"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, commands := tc.backend.start(t)
			_, err := connectSieveBackend(t, addr, tc.settings, nil)
			if !errors.Is(err, server.ErrBackendConnectionFailed) || !strings.HasSuffix(err.Error(), "backend refused the connection: "+tc.refusal) {
				t.Fatalf("connectToBackendAndAuth = %v, want a backend connection failure carrying %q", err, tc.refusal)
			}
			if got := commands(); !slices.Equal(got, tc.commands) {
				t.Errorf("backend received %q, want %q", got, tc.commands)
			}
		})
	}
}

// The OK that ends the greeting is matched case-insensitively too (RFC 5804 section 4):
// a lower-case "ok" is not a capability line to read past.
func TestConnectToBackendEndsGreetingAtLowerCaseOK(t *testing.T) {
	addr, commands := fakeSieveBackend{greeting: "\"IMPLEMENTATION\" \"fake\"\r\n\"NOTIFY\" \"mailto\"\r\nok\r\n"}.start(t)
	sess, err := connectSieveBackend(t, addr, proxy.BackendSettings{}, nil)
	if err != nil {
		t.Fatalf("connectToBackendAndAuth: %v", err)
	}
	sess.backendConn.Close()
	if got := commands(); len(got) != 1 || !strings.HasPrefix(got[0], "AUTHENTICATE \"PLAIN\" ") {
		t.Errorf("backend received %q, want AUTHENTICATE", got)
	}
}

func TestConnectToBackendCapabilityLiteralsAreNotStatusReplies(t *testing.T) {
	for _, greeting := range []string{
		"{2}\r\nNO\r\nOK\r\n",
		"\"IMPLEMENTATION\" {3}\r\nBYE\r\nOK\r\n",
		"{2}\r\nNO {3}\r\nBYE\r\nOK\r\n",
		"\"IMPLEMENTATION\" {6}\r\nNO\r\nOK\r\nOK\r\n",
		"OK {2}\r\nNO\r\n",
		"OK (XTEST ({2}\r\nNO))\r\n",
		"{0}\r\n {3}\r\nBYE\r\nOK\r\n",
	} {
		t.Run(greeting, func(t *testing.T) {
			addr, commands := fakeSieveBackend{greeting: greeting}.start(t)
			sess, err := connectSieveBackend(t, addr, proxy.BackendSettings{}, nil)
			if err != nil {
				t.Fatalf("connectToBackendAndAuth: %v", err)
			}
			sess.backendConn.Close()
			if got := commands(); len(got) != 1 || !strings.HasPrefix(got[0], "AUTHENTICATE \"PLAIN\" ") {
				t.Errorf("backend received %q, want AUTHENTICATE", got)
			}
		})
	}
}

func TestBackendCapabilityLiteralBounds(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        error
	}{
		{"oversized declaration without payload", "{8193}\r\n", server.ErrLineTooLong},
		{"truncated literal", "{3}\r\nNO", io.EOF},
		{"record bound includes literal payload", "{8190}\r\n", server.ErrLineTooLong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readBackendCapabilityRecord(bufio.NewReader(strings.NewReader(tc.input)))
			if !errors.Is(err, tc.want) {
				t.Fatalf("reading capability record: %v, want %v", err, tc.want)
			}
		})
	}
}

// What the backend sends behind the post-STARTTLS capabilities sits in the reader that
// read them. Authentication must go on reading from that reader: a fresh one on the
// connection silently skips those bytes and takes a later line for the reply.
func TestAuthenticationReadsOnFromThePostSTARTTLSReader(t *testing.T) {
	addr, _ := fakeSieveBackend{
		startTLSReply: "OK \"Begin TLS negotiation now.\"\r\n",
		afterTLSCaps:  "NO \"sent behind the capabilities\"\r\n",
	}.start(t)
	_, err := connectSieveBackend(t, addr, proxy.BackendSettings{TLS: true, TLSUseStartTLS: true}, nil)
	if !errors.Is(err, server.ErrBackendAuthFailed) || !strings.Contains(err.Error(), "sent behind the capabilities") {
		t.Fatalf("connectToBackendAndAuth = %v, want the line buffered behind the capabilities read as the AUTHENTICATE reply", err)
	}
}
