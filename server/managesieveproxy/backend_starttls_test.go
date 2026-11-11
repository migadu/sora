package managesieveproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
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
		io.WriteString(conn, fakeSieveCapabilities)
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
				io.WriteString(conn, "OK\r\n")
				continue
			}
			io.WriteString(conn, reply)
			if !strings.HasPrefix(reply, "OK") {
				continue
			}
			secure := tls.Server(conn, tlsConfig)
			if secure.Handshake() != nil {
				return
			}
			conn, r = secure, bufio.NewReader(secure)
			io.WriteString(conn, fakeSieveCapabilities+b.afterTLSCaps)
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
