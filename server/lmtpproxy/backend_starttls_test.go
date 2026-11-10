package lmtpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/server/proxy"
)

// fakeLMTPBackend scripts one backend connection for the STARTTLS tests.
type fakeLMTPBackend struct {
	implicitTLS   bool   // the listener speaks TLS from the first byte
	startTLSReply string // reply to STARTTLS; "" refuses it with 502
	noHandshake   bool   // after a 220 reply stay silent instead of handshaking
}

// start serves one connection and returns its address and a function that waits for
// the connection to end and returns the commands the proxy sent, in order.
func (b fakeLMTPBackend) start(t *testing.T) (addr string, commands func() []string) {
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
		reply = "502 5.5.1 STARTTLS not supported\r\n"
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
		io.WriteString(conn, "220 fake LMTP backend ready\r\n")
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
				io.WriteString(conn, "250 OK\r\n")
				continue
			}
			io.WriteString(conn, reply)
			if !strings.HasPrefix(reply, "220") {
				continue
			}
			if b.noHandshake {
				io.Copy(io.Discard, conn) // swallow the ClientHello, answer nothing
				return
			}
			secure := tls.Server(conn, tlsConfig)
			if secure.Handshake() != nil {
				return
			}
			conn, r = secure, bufio.NewReader(secure)
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

// connectLMTPBackend runs connectToBackend against addr on a proxy whose own backend
// settings are settings, for a recipient routed by route (nil: no remote lookup route).
func connectLMTPBackend(t *testing.T, addr string, settings proxy.BackendSettings, route *proxy.UserRoutingInfo, connectTimeout time.Duration) (*Session, error) {
	t.Helper()
	cm, err := proxy.NewConnectionManagerFromOptions(proxy.ManagerOptions{
		RemoteAddrs:        []string{addr},
		RemotePort:         24,
		Settings:           settings,
		ConnectTimeout:     connectTimeout,
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
		originalAddress:       "user@example.com",
		ctx:                   context.Background(),
		routingInfo:           route,
		isRemoteLookupAccount: route != nil,
	}
	err = sess.connectToBackend()
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
	addr, commands := fakeLMTPBackend{startTLSReply: "220 2.0.0 ready to start TLS\r\n"}.start(t)
	sess, err := connectLMTPBackend(t, addr, proxy.BackendSettings{TLS: true, TLSUseStartTLS: true}, nil, 2*time.Second)
	if err != nil {
		t.Fatalf("connectToBackend: %v", err)
	}
	if _, ok := sess.backendConn.(*tls.Conn); !ok {
		t.Errorf("backendConn after STARTTLS is %T, want *tls.Conn", sess.backendConn)
	}
	sess.backendConn.Close()
	got := commands()
	if len(got) != 3 || !strings.HasPrefix(got[0], "LHLO ") || got[1] != "STARTTLS" || !strings.HasPrefix(got[2], "LHLO ") {
		t.Errorf("backend received %q, want LHLO, STARTTLS, LHLO", got)
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
			addr, commands := fakeLMTPBackend{implicitTLS: tc.implicitTLS}.start(t)
			route := tc.route
			route.ServerAddress = addr
			route.IsRemoteLookupAccount = true
			sess, err := connectLMTPBackend(t, addr, tc.server, &route, 2*time.Second)
			if err != nil {
				t.Errorf("connectToBackend: %v", err)
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

// Bytes that follow the STARTTLS 220 in the same read came in plaintext, where anyone
// on the path could have put them: the connection fails rather than dropping them.
func TestConnectToBackendRefusesDataAfterSTARTTLSResponse(t *testing.T) {
	addr, _ := fakeLMTPBackend{startTLSReply: "220 2.0.0 ready to start TLS\r\n250 injected\r\n"}.start(t)
	_, err := connectLMTPBackend(t, addr, proxy.BackendSettings{TLS: true, TLSUseStartTLS: true}, nil, 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "sent data after its STARTTLS response") {
		t.Fatalf("connectToBackend = %v, want the refusal of data after 220", err)
	}
}

// A backend that answers 220 and then never handshakes must not hold the session: the
// TLS handshake runs under the connect timeout like every other backend read.
func TestConnectToBackendSTARTTLSHandshakeTimesOut(t *testing.T) {
	addr, _ := fakeLMTPBackend{startTLSReply: "220 2.0.0 ready to start TLS\r\n", noHandshake: true}.start(t)
	done := make(chan error, 1)
	go func() {
		sess, err := connectLMTPBackend(t, addr, proxy.BackendSettings{TLS: true, TLSUseStartTLS: true}, nil, 500*time.Millisecond)
		if sess.backendConn != nil {
			sess.backendConn.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("connectToBackend succeeded against a backend that never handshakes")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connectToBackend hung in the TLS handshake after STARTTLS: no deadline on the backend connection")
	}
}
