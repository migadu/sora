package imapproxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/server/proxy"
)

// proxyV2Signature opens every PROXY protocol v2 header.
const proxyV2Signature = "\r\n\r\n\x00\r\nQUIT\n"

// skipProxyV2Header consumes the PROXY v2 header r starts with, if there is one, and
// reports whether there was. Without a header it waits for the first 12 bytes of the
// proxy's first command (or the end of the connection).
func skipProxyV2Header(r *bufio.Reader) bool {
	signature, err := r.Peek(len(proxyV2Signature))
	if err != nil || string(signature) != proxyV2Signature {
		return false
	}
	fixed := make([]byte, 16) // signature, version and command, family, address length
	if _, err := io.ReadFull(r, fixed); err != nil {
		return false
	}
	_, err = r.Discard(int(binary.BigEndian.Uint16(fixed[14:])))
	return err == nil
}

// idForwardingBackend serves one plaintext connection: a greeting, then the ID response
// (an untagged ID and the tagged idStatus) idDelay after the ID command, and an OK at once
// to AUTHENTICATE. commands waits for the connection to end and returns the command names
// the backend read, in order, with "PROXY" first when the connection started with a PROXY
// v2 header.
func idForwardingBackend(t *testing.T, idDelay time.Duration, idStatus string) (addr string, commands func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var got []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(conn, "* OK ready\r\n")
		r := bufio.NewReader(conn)
		if skipProxyV2Header(r) {
			mu.Lock()
			got = append(got, "PROXY")
			mu.Unlock()
		}
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			tag, rest, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
			command, _, _ := strings.Cut(rest, " ")
			mu.Lock()
			got = append(got, command)
			mu.Unlock()
			switch command {
			case "ID":
				time.Sleep(idDelay)
				io.WriteString(conn, "* ID (\"name\" \"fake\")\r\n"+tag+" "+idStatus+"\r\n")
			case "AUTHENTICATE":
				io.WriteString(conn, tag+" OK Logged in\r\n")
			}
		}
	}()
	return ln.Addr().String(), func() []string {
		t.Helper()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("the fake backend connection did not end")
		}
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

// A forwarded ID whose tagged reply was not read by the deadline leaves the backend leg
// at an unknown point in its stream: the reply is still on its way, and AUTHENTICATE
// would read it as its own. The proxy must not log in on that leg. It fails the login the
// way it fails a backend connect, as a temporary backend failure. An ID the backend
// answered (accepted or refused) was read up to its tagged reply, so the login goes on.
func TestPostAuthenticationSetupIDReplyNotRead(t *testing.T) {
	const connectTimeout = 500 * time.Millisecond // newTestConnManager
	for _, tc := range []struct {
		name      string
		idDelay   time.Duration
		idStatus  string
		wantOK    bool
		wantReply string
		wantSent  []string
	}{
		{"ID answered after the deadline", connectTimeout + 200*time.Millisecond, "OK ID completed", false,
			"A1 NO [UNAVAILABLE] Backend server temporarily unavailable", []string{"ID"}},
		{"ID refused after the deadline", connectTimeout + 200*time.Millisecond, "NO ID refused", false,
			"A1 NO [UNAVAILABLE] Backend server temporarily unavailable", []string{"ID"}},
		{"ID accepted", 0, "OK ID completed", true, "A1 OK Logged in", []string{"ID", "AUTHENTICATE"}},
		{"ID refused", 0, "NO ID refused", true, "A1 OK Logged in", []string{"ID", "AUTHENTICATE"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, commands := idForwardingBackend(t, tc.idDelay, tc.idStatus)
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			srv := &Server{
				name:               "test",
				hostname:           "test-host",
				ctx:                ctx,
				cancel:             cancel,
				activeSessions:     make(map[*Session]struct{}),
				connManager:        newTestConnManager(t, addr),
				authLimiter:        &fakeAuthLimiter{},
				remoteUseIDCommand: true,
			}
			client, remote := net.Pipe()
			t.Cleanup(func() { client.Close(); remote.Close() })
			replies := make(chan string, 8)
			go func() {
				r := bufio.NewReader(remote)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					replies <- strings.TrimRight(line, "\r\n")
				}
			}()
			sess := newSession(srv, client)
			sess.username = "user@example.com"

			ok := sess.postAuthenticationSetup("A1", time.Now())
			if sess.backendConn != nil {
				sess.backendConn.Close() // ends the fake backend's connection on success too
			}
			var reply string
			select {
			case reply = <-replies:
			case <-time.After(5 * time.Second):
				t.Fatal("no reply to the client's login")
			}
			sent := commands()

			if ok != tc.wantOK {
				t.Errorf("postAuthenticationSetup = %v, want %v", ok, tc.wantOK)
			}
			if reply != tc.wantReply {
				t.Errorf("the client got %q, want %q", reply, tc.wantReply)
			}
			if strings.Join(sent, " ") != strings.Join(tc.wantSent, " ") {
				t.Errorf("the backend read %q, want %q", sent, tc.wantSent)
			}
		})
	}
}

// Next to a PROXY header an IMAP backend judges ID forwarding by the client the header
// names, not by this proxy (server.ForwardingSourceIP), and ignores the fields: that client
// is not in its trusted_networks. The header already carries the client's address and
// port, its JA4 fingerprint and the session ID, so the ID there is a wasted round trip on
// every login. The proxy sends it only on a leg without a header, by the settings the dial
// uses: the server's, a lookup pin's, or the named pool's.
func TestConnectToBackendSkipsIDNextToProxyHeader(t *testing.T) {
	for _, tc := range []struct {
		name               string
		route              string // "server" (remote_addrs), "pin" (remote lookup) or "pool"
		proxyProtocol      bool   // the proxy server's remote_use_proxy_protocol
		routeProxyProtocol bool   // the pin's or the pool's remote_use_proxy_protocol
		wantSent           []string
	}{
		{"server settings, PROXY header", "server", true, false, []string{"PROXY"}},
		{"server settings, no PROXY header", "server", false, false, []string{"ID"}},
		{"lookup pin with PROXY header", "pin", false, true, []string{"PROXY"}},
		{"lookup pin without PROXY header", "pin", true, false, []string{"ID"}},
		{"pool with PROXY header", "pool", false, true, []string{"PROXY"}},
		{"pool without PROXY header", "pool", true, false, []string{"ID"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, commands := idForwardingBackend(t, 0, "OK ID completed")
			cm, err := proxy.NewConnectionManager([]string{addr}, 143, false, false, tc.proxyProtocol, 500*time.Millisecond)
			if tc.route == "pool" {
				cm, err = proxy.NewConnectionManagerWithPools([]proxy.PoolSpec{{
					Name: "sora0", Backends: []string{addr}, Default: true,
					Settings: proxy.BackendSettings{UseProxyProtocol: tc.routeProxyProtocol, UseIDCommand: true},
				}}, 143, 500*time.Millisecond, nil, "test", true)
			}
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			srv := &Server{
				name:               "test",
				hostname:           "test-host",
				ctx:                ctx,
				cancel:             cancel,
				activeSessions:     make(map[*Session]struct{}),
				connManager:        cm,
				authLimiter:        &fakeAuthLimiter{},
				remoteUseIDCommand: true,
			}
			dialed, client := tcpPair(t)
			t.Cleanup(func() { dialed.Close(); client.Close() })
			sess := newSession(srv, client)
			sess.username = "user@example.com"
			// The routing info an uncached database login leaves (authenticate), or a pin.
			sess.routingInfo = &proxy.UserRoutingInfo{RemoteUseIDCommand: true}
			if tc.route == "pin" {
				sess.isRemoteLookupAccount = true
				sess.routingInfo = &proxy.UserRoutingInfo{
					ServerAddress:          addr,
					IsRemoteLookupAccount:  true,
					RemoteUseProxyProtocol: tc.routeProxyProtocol,
					RemoteUseIDCommand:     true,
				}
			}

			err = sess.connectToBackend()
			if sess.backendConn != nil {
				sess.backendConn.Close() // ends the fake backend's connection
			}
			if err != nil {
				t.Errorf("connectToBackend: %v", err)
			}
			if sent := commands(); strings.Join(sent, " ") != strings.Join(tc.wantSent, " ") {
				t.Errorf("the backend read %q, want %q", sent, tc.wantSent)
			}
		})
	}
}
