package pop3proxy

import (
	"bufio"
	"context"
	"encoding/binary"
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

// proxyV2Signature opens every PROXY protocol v2 header.
const proxyV2Signature = "\r\n\r\n\x00\r\nQUIT\n"

// skipProxyV2Header consumes the PROXY v2 header r starts with, if there is one, and
// reports whether there was. Without a header it waits for the first 12 bytes of the
// proxy's first command, which every command of the backend leg has.
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

// xclientBackend serves one plaintext connection: a greeting, then xclientReply
// xclientDelay after XCLIENT, and authReply at once to AUTH. commands waits for the
// connection to end and returns the command names the backend read, in order, with
// "PROXY" first when the connection started with a PROXY v2 header.
func xclientBackend(t *testing.T, xclientDelay time.Duration, xclientReply, authReply string) (addr string, commands func() []string) {
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
		io.WriteString(conn, "+OK fake backend ready\r\n")
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
			command, _, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
			mu.Lock()
			got = append(got, command)
			mu.Unlock()
			switch command {
			case "XCLIENT":
				time.Sleep(xclientDelay)
				io.WriteString(conn, xclientReply+"\r\n")
			case "AUTH":
				io.WriteString(conn, authReply+"\r\n")
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

// An XCLIENT whose reply was not read by the deadline leaves the backend leg at an
// unknown point in its stream: POP3 replies carry no tag, so the late +OK to XCLIENT
// would be read as the reply to AUTH, and the backend's real AUTH reply would reach the
// client as the reply to its next command. The proxy must not log in on that leg. It
// fails the connect, which the client sees as a temporary backend failure. An XCLIENT
// the backend answered (accepted or refused) was read, so the login goes on.
func TestConnectToBackendXCLIENTReplyNotRead(t *testing.T) {
	const connectTimeout = 500 * time.Millisecond
	for _, tc := range []struct {
		name         string
		xclientDelay time.Duration
		xclientReply string
		authReply    string
		wantErr      bool
		wantSent     []string
	}{
		{"XCLIENT answered after the deadline", connectTimeout + 200*time.Millisecond, "+OK XCLIENT accepted",
			"-ERR [AUTH] Authentication failed", true, []string{"XCLIENT"}},
		{"XCLIENT accepted", 0, "+OK XCLIENT accepted", "+OK logged in", false, []string{"XCLIENT", "AUTH"}},
		{"XCLIENT refused", 0, "-ERR XCLIENT not permitted", "+OK logged in", false, []string{"XCLIENT", "AUTH"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, commands := xclientBackend(t, tc.xclientDelay, tc.xclientReply, tc.authReply)
			clientA, clientB := net.Pipe()
			t.Cleanup(func() { clientA.Close(); clientB.Close() })
			sess := &POP3ProxySession{
				server: &POP3ProxyServer{
					name:             "test",
					hostname:         "test-host",
					connManager:      newPOP3TestConnManager(t, addr, connectTimeout),
					remoteUseXCLIENT: true,
				},
				clientConn:   clientA,
				listenerConn: clientA,
				ctx:          context.Background(),
				username:     "user@example.com",
			}

			err := sess.connectToBackend()
			if sess.backendConn != nil {
				sess.backendConn.Close() // ends the fake backend's connection on success too
			}
			sent := commands()

			if tc.wantErr {
				if !errors.Is(err, server.ErrBackendConnectionFailed) {
					t.Errorf("connectToBackend = %v, want a backend connect failure", err)
				}
			} else if err != nil {
				t.Errorf("connectToBackend: %v", err)
			}
			if strings.Join(sent, " ") != strings.Join(tc.wantSent, " ") {
				t.Errorf("the backend read %q, want %q", sent, tc.wantSent)
			}
		})
	}
}

// tcpPair returns the two ends of a loopback TCP connection: a PROXY header names a client
// only when the client connection has a TCP address.
func tcpPair(t *testing.T) (dialed, accepted net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if dialed, err = net.Dial("tcp", ln.Addr().String()); err != nil {
		t.Fatal(err)
	}
	if accepted, err = ln.Accept(); err != nil {
		dialed.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { dialed.Close(); accepted.Close() })
	return dialed, accepted
}

// Next to a PROXY header a POP3 backend judges XCLIENT by the client the header names, not
// by this proxy (server.ForwardingSourceIP), and refuses it: that client is not in its
// trusted_networks. The header already carries the client's address and port, so XCLIENT
// there is a wasted round trip and a WARN line on every login. The proxy sends it only on a
// leg without a header, by the settings the dial uses: the server's, a lookup pin's, or the
// named pool's (whose remote_use_xclient also covers LMTP, which still needs XCLIENT).
func TestConnectToBackendSkipsXCLIENTNextToProxyHeader(t *testing.T) {
	for _, tc := range []struct {
		name               string
		route              string // "server" (remote_addrs), "pin" (remote lookup) or "pool"
		proxyProtocol      bool   // the proxy server's remote_use_proxy_protocol
		routeProxyProtocol bool   // the pin's or the pool's remote_use_proxy_protocol
		wantSent           []string
	}{
		{"server settings, PROXY header", "server", true, false, []string{"PROXY", "AUTH"}},
		{"server settings, no PROXY header", "server", false, false, []string{"XCLIENT", "AUTH"}},
		{"lookup pin with PROXY header", "pin", false, true, []string{"PROXY", "AUTH"}},
		{"lookup pin without PROXY header", "pin", true, false, []string{"XCLIENT", "AUTH"}},
		{"pool with PROXY header", "pool", false, true, []string{"PROXY", "AUTH"}},
		{"pool without PROXY header", "pool", true, false, []string{"XCLIENT", "AUTH"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, commands := xclientBackend(t, 0, "-ERR Connection not from trusted proxy", "+OK logged in")
			cm, err := proxy.NewConnectionManager([]string{addr}, 110, false, false, tc.proxyProtocol, 500*time.Millisecond)
			if tc.route == "pool" {
				cm, err = proxy.NewConnectionManagerWithPools([]proxy.PoolSpec{{
					Name: "sora0", Backends: []string{addr}, Default: true,
					Settings: proxy.BackendSettings{UseProxyProtocol: tc.routeProxyProtocol, UseXCLIENT: true},
				}}, 110, 500*time.Millisecond, nil, "test", true)
			}
			if err != nil {
				t.Fatal(err)
			}
			// The routing info an uncached database login leaves (authenticate), or a pin.
			route := &proxy.UserRoutingInfo{RemoteUseXCLIENT: true}
			if tc.route == "pin" {
				route = &proxy.UserRoutingInfo{
					ServerAddress:          addr,
					IsRemoteLookupAccount:  true,
					RemoteUseProxyProtocol: tc.routeProxyProtocol,
					RemoteUseXCLIENT:       true,
				}
			}
			_, client := tcpPair(t)
			sess := &POP3ProxySession{
				server: &POP3ProxyServer{
					name:             "test",
					hostname:         "test-host",
					connManager:      cm,
					remoteUseXCLIENT: true,
				},
				clientConn:            client,
				listenerConn:          client,
				ctx:                   context.Background(),
				username:              "user@example.com",
				isRemoteLookupAccount: tc.route == "pin",
				routingInfo:           route,
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
