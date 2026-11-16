package managesieveproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

const testJA4 = "t13d1516h2_8daaf6152771_e5627efa2ab1"

// ja4Conn is an accepted client connection whose TLS handshake gave testJA4.
type ja4Conn struct{ net.Conn }

func (ja4Conn) GetJA4Fingerprint() (string, error) { return testJA4, nil }

// acceptedClientConn returns the proxy's side of a TCP connection from a client, so the
// proxy has the client and server addresses a PROXY header names.
func acceptedClientConn(t *testing.T) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// proxyHeaderBackend accepts one connection, reads the PROXY header sent on it, returns
// what the header carried and closes the connection.
func proxyHeaderBackend(t *testing.T) (string, <-chan *server.ProxyProtocolInfo) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	reader, err := server.NewProxyProtocolReader("managesieve", server.ProxyProtocolConfig{Enabled: true, TrustedProxies: []string{"127.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	headers := make(chan *server.ProxyProtocolInfo, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		info, _, err := reader.ReadProxyHeader(conn)
		if err != nil {
			t.Errorf("backend read no PROXY header: %v", err)
			info = nil
		}
		headers <- info
	}()
	return ln.Addr().String(), headers
}

// The backend logs the proxy's session ID as proxy_session only when the PROXY v2 header
// carries it (TLV 0xE1), as the IMAP proxy's header does, next to the client's JA4
// fingerprint (TLV 0xE0). The ManageSieve proxy dialed with neither, so a ManageSieve
// session could not be followed from the proxy's log to the backend's (#1369).
func TestConnectToBackendProxyHeaderCarriesSessionID(t *testing.T) {
	addr, headers := proxyHeaderBackend(t)
	cm, err := proxy.NewConnectionManager([]string{addr}, 4190, false, false, true /* remote_use_proxy_protocol */, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client := acceptedClientConn(t)
	sess := &Session{
		server:       &Server{name: "test", hostname: "test-host", connManager: cm},
		clientConn:   client,
		listenerConn: ja4Conn{client},
		ctx:          context.Background(),
		username:     "user@example.com",
		sessionID:    "proxysession1369",
	}

	_ = sess.connectToBackendAndAuth() // fails at the greeting: the backend closes after the header
	if sess.backendConn != nil {
		sess.backendConn.Close()
	}

	select {
	case info := <-headers:
		if info == nil {
			return
		}
		if info.ProxySessionID != sess.sessionID {
			t.Errorf("PROXY header session ID = %q, want the proxy session's %q", info.ProxySessionID, sess.sessionID)
		}
		if info.JA4Fingerprint != testJA4 {
			t.Errorf("PROXY header JA4 = %q, want the client's %q", info.JA4Fingerprint, testJA4)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the backend received no connection")
	}
}
