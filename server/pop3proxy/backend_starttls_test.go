package pop3proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// fakeSTLSBackend serves one connection: a greeting, then reply to STLS. After a
// +OK it upgrades with TLS. got receives the next line the proxy sent, through
// TLS after an upgrade and in plaintext otherwise ("" when none came within a
// second), so a test sees whether credentials ever crossed in the clear.
func fakeSTLSBackend(t *testing.T, reply string) (addr string, got <-chan string) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("../../testdata/sora.crt", "../../testdata/sora.key")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	lines := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		io.WriteString(conn, "+OK fake backend ready\r\n")
		if line, _ := r.ReadString('\n'); line != "STLS\r\n" {
			lines <- line
			return
		}
		io.WriteString(conn, reply)
		var rw io.ReadWriter = struct {
			io.Reader
			io.Writer
		}{r, conn}
		if strings.HasPrefix(reply, "+OK") {
			tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
			if tlsConn.Handshake() != nil {
				lines <- ""
				return
			}
			rw, r = tlsConn, bufio.NewReader(tlsConn)
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		line, _ := r.ReadString('\n')
		lines <- line
		io.WriteString(rw, "+OK logged in\r\n")
	}()
	return ln.Addr().String(), lines
}

// connectThroughSTLS runs connectToBackend against addr with remote_tls and
// remote_tls_use_starttls.
func connectThroughSTLS(t *testing.T, addr string) (*POP3ProxySession, error) {
	t.Helper()
	cm, err := proxy.NewConnectionManagerFromOptions(proxy.ManagerOptions{
		RemoteAddrs:        []string{addr},
		RemotePort:         110,
		Settings:           proxy.BackendSettings{TLS: true, TLSUseStartTLS: true},
		ConnectTimeout:     2 * time.Second,
		ServerName:         "test",
		DisableHealthCheck: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	clientA, clientB := net.Pipe()
	t.Cleanup(func() { clientA.Close(); clientB.Close() })
	sess := &POP3ProxySession{
		server:     &POP3ProxyServer{name: "test", hostname: "test-host", connManager: cm},
		clientConn: clientA,
		ctx:        context.Background(),
		username:   "user@example.com",
	}
	err = sess.connectToBackend()
	if sess.backendConn != nil {
		t.Cleanup(func() { sess.backendConn.Close() })
	}
	return sess, err
}

// remote_tls_use_starttls on a pop3_proxy: the leg is dialed plaintext, so the proxy
// must upgrade it with STLS before AUTH carries the master credential across.
func TestConnectToBackendUpgradesWithSTLS(t *testing.T) {
	addr, got := fakeSTLSBackend(t, "+OK begin TLS\r\n")
	sess, err := connectThroughSTLS(t, addr)
	if err != nil {
		t.Fatalf("connectToBackend: %v", err)
	}
	if line := <-got; !strings.HasPrefix(line, "AUTH PLAIN ") {
		t.Fatalf("the backend read %q through TLS, want AUTH PLAIN", line)
	}
	if _, ok := sess.backendConn.(*tls.Conn); !ok {
		t.Errorf("backendConn after STLS is %T, want the *tls.Conn the relay must use", sess.backendConn)
	}
}

// A backend that refuses STLS must not get the credential in plaintext instead.
func TestConnectToBackendFailsClosedWhenSTLSIsRefused(t *testing.T) {
	addr, got := fakeSTLSBackend(t, "-ERR STLS not available\r\n")
	_, err := connectThroughSTLS(t, addr)
	if err == nil || !server.IsBackendError(err) {
		t.Fatalf("connectToBackend = %v, want a backend error", err)
	}
	if line := <-got; line != "" {
		t.Fatalf("after the refused STLS the proxy sent %q in plaintext", line)
	}
}

// Bytes that follow the STLS +OK in the same read came in plaintext, where anyone on
// the path could have put them: the connection fails rather than dropping them.
func TestConnectToBackendRefusesDataAfterSTLSResponse(t *testing.T) {
	addr, _ := fakeSTLSBackend(t, "+OK begin TLS\r\n+OK injected\r\n")
	_, err := connectThroughSTLS(t, addr)
	if err == nil || !strings.Contains(err.Error(), "sent data after its STLS response") {
		t.Fatalf("connectToBackend = %v, want the refusal of data after +OK", err)
	}
}
