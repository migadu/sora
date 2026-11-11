package imapproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server/proxy"
)

// fakeSTARTTLSBackend serves one connection: a greeting, then reply(tag) to
// STARTTLS. After a tagged OK it upgrades with TLS. got receives the next line
// the proxy sent, through TLS after an upgrade and in plaintext otherwise (""
// when none came within a second), so a test sees whether credentials ever
// crossed in the clear.
func fakeSTARTTLSBackend(t *testing.T, reply func(tag string) string) (addr string, got <-chan string) {
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
		io.WriteString(conn, "* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] fake backend ready\r\n")
		line, _ := r.ReadString('\n')
		tag, cmd, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
		if cmd != "STARTTLS" {
			lines <- line
			return
		}
		resp := reply(tag)
		io.WriteString(conn, resp)
		var w io.Writer = conn
		if strings.HasPrefix(resp, tag+" OK") {
			tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
			if tlsConn.Handshake() != nil {
				lines <- ""
				return
			}
			w, r = tlsConn, bufio.NewReader(tlsConn)
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		line, _ = r.ReadString('\n')
		lines <- line
		if authTag, _, ok := strings.Cut(line, " "); ok {
			io.WriteString(w, authTag+" OK logged in\r\n")
		}
	}()
	return ln.Addr().String(), lines
}

// connectThroughSTARTTLS runs connectToBackend against addr with remote_tls and
// remote_tls_use_starttls.
func connectThroughSTARTTLS(t *testing.T, addr string) (*Session, error) {
	t.Helper()
	cm, err := proxy.NewConnectionManagerFromOptions(proxy.ManagerOptions{
		RemoteAddrs:        []string{addr},
		RemotePort:         143,
		Settings:           proxy.BackendSettings{TLS: true, TLSUseStartTLS: true},
		ConnectTimeout:     2 * time.Second,
		ServerName:         "test",
		DisableHealthCheck: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := &Server{
		name:           "test",
		hostname:       "test-host",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
		connManager:    cm,
		authLimiter:    &fakeAuthLimiter{},
	}
	client, remote := net.Pipe()
	t.Cleanup(func() { client.Close(); remote.Close() })
	sess := newSession(srv, client)
	sess.username = "user@example.com"
	err = sess.connectToBackend()
	if sess.backendConn != nil {
		t.Cleanup(func() { sess.backendConn.Close() })
	}
	return sess, err
}

// remote_tls_use_starttls on an imap_proxy: the leg is dialed plaintext, so the proxy
// must upgrade it with STARTTLS before AUTHENTICATE carries the master credential.
func TestConnectToBackendUpgradesWithSTARTTLS(t *testing.T) {
	addr, got := fakeSTARTTLSBackend(t, func(tag string) string { return tag + " OK begin TLS\r\n" })
	sess, err := connectThroughSTARTTLS(t, addr)
	if err != nil {
		t.Fatalf("connectToBackend: %v", err)
	}
	if _, err := sess.authenticateToBackend(); err != nil {
		t.Fatalf("authenticateToBackend after STARTTLS: %v", err)
	}
	if line := <-got; !strings.Contains(line, " AUTHENTICATE PLAIN ") {
		t.Fatalf("the backend read %q through TLS, want AUTHENTICATE PLAIN", line)
	}
	if _, ok := sess.backendConn.(*tls.Conn); !ok {
		t.Errorf("backendConn after STARTTLS is %T, want the *tls.Conn the relay must use", sess.backendConn)
	}
}

// A backend that refuses STARTTLS must not get the credential in plaintext instead.
func TestConnectToBackendFailsClosedWhenSTARTTLSIsRefused(t *testing.T) {
	addr, got := fakeSTARTTLSBackend(t, func(tag string) string { return tag + " NO STARTTLS not available\r\n" })
	if _, err := connectThroughSTARTTLS(t, addr); err == nil {
		t.Fatal("connectToBackend succeeded although the backend refused STARTTLS")
	}
	if line := <-got; line != "" {
		t.Fatalf("after the refused STARTTLS the proxy sent %q in plaintext", line)
	}
}

// Bytes that follow the tagged OK in the same read came in plaintext, where anyone on
// the path could have put them: the connection fails rather than dropping them.
func TestConnectToBackendRefusesDataAfterSTARTTLSResponse(t *testing.T) {
	addr, _ := fakeSTARTTLSBackend(t, func(tag string) string {
		return tag + " OK begin TLS\r\n* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] injected\r\n"
	})
	_, err := connectThroughSTARTTLS(t, addr)
	if err == nil || !strings.Contains(err.Error(), "sent data after its STARTTLS response") {
		t.Fatalf("connectToBackend = %v, want the refusal of data after the OK", err)
	}
}
