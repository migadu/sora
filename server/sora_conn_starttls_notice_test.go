package server

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func newNoticeTestConn(t *testing.T, config SoraConnConfig) (*SoraConn, net.Conn) {
	t.Helper()
	transport, peer := net.Pipe()
	config.NoAbsoluteTimeout = true
	sc := NewSoraConn(transport, config)
	t.Cleanup(func() { peer.Close(); sc.Close() })
	return sc, peer
}

func handshakeNoticeTestConn(t *testing.T, sc *SoraConn, peer net.Conn) (*tls.Conn, *tls.Conn) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("../testdata/sora.crt", "../testdata/sora.key")
	if err != nil {
		t.Fatal(err)
	}
	sc.SetDeadline(time.Now().Add(5 * time.Second))
	secure := tls.Server(sc, StartTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}, "test"))
	client := tls.Client(peer, &tls.Config{InsecureSkipVerify: true})
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.Handshake() }()
	if err := secure.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-clientDone; err != nil {
		t.Fatal(err)
	}
	CompleteStartTLS(unwrapConn{sc}, secure)
	return secure, client
}

// Client data is opaque to the transport. Only the library's accepted
// transition changes whether a plaintext notice is safe.
func TestNoticeConnIgnoresCommandLikeClientData(t *testing.T) {
	sc, peer := newNoticeTestConn(t, SoraConnConfig{})
	for _, data := range []string{"USER STLS\r\n", "STLS\r\n", "literal\r\nSTARTTLS\r\n", "a STARTTLS bogus\r\n"} {
		done := make(chan error, 1)
		go func() { _, err := peer.Write([]byte(data)); done <- err }()
		if _, err := io.ReadFull(sc, make([]byte, len(data))); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		for _, conn := range []net.Conn{sc, unwrapConn{sc}} {
			if got := NoticeConn(conn); got != conn {
				t.Fatalf("notice writer after opaque data %q = %T", data, got)
			}
		}
	}
}

// The completed connection is published without waiting for another read or
// asking a library accessor from a different goroutine.
func TestNoticeConnFollowsExplicitStartTLSHooks(t *testing.T) {
	sc, peer := newNoticeTestConn(t, SoraConnConfig{})
	if got := NoticeConn(sc); got != sc {
		t.Fatalf("plaintext writer = %T", got)
	}
	BeginStartTLS(unwrapConn{sc})
	if WriteNotice(sc, func(net.Conn) { t.Error("notice during handshake") }) {
		t.Fatal("writer available during handshake")
	}
	answered := make(chan net.Conn, 1)
	go func() { answered <- NoticeConn(sc) }()
	select {
	case got := <-answered:
		if got != nil {
			t.Fatalf("negotiating writer = %T", got)
		}
	case <-time.After(time.Second):
		t.Fatal("notice selection waited for handshake")
	}
	secure, client := handshakeNoticeTestConn(t, sc, peer)
	for _, conn := range []net.Conn{sc, unwrapConn{sc}} {
		if got := NoticeConn(conn); got != secure {
			t.Fatalf("completed TLS writer = %T", got)
		}
	}
	written := make(chan bool, 1)
	go func() { written <- WriteNotice(sc, func(conn net.Conn) { fmt.Fprint(conn, "goodbye\r\n") }) }()
	got := make([]byte, len("goodbye\r\n"))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "goodbye\r\n" || !<-written {
		t.Fatalf("TLS notice = %q", got)
	}
}

func TestTimeoutNoticeUsesCompletedStartTLSConn(t *testing.T) {
	sc, peer := newNoticeTestConn(t, SoraConnConfig{
		IdleTimeout: time.Minute,
		OnTimeout:   func(conn net.Conn, reason string) { fmt.Fprintf(conn, "goodbye %s\r\n", reason) },
	})
	BeginStartTLS(sc)
	_, client := handshakeNoticeTestConn(t, sc, peer)
	sc.checkTimeouts(time.Now().Add(time.Hour))
	got := make([]byte, len("goodbye idle\r\n"))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "goodbye idle\r\n" {
		t.Fatalf("timeout notice = %q", got)
	}
}

func TestTimeoutNoticeReachesPlaintextSessionOfStartTLSListener(t *testing.T) {
	sc, peer := newNoticeTestConn(t, SoraConnConfig{
		IdleTimeout: time.Minute,
		OnTimeout:   func(conn net.Conn, reason string) { fmt.Fprintf(conn, "goodbye %s\r\n", reason) },
	})
	sc.checkTimeouts(time.Now().Add(time.Hour))
	peer.SetReadDeadline(time.Now().Add(time.Second))
	got, _ := io.ReadAll(peer)
	if string(got) != "goodbye idle\r\n" {
		t.Fatalf("plaintext timeout notice = %q", got)
	}
}

// An earlier plaintext notice must finish before the pre-acknowledgement hook
// returns. No plaintext writer can be selected after that transition.
func TestBeginStartTLSWaitsForPriorNotice(t *testing.T) {
	sc, _ := newNoticeTestConn(t, SoraConnConfig{})
	writing, finish := make(chan struct{}), make(chan struct{})
	written := make(chan bool, 1)
	go func() { written <- WriteNotice(sc, func(net.Conn) { close(writing); <-finish }) }()
	<-writing
	begun := make(chan struct{})
	go func() { BeginStartTLS(sc); close(begun) }()
	select {
	case <-begun:
		t.Fatal("STARTTLS acknowledged before earlier notice completed")
	case <-time.After(50 * time.Millisecond):
	}
	close(finish)
	<-begun
	if !<-written {
		t.Fatal("no writer for earlier plaintext notice")
	}
	if WriteNotice(sc, func(net.Conn) { t.Error("plaintext notice after BeginStartTLS") }) {
		t.Fatal("notice writer during negotiation")
	}
}
