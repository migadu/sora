package server

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
)

// TestSoraTLSConnRefusesIOBeforeHandshake pins the fail-loud guard: a
// SoraTLSConn accepted from an implicit-TLS listener must refuse Read/Write
// until PerformHandshake has run. Without the guard, a listener-composition
// regression (a wrapper hiding the SoraTLSConn from the handshake trigger)
// silently degrades to a plaintext greeting on a TLS port — the Shape-A
// failure documented in docs/proxy-protocol-tls-composition.md.
func TestSoraTLSConnRefusesIOBeforeHandshake(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	defer serverEnd.Close()

	conn := NewSoraTLSConn(serverEnd, &tls.Config{}, SoraConnConfig{Protocol: "test"})

	if _, err := conn.Write([]byte("* OK plaintext greeting\r\n")); !errors.Is(err, ErrTLSHandshakeNotPerformed) {
		t.Fatalf("Write before handshake: want ErrTLSHandshakeNotPerformed, got %v", err)
	}
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); !errors.Is(err, ErrTLSHandshakeNotPerformed) {
		t.Fatalf("Read before handshake: want ErrTLSHandshakeNotPerformed, got %v", err)
	}
}

// TestSoraTLSConnReturnsHandshakeErrAfterFailure verifies that after a failed
// handshake attempt the guard surfaces the cached handshake error instead of
// allowing plaintext I/O on the broken stream.
func TestSoraTLSConnReturnsHandshakeErrAfterFailure(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()

	conn := NewSoraTLSConn(serverEnd, &tls.Config{}, SoraConnConfig{Protocol: "test"})

	// Feed a plaintext line so the pre-handshake probe rejects the
	// connection (ErrPlainTextOnTLSPort) instead of blocking, and drain the
	// probe's rejection message — net.Pipe writes are synchronous, so the
	// server side would otherwise block writing it.
	go func() {
		clientEnd.Write([]byte("EHLO plaintext\r\n"))
		buf := make([]byte, 256)
		for {
			if _, err := clientEnd.Read(buf); err != nil {
				return
			}
		}
	}()

	hsErr := conn.PerformHandshake()
	if hsErr == nil {
		t.Fatal("PerformHandshake should fail on plaintext input")
	}

	if _, err := conn.Write([]byte("greeting\r\n")); !errors.Is(err, hsErr) {
		t.Fatalf("Write after failed handshake: want cached handshake error %v, got %v", hsErr, err)
	}
}
