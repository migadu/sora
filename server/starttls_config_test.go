package server

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

// A protocol library hands tls.Server its plaintext connection on STARTTLS: the
// SoraConn under it must come out of the handshake with the client's JA4, as an
// implicit-TLS SoraTLSConn does, or JA4 client filters never match a STARTTLS
// session.
func TestStartTLSConfigRecordsJA4OnTheSoraConn(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("../testdata/sora.crt", "../testdata/sora.key")
	if err != nil {
		t.Fatal(err)
	}
	serverEnd, clientEnd := net.Pipe()
	defer serverEnd.Close()
	defer clientEnd.Close()
	sc := NewSoraConn(serverEnd, SoraConnConfig{Protocol: "test"})
	// The library's own wrapper (go-imap's limiter conn, say) sits above it.
	upgraded := tls.Server(unwrapConn{sc}, StartTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}, "test"))

	clientErr := make(chan error, 1)
	go func() {
		clientErr <- tls.Client(clientEnd, &tls.Config{InsecureSkipVerify: true}).Handshake()
	}()
	upgraded.SetDeadline(time.Now().Add(5 * time.Second))
	if err := upgraded.Handshake(); err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if err := <-clientErr; err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	ja4, _ := sc.GetJA4Fingerprint()
	if !strings.HasPrefix(ja4, "t13") {
		t.Fatalf("JA4 recorded on the SoraConn = %q, want a TLS 1.3 fingerprint", ja4)
	}
}

// A listener without TLS hands its library no config, and StartTLSConfig must
// keep it that way rather than offer STARTTLS with an empty one.
func TestStartTLSConfigOfNilIsNil(t *testing.T) {
	if cfg := StartTLSConfig(nil, "test"); cfg != nil {
		t.Fatalf("StartTLSConfig(nil) = %v, want nil", cfg)
	}
}
