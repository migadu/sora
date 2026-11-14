package delivery

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

// greetingRecorder is a go-smtp backend that records every HELO/EHLO the relay
// client sends: the server calls NewSession on each greeting, with the
// command and its argument on the Conn. It also records the SNI of each TLS
// handshake.
type greetingRecorder struct {
	mu        sync.Mutex
	greetings []string
	sni       []string
	delivered int
}

func (b *greetingRecorder) NewSession(c *smtp.Conn) (smtp.Session, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.greetings = append(b.greetings, c.Greeting()+" "+c.Hostname())
	return &greetingSession{b: b}, nil
}

type greetingSession struct{ b *greetingRecorder }

func (s *greetingSession) Reset()        {}
func (s *greetingSession) Logout() error { return nil }
func (s *greetingSession) Mail(ctx context.Context, from string, opts *smtp.MailOptions) error {
	return nil
}
func (s *greetingSession) Rcpt(ctx context.Context, to string, opts *smtp.RcptOptions) error {
	return nil
}
func (s *greetingSession) Data(ctx context.Context, r io.Reader) error {
	if _, err := io.Copy(io.Discard, r); err != nil {
		return err
	}
	s.b.mu.Lock()
	s.b.delivered++
	s.b.mu.Unlock()
	return nil
}

func relayTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startGreetingRecorder serves SMTP on loopback in plaintext, with STARTTLS
// offered, or with implicit TLS, and returns the address as "localhost:port"
// so the client derives a TLS server name from it.
func startGreetingRecorder(t *testing.T, startTLS, implicitTLS bool) (string, *greetingRecorder) {
	t.Helper()
	backend := &greetingRecorder{}
	srv := smtp.NewServer(backend)
	srv.Domain = "relay.example.com"

	cert := relayTestCert(t)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			backend.mu.Lock()
			backend.sni = append(backend.sni, hello.ServerName)
			backend.mu.Unlock()
			return &cert, nil
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if implicitTLS {
		ln = tls.NewListener(ln, tlsConfig)
	} else if startTLS {
		srv.TLSConfig = tlsConfig
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return net.JoinHostPort("localhost", port), backend
}

// TestSMTPRelayEHLOUsesConfiguredName checks that every EHLO the relay sends
// carries the configured name, including the one before STARTTLS. RFC 5321
// §2.3.5: "The domain name given in the EHLO command MUST be either a primary
// host name (a domain name that resolves to an address RR) or, if the host has
// no name, an address literal". RFC 3207 §4.2 has the client send EHLO again
// after the handshake. A relay that checks the name when the EHLO arrives
// refuses "EHLO localhost" before STARTTLS is ever reached.
func TestSMTPRelayEHLOUsesConfiguredName(t *testing.T) {
	tests := []struct {
		name        string
		useTLS      bool
		startTLS    bool
		implicitTLS bool
		heloHost    string
		wantEHLOs   []string
		wantSNI     []string
	}{
		{
			name:      "plaintext",
			heloHost:  "mail.example.com",
			wantEHLOs: []string{"EHLO mail.example.com"},
		},
		{
			name:      "STARTTLS",
			useTLS:    true,
			startTLS:  true,
			heloHost:  "mail.example.com",
			wantEHLOs: []string{"EHLO mail.example.com", "EHLO mail.example.com"},
			wantSNI:   []string{"localhost"},
		},
		{
			name:        "implicit TLS",
			useTLS:      true,
			implicitTLS: true,
			heloHost:    "mail.example.com",
			wantEHLOs:   []string{"EHLO mail.example.com"},
			wantSNI:     []string{"localhost"},
		},
		{
			// No name configured keeps the go-smtp default on both EHLOs.
			name:      "STARTTLS without a configured name",
			useTLS:    true,
			startTLS:  true,
			wantEHLOs: []string{"EHLO localhost", "EHLO localhost"},
			wantSNI:   []string{"localhost"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, backend := startGreetingRecorder(t, tt.startTLS, tt.implicitTLS)
			handler := &SMTPRelayHandler{
				SMTPHost:     addr,
				UseTLS:       tt.useTLS,
				TLSVerify:    false, // self-signed test certificate
				UseStartTLS:  tt.startTLS,
				HELOHost:     tt.heloHost,
				MetricsLabel: "test",
				Logger:       &testLogger{},
			}

			if err := handler.SendToExternalRelay("sender@example.com", "recipient@example.com",
				[]byte("Subject: EHLO\r\n\r\nbody\r\n")); err != nil {
				t.Fatalf("SendToExternalRelay: %v", err)
			}

			backend.mu.Lock()
			defer backend.mu.Unlock()
			if got, want := strings.Join(backend.greetings, " | "), strings.Join(tt.wantEHLOs, " | "); got != want {
				t.Errorf("greetings = [%s], want [%s]", got, want)
			}
			if got, want := strings.Join(backend.sni, " | "), strings.Join(tt.wantSNI, " | "); got != want {
				t.Errorf("TLS server names = [%s], want [%s]", got, want)
			}
			if backend.delivered != 1 {
				t.Errorf("delivered %d messages, want 1", backend.delivered)
			}
		})
	}
}
