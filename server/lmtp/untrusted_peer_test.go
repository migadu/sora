package lmtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// A peer outside trusted_networks is closed at accept, as lmtp_proxy closes it: it is
// not greeted, gets no TLS handshake on an implicit-TLS listener, and takes no
// max_connections slot. Before (#458) it was greeted with 220, refused only at LHLO with
// a 451 on a connection that stayed open, and held its slot for as long as it kept
// sending commands, so such peers could fill max_connections and block delivery from the
// trusted MTAs. A peer inside trusted_networks is greeted as before.
func TestTrustedNetworksCheckedAtAccept(t *testing.T) {
	for _, tc := range []struct {
		name        string
		trusted     []string
		implicitTLS bool
		admitted    bool
	}{
		{"untrusted plain text", []string{"192.0.2.0/24"}, false, false},
		{"untrusted implicit TLS", []string{"192.0.2.0/24"}, true, false},
		{"trusted plain text", []string{"127.0.0.0/8"}, false, true},
		{"trusted implicit TLS", []string{"127.0.0.0/8"}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, addr := startAdmissionTestBackend(t, tc.trusted, tc.implicitTLS)
			raw := dialUntilListening(t, addr)
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(2 * time.Second))

			var conn net.Conn = raw
			if tc.implicitTLS {
				tlsConn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
				err := tlsConn.Handshake()
				if !tc.admitted {
					if err == nil {
						line, _ := bufio.NewReader(tlsConn).ReadString('\n')
						t.Fatalf("peer outside trusted_networks completed the TLS handshake and was sent %q, holding %d max_connections slot(s); want the connection closed at accept",
							line, b.limiter.GetStats().TotalConnections)
					}
					assertNoSlotHeld(t, b)
					return
				}
				if err != nil {
					t.Fatalf("TLS handshake from a trusted peer: %v", err)
				}
				conn = tlsConn
			}

			if tc.admitted {
				if line := readReplyLine(t, bufio.NewReader(conn)); !strings.HasPrefix(line, "220 ") {
					t.Fatalf("trusted peer greeted with %q, want 220", line)
				}
				if n := b.limiter.GetStats().TotalConnections; n != 1 {
					t.Errorf("trusted peer holds %d max_connections slots, want 1", n)
				}
				return
			}

			got, err := io.ReadAll(conn)
			if len(got) > 0 {
				t.Errorf("peer outside trusted_networks was sent %q; want the connection closed at accept with nothing sent", got)
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Errorf("peer outside trusted_networks still connected, holding %d max_connections slot(s)", b.limiter.GetStats().TotalConnections)
			}
			assertNoSlotHeld(t, b)
		})
	}
}

func assertNoSlotHeld(t *testing.T, b *LMTPServerBackend) {
	t.Helper()
	if n := b.limiter.GetStats().TotalConnections; n != 0 {
		t.Errorf("peer outside trusted_networks holds %d max_connections slot(s), want 0", n)
	}
}

// startAdmissionTestBackend starts an LMTP backend admitting the trusted networks, with
// a single max_connections slot, stopped when the test ends.
func startAdmissionTestBackend(t *testing.T, trusted []string, implicitTLS bool) (*LMTPServerBackend, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	options := LMTPServerOptions{
		TrustedNetworks: trusted,
		MaxConnections:  1,
	}
	if implicitTLS {
		options.TLS = true
		options.TLSConfig = &tls.Config{Certificates: []tls.Certificate{selfSignedTestCert(t)}}
	}
	b, err := New(ctx, "admission-test", "localhost", addr, nil, nil, nil, options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go b.Start(make(chan error, 1))
	t.Cleanup(func() { b.Close() })
	return b, addr
}

// dialUntilListening dials addr until the server listens, so the connection it returns
// is the first the server accepts.
func dialUntilListening(t *testing.T, addr string) net.Conn {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); ; {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
