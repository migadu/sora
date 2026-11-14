package lmtp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

// startProxiedXCLIENTBackend serves a database-free LMTP backend whose listener takes
// PROXY headers from 127.0.0.1, a layer-4 load balancer, and returns its address and the
// sessions go-smtp creates, in order.
func startProxiedXCLIENTBackend(t *testing.T) (string, <-chan *LMTPSession) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	b, err := New(ctx, "xclient-proxy-trust", "localhost", addr, nil, nil, nil, LMTPServerOptions{
		// The load balancer (127.0.0.1) and a proxy behind it (127.0.0.2).
		TrustedNetworks:             []string{"127.0.0.1/32", "127.0.0.2/32"},
		ProxyProtocol:               true,
		ProxyProtocolTrustedProxies: []string{"127.0.0.1/32"},
		MaxConnections:              10,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sessions := make(chan *LMTPSession, 8)
	b.server.Backend = smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
		s, err := b.NewSession(c)
		if err == nil {
			sessions <- s.(*LMTPSession)
		}
		return s, err
	})
	go b.Start(make(chan error, 1))
	t.Cleanup(func() { b.Close() })
	return addr, sessions
}

// lmtpReply reads one complete (possibly multi-line) reply and returns its last line.
func lmtpReply(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	for {
		line := readReplyLine(t, r)
		if len(line) < 4 || line[3] != '-' {
			return line
		}
	}
}

// The PROXY header's sender (a layer-4 load balancer) is trusted to say who the client is,
// not to vouch for the commands after the header: those are the client's own. So XCLIENT
// ADDR replaces the address the header gave only when the header's source is itself
// trusted, a proxy behind the load balancer. The rest of the XCLIENT still applies: an
// lmtp_proxy sends a PROXY header for the address and XCLIENT for the client's HELO.
// The delivery session is the one go-smtp creates at the LHLO after XCLIENT, which takes
// the XCLIENT attributes go-smtp kept on the connection.
func TestXCLIENTAddrTrustedByProxyHeaderSource(t *testing.T) {
	for _, tc := range []struct {
		name, clientIP, wantRemote string
	}{
		{"untrusted client behind trusted load balancer", "198.51.100.66", "198.51.100.66"},
		{"trusted proxy behind trusted load balancer", "127.0.0.2", "203.0.113.7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, sessions := startProxiedXCLIENTBackend(t)
			conn := dialUntilListening(t, addr)
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			fmt.Fprintf(conn, "PROXY TCP4 %s 127.0.0.1 51000 24\r\n", tc.clientIP)
			r := bufio.NewReader(conn)
			if line := lmtpReply(t, r); !strings.HasPrefix(line, "220 ") {
				t.Fatalf("greeting = %q", line)
			}

			fmt.Fprint(conn, "LHLO mta.example.org\r\n")
			if line := lmtpReply(t, r); !strings.HasPrefix(line, "250 ") {
				t.Fatalf("LHLO = %q", line)
			}
			fmt.Fprint(conn, "XCLIENT ADDR=203.0.113.7 HELO=mx.example.org\r\n")
			if line := lmtpReply(t, r); !strings.HasPrefix(line, "220 ") {
				t.Fatalf("XCLIENT = %q, want the new greeting", line)
			}
			fmt.Fprint(conn, "LHLO mta.example.org\r\n")
			if line := lmtpReply(t, r); !strings.HasPrefix(line, "250 ") {
				t.Fatalf("LHLO after XCLIENT = %q", line)
			}

			var delivery *LMTPSession
			for i := 0; i < 2; i++ {
				select {
				case delivery = <-sessions:
				case <-time.After(3 * time.Second):
					t.Fatalf("session %d was not created", i+1)
				}
			}
			if delivery.RemoteIP != tc.wantRemote {
				t.Errorf("delivery session client address = %q, want %q", delivery.RemoteIP, tc.wantRemote)
			}
			if delivery.ForwardingParams == nil || delivery.ForwardingParams.HELO != "mx.example.org" {
				t.Errorf("delivery session lost the forwarded HELO: %+v", delivery.ForwardingParams)
			}
		})
	}
}
