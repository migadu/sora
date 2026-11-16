package pop3

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// onlySession returns the server's one active session.
func onlySession(t *testing.T, s *POP3Server) *POP3Session {
	t.Helper()
	s.activeSessionsMutex.RLock()
	defer s.activeSessionsMutex.RUnlock()
	if len(s.activeSessions) != 1 {
		t.Fatalf("%d active sessions, want 1", len(s.activeSessions))
	}
	for session := range s.activeSessions {
		return session
	}
	return nil
}

// The PROXY header's sender (a layer-4 load balancer) is trusted to say who the client is,
// not to vouch for the commands after the header: those may be the client's own. So
// XCLIENT ADDR replaces the address the header gave only when the header's source is
// itself trusted, a proxy behind the load balancer. Judging the sender let any client
// behind it pick the address the auth rate limiter and the per-IP connection limits count.
// XCLIENT itself is still answered +OK when its sender is trusted: a pop3_proxy sends a
// PROXY header and XCLIENT on one connection, and a refusal is a warning on every login.
func TestXCLIENTTrustedByProxyHeaderSource(t *testing.T) {
	for _, tc := range []struct {
		name, clientIP string
		trusted        []string // trusted_networks
		accepted       bool
		wantRemote     string
	}{
		// trusted_networks lists the load balancer (127.0.0.1) and a proxy behind it.
		{"untrusted client behind trusted load balancer", "198.51.100.66", []string{"127.0.0.1/32", "127.0.0.2/32"}, true, "198.51.100.66"},
		{"trusted proxy behind trusted load balancer", "127.0.0.2", []string{"127.0.0.1/32", "127.0.0.2/32"}, true, "203.0.113.5"},
		// The load balancer may send PROXY headers but is not in trusted_networks.
		{"untrusted client behind untrusted load balancer", "198.51.100.66", []string{"127.0.0.2/32"}, false, "198.51.100.66"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, addr := newReloadTestServer(t, POP3ServerOptions{
				TrustedNetworks:             tc.trusted,
				ProxyProtocol:               true,
				ProxyProtocolTrustedProxies: []string{"127.0.0.1/32"},
				CommandTimeout:              time.Minute,
			})
			startListenerTestServer(t, s, addr)
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			fmt.Fprintf(conn, "PROXY TCP4 %s 127.0.0.1 51000 110\r\n", tc.clientIP)
			r := bufio.NewReader(conn)
			if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
				t.Fatalf("greeting = %q, %v", line, err)
			}
			fmt.Fprint(conn, "XCLIENT ADDR=203.0.113.5 PORT=51000 TTL=5\r\n")
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.HasPrefix(line, "+OK"); got != tc.accepted {
				t.Errorf("XCLIENT from %s behind the load balancer: %q, want accepted = %v", tc.clientIP, line, tc.accepted)
			}
			if got := onlySession(t, s).RemoteIP; got != tc.wantRemote {
				t.Errorf("session client address = %q, want %q", got, tc.wantRemote)
			}
		})
	}
}
