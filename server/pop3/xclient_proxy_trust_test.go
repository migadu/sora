package pop3

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// The PROXY header's sender (a layer-4 load balancer) is trusted to say who the client is,
// not to vouch for the commands after the header: those are the client's own. So XCLIENT
// is honoured only when the header's source is itself trusted, a proxy behind the load
// balancer. Judging the sender let any client behind it pick the address the auth rate
// limiter and the per-IP connection limits count.
func TestXCLIENTTrustedByProxyHeaderSource(t *testing.T) {
	for _, tc := range []struct {
		name, clientIP string
		accepted       bool
	}{
		{"untrusted client behind trusted load balancer", "198.51.100.66", false},
		{"trusted proxy behind trusted load balancer", "127.0.0.2", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// trusted_networks lists the load balancer (127.0.0.1) and a proxy behind it.
			s, addr := newReloadTestServer(t, POP3ServerOptions{
				TrustedNetworks:             []string{"127.0.0.1/32", "127.0.0.2/32"},
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
		})
	}
}
