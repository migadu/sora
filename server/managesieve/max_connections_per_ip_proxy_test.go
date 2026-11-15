package managesieve

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// dialPROXYClient connects to addr as a trusted PROXY peer naming clientIP and
// returns the first line the server sends, or the read error.
func dialPROXYClient(t *testing.T, addr, clientIP string) (string, error) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_, port, _ := net.SplitHostPort(addr)
	if _, err := fmt.Fprintf(c, "PROXY TCP4 %s 127.0.0.1 51000 %s\r\n", clientIP, port); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	return bufio.NewReader(c).ReadString('\n')
}

// max_connections_per_ip counts the client a trusted PROXY peer names (#539).
func TestMaxConnectionsPerIPCountsPROXYClient(t *testing.T) {
	_, addr := startListenerTestServer(t, ManageSieveServerOptions{
		CommandTimeout:       time.Minute,
		ProxyProtocol:        true,
		ProxyProtocolTimeout: "5s",
		TrustedNetworks:      []string{"127.0.0.0/8"},
		MaxConnectionsPerIP:  1,
	})

	if line, err := dialPROXYClient(t, addr, "192.0.2.10"); err != nil {
		t.Fatalf("first connection from 192.0.2.10: %v", err)
	} else {
		t.Logf("first connection from 192.0.2.10: %q", line)
	}
	// Refused with a reply, not a silent close: the PROXY peer is a proxy that has to
	// tell one client's refusal from a dead backend (#703).
	if line, err := dialPROXYClient(t, addr, "192.0.2.10"); err != nil || !strings.HasPrefix(line, "NO ") {
		t.Errorf("second connection from 192.0.2.10 behind a trusted PROXY peer: %q, %v; want max_connections_per_ip = 1 to refuse it with a NO reply", line, err)
	}
	if _, err := dialPROXYClient(t, addr, "192.0.2.11"); err != nil {
		t.Errorf("connection from another client, 192.0.2.11: %v", err)
	}
}
