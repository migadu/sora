package pop3

import (
	"bufio"
	"fmt"
	"net"
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
	s, addr := newReloadTestServer(t, POP3ServerOptions{
		CommandTimeout:       time.Minute,
		ProxyProtocol:        true,
		ProxyProtocolTimeout: "5s",
		TrustedNetworks:      []string{"127.0.0.0/8"},
		MaxConnectionsPerIP:  1,
	})
	errChan := make(chan error, 1)
	go s.Start(errChan)
	t.Cleanup(s.Close)
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
	}

	if line, err := dialPROXYClient(t, addr, "192.0.2.10"); err != nil {
		t.Fatalf("first connection from 192.0.2.10: %v", err)
	} else {
		t.Logf("first connection from 192.0.2.10: %q", line)
	}
	if line, err := dialPROXYClient(t, addr, "192.0.2.10"); err == nil {
		t.Errorf("second connection from 192.0.2.10 behind a trusted PROXY peer was greeted (%q), want it closed by max_connections_per_ip = 1", line)
	}
	if _, err := dialPROXYClient(t, addr, "192.0.2.11"); err != nil {
		t.Errorf("connection from another client, 192.0.2.11: %v", err)
	}
}
