package managesieveproxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
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

// max_connections_per_ip counts the client a trusted PROXY peer (a load balancer
// in front of the proxy) names (#539).
func TestMaxConnectionsPerIPCountsPROXYClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	srv, err := New(ctx, &resilient.ResilientDatabase{}, "localhost", ServerOptions{
		Name:                 "test",
		Addr:                 addr,
		RemoteAddrs:          []string{"127.0.0.1:4190"},
		RemotePort:           4190,
		InsecureAuth:         true,
		ConnectTimeout:       time.Second,
		AuthRateLimit:        server.AuthRateLimiterConfig{},
		RemoteLookup:         &config.RemoteLookupConfig{},
		ProxyProtocol:        true,
		ProxyProtocolTimeout: "5s",
		TrustedNetworks:      []string{"127.0.0.0/8"},
		MaxConnections:       10,
		MaxConnectionsPerIP:  1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { srv.Stop() })
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
