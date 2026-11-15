package managesieve

import (
	"bufio"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server/proxy"
)

// A client over the backend's max_connections_per_ip, named by a proxy's PROXY header,
// is refused after the TLS handshake with a BYE (TRYLATER) reply, so the proxy's
// implicit-TLS dial succeeds and the refusal stays that client's. A silent close
// before the handshake made the proxy count a backend failure, and two refused
// connections of one client marked the backend unhealthy for every user (#703).
func TestPerIPRefusalOfPROXYClientKeepsBackendHealthy(t *testing.T) {
	_, addr := startListenerTestServer(t, ManageSieveServerOptions{
		TLS:                  true,
		TLSCertFile:          "../../testdata/sora.crt",
		TLSKeyFile:           "../../testdata/sora.key",
		CommandTimeout:       time.Minute,
		MaxConnections:       10,
		ProxyProtocol:        true,
		ProxyProtocolTimeout: "5s",
		TrustedNetworks:      []string{"127.0.0.0/8"},
		MaxConnectionsPerIP:  1,
	})

	cm, err := proxy.NewConnectionManager([]string{addr}, 4190, true /* remote_tls */, false, true /* PROXY */, 2*time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}
	// greeting connects as the proxy does for clientIP and returns the backend's first line and reader.
	greeting := func(clientIP string) (string, *bufio.Reader, error) {
		conn, _, err := cm.ConnectWithProxy(context.Background(), addr, clientIP, 51000, "127.0.0.1", 4190, nil)
		if err != nil {
			return "", nil, err
		}
		t.Cleanup(func() { conn.Close() })
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		line, err := r.ReadString('\n')
		return line, r, err
	}

	// An accepted connection's greeting starts with its capabilities.
	if line, _, err := greeting("192.0.2.10"); err != nil || !strings.HasPrefix(line, `"IMPLEMENTATION"`) {
		t.Fatalf("first connection from 192.0.2.10: %q, %v", line, err)
	}
	for i := 1; i <= 3; i++ {
		line, r, err := greeting("192.0.2.10")
		if err != nil || line != "BYE (TRYLATER) \"Too many connections\"\r\n" {
			t.Fatalf("connection %d over the limit from 192.0.2.10: %q, %v; want a BYE (TRYLATER) reply over TLS", i, line, err)
		}
		assertRefusalCloses(t, r)
	}
	if !cm.IsBackendHealthy(addr) {
		t.Error("one client's per-IP refusals marked the backend unhealthy for every user")
	}
	if line, _, err := greeting("192.0.2.11"); err != nil || !strings.HasPrefix(line, `"IMPLEMENTATION"`) {
		t.Errorf("connection from another client, 192.0.2.11: %q, %v", line, err)
	}
}
