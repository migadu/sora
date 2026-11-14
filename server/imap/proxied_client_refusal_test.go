package imap

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// A client over the backend's max_connections_per_ip, named by a proxy's PROXY header,
// is refused after the TLS handshake with a BYE greeting, so the proxy's implicit-TLS
// dial succeeds and the refusal stays that client's. A silent close before the
// handshake made the proxy count a backend failure, and two refused connections of
// one client marked the backend unhealthy for every user (#703).
func TestPerIPRefusalOfPROXYClientKeepsBackendHealthy(t *testing.T) {
	srv, addr, err := newGlobalTLSTestServer(t, IMAPServerOptions{
		TLS:                  true,
		TLSConfig:            globalTLSTestConfig(t),
		ProxyProtocol:        true,
		ProxyProtocolTimeout: "5s",
		TrustedNetworks:      []string{"127.0.0.0/8"},
		MaxConnectionsPerIP:  1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	serveReloadTestServer(t, srv, addr)

	cm, err := proxy.NewConnectionManager([]string{addr}, 993, true /* remote_tls */, false, true /* PROXY */, 2*time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}
	// greeting connects as the proxy does for clientIP and returns the backend's greeting.
	greeting := func(clientIP string) (string, error) {
		conn, _, err := cm.ConnectWithProxy(context.Background(), addr, clientIP, 51000, "127.0.0.1", 993, nil)
		if err != nil {
			return "", err
		}
		t.Cleanup(func() { conn.Close() })
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		return bufio.NewReader(conn).ReadString('\n')
	}

	if line, err := greeting("192.0.2.10"); err != nil || !strings.HasPrefix(line, "* OK") {
		t.Fatalf("first connection from 192.0.2.10: %q, %v", line, err)
	}
	for i := 1; i <= 3; i++ {
		if line, err := greeting("192.0.2.10"); err != nil || !strings.HasPrefix(line, "* BYE ") {
			t.Errorf("connection %d over the limit from 192.0.2.10: %q, %v; want a BYE greeting over TLS", i, line, err)
		}
	}
	if !cm.IsBackendHealthy(addr) {
		t.Error("one client's per-IP refusals marked the backend unhealthy for every user")
	}
	if line, err := greeting("192.0.2.11"); err != nil || !strings.HasPrefix(line, "* OK") {
		t.Errorf("connection from another client, 192.0.2.11: %q, %v", line, err)
	}
}

// A client the auth rate limiter blocks by IP (Tier 2), named by a proxy's PROXY header,
// is refused after the TLS handshake with a BYE greeting, like a client over its per-IP
// connection limit: the block stays that client's, and the backend stays healthy for
// everyone else (#766).
func TestTier2BlockedPROXYClientKeepsBackendHealthy(t *testing.T) {
	limiter := serverPkg.NewAuthRateLimiter("imap", "tier2-proxied-refusal", "localhost", serverPkg.AuthRateLimiterConfig{
		Enabled:          true,
		MaxAttemptsPerIP: 1,
		IPBlockDuration:  time.Minute,
		IPWindowDuration: time.Minute,
		CleanupInterval:  time.Minute,
	})
	t.Cleanup(limiter.Stop)
	blocked := &serverPkg.StringAddr{Addr: "192.0.2.10:51000"}
	limiter.RecordAuthAttempt(context.Background(), blocked, "user@example.com", false)
	if !limiter.IsIPBlocked(blocked) {
		t.Fatal("fixture did not establish a Tier 2 block of 192.0.2.10")
	}

	srv, addr, err := newGlobalTLSTestServer(t, IMAPServerOptions{
		TLS:                  true,
		TLSConfig:            globalTLSTestConfig(t),
		ProxyProtocol:        true,
		ProxyProtocolTimeout: "5s",
		TrustedNetworks:      []string{"127.0.0.0/8"},
		AuthLimiterOverride:  limiter,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	serveReloadTestServer(t, srv, addr)

	cm, err := proxy.NewConnectionManager([]string{addr}, 993, true /* remote_tls */, false, true /* PROXY */, 2*time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}
	// greeting connects as the proxy does for clientIP and returns the backend's greeting.
	greeting := func(clientIP string) (string, error) {
		conn, _, err := cm.ConnectWithProxy(context.Background(), addr, clientIP, 51000, "127.0.0.1", 993, nil)
		if err != nil {
			return "", err
		}
		t.Cleanup(func() { conn.Close() })
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		return bufio.NewReader(conn).ReadString('\n')
	}

	if line, err := greeting("192.0.2.11"); err != nil || !strings.HasPrefix(line, "* OK") {
		t.Fatalf("connection from unblocked 192.0.2.11: %q, %v", line, err)
	}
	for i := 1; i <= 3; i++ {
		if line, err := greeting("192.0.2.10"); err != nil || !strings.HasPrefix(line, "* BYE ") {
			t.Errorf("connection %d from blocked 192.0.2.10: %q, %v; want a BYE greeting over TLS", i, line, err)
		}
	}
	if !cm.IsBackendHealthy(addr) {
		t.Error("one blocked client's connections marked the backend unhealthy for every user")
	}
	if line, err := greeting("192.0.2.11"); err != nil || !strings.HasPrefix(line, "* OK") {
		t.Errorf("connection from unblocked 192.0.2.11 after the blocked client's: %q, %v", line, err)
	}
}

// A Tier 2 blocked client connecting directly, with no PROXY peer naming it, is still
// closed before the TLS handshake and told nothing.
func TestTier2BlockedDirectClientIsClosedSilently(t *testing.T) {
	limiter := serverPkg.NewAuthRateLimiter("imap", "tier2-direct-refusal", "localhost", serverPkg.AuthRateLimiterConfig{
		Enabled:          true,
		MaxAttemptsPerIP: 1,
		IPBlockDuration:  time.Minute,
		IPWindowDuration: time.Minute,
		CleanupInterval:  time.Minute,
	})
	t.Cleanup(limiter.Stop)
	limiter.RecordAuthAttempt(context.Background(), &serverPkg.StringAddr{Addr: "127.0.0.1:51000"}, "user@example.com", false)

	srv, addr, err := newGlobalTLSTestServer(t, IMAPServerOptions{
		TLS:                 true,
		TLSConfig:           globalTLSTestConfig(t),
		AuthLimiterOverride: limiter,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	serveReloadTestServer(t, srv, addr)

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return // closed before the handshake
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if line, err := bufio.NewReader(conn).ReadString('\n'); err == nil || line != "" {
		t.Errorf("blocked direct client read %q, %v; want the connection closed without a reply", line, err)
	}
}
