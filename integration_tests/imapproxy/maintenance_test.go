//go:build integration

package imapproxy_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
	"github.com/migadu/sora/server/proxy"
)

// rawIMAPLogin opens a proxy connection and logs in, returning the connection and its reader.
func rawIMAPLogin(t *testing.T, proxyAddr, email, password string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	r := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	fmt.Fprintf(conn, "a1 LOGIN %q %q\r\n", email, password)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read LOGIN response: %v", err)
		}
		if strings.HasPrefix(line, "a1 ") {
			if !strings.HasPrefix(line, "a1 OK") {
				t.Fatalf("LOGIN failed: %s", strings.TrimSpace(line))
			}
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	return conn, r
}

// sessionHosts returns the backend host of every proxied session.
func sessionHosts(p *imapproxy.Server) []string {
	var hosts []string
	for _, target := range p.MaintenanceTargets() {
		h, _, _ := net.SplitHostPort(target.Backend)
		hosts = append(hosts, h)
	}
	return hosts
}

func waitForSessions(t *testing.T, p *imapproxy.Server, cond func(hosts []string) bool, what string) []string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		hosts := sessionHosts(p)
		if cond(hosts) {
			return hosts
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s; session backends: %v", what, hosts)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestIMAPProxyBackendMaintenance drives maintenance end to end through the database list
// the proxies poll: a session on the backend put in maintenance gets BYE [UNAVAILABLE],
// the client's next login lands on the other backend, and turning maintenance off routes
// the user back.
func TestIMAPProxyBackendMaintenance(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Two backends on different HOSTS (maintenance is per host): 127.0.0.1 and ::1.
	backend1, account := common.SetupIMAPServerWithPROXY(t)
	defer backend1.Close()
	backend2 := common.SetupIMAPServerWithPROXYAndDatabaseAt(t, backend1.ResilientDB, common.GetRandomIPv6LoopbackAddress(t))
	defer backend2.Close()
	rdb := backend1.ResilientDB

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyAddr := common.GetRandomAddress(t)
	proxyServer, err := imapproxy.New(ctx, rdb, "test-maintenance-proxy", imapproxy.ServerOptions{
		Name:                   "test-maintenance-proxy",
		Addr:                   proxyAddr,
		RemoteAddrs:            []string{backend1.Address, backend2.Address},
		RemotePort:             143,
		MasterSASLUsername:     "proxyuser",
		MasterSASLPassword:     "proxypass",
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         2 * time.Second,
		AuthIdleTimeout:        30 * time.Second,
		AuthRateLimit:          server.DefaultAuthRateLimiterConfig(),
	})
	if err != nil {
		t.Fatalf("create proxy: %v", err)
	}

	// Wire maintenance as cmd/sora does: one set, the poller reading the database, the drain.
	m := proxy.NewMaintenance()
	proxyServer.GetConnectionManager().SetMaintenance(m)
	proxy.StartSessionDrainer(ctx, m, 50, proxyServer.MaintenanceTargets, "test")
	poller := proxy.NewMaintenancePoller(m, func(ctx context.Context) ([]string, error) {
		rows, err := rdb.ListBackendMaintenanceWithRetry(ctx)
		if err != nil {
			return nil, err
		}
		hosts := make([]string, len(rows))
		for i, r := range rows {
			hosts[i] = r.Host
		}
		return hosts, nil
	})

	go func() {
		if err := proxyServer.Start(); err != nil {
			t.Logf("proxy stopped: %v", err)
		}
	}()
	defer proxyServer.Stop()
	time.Sleep(100 * time.Millisecond)

	// 1. A session lands on the user's backend X.
	conn1, r1 := rawIMAPLogin(t, proxyAddr, account.Email, account.Password)
	hostX := waitForSessions(t, proxyServer, func(h []string) bool { return len(h) == 1 }, "first session")[0]
	t.Logf("user's backend host: %s", hostX)

	// 2. X goes into maintenance through the database, as `sora-admin backends maintenance on` does.
	for _, h := range []string{"127.0.0.1", "::1"} {
		_, _ = rdb.ClearBackendMaintenanceWithRetry(ctx, h) // leftovers of an aborted run
	}
	if _, err := rdb.SetBackendMaintenanceWithRetry(ctx, db.BackendMaintenance{Host: hostX, InstanceID: "test-instance", Reason: t.Name()}); err != nil {
		t.Fatalf("set maintenance: %v", err)
	}
	t.Cleanup(func() { _, _ = rdb.ClearBackendMaintenanceWithRetry(context.Background(), hostX) })
	if err := poller.Refresh(ctx); err != nil {
		t.Fatalf("poller refresh: %v", err)
	}

	// 3. The session on X is told to go and closed.
	_ = conn1.SetReadDeadline(time.Now().Add(10 * time.Second))
	sawBye := false
	for {
		line, err := r1.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "* BYE [UNAVAILABLE]") {
			sawBye = true
		}
	}
	if !sawBye {
		t.Fatal("session on the backend in maintenance was not sent BYE [UNAVAILABLE]")
	}
	waitForSessions(t, proxyServer, func(h []string) bool { return len(h) == 0 }, "drained session to end")

	// 4. The client reconnects and lands on the other backend.
	conn2, _ := rawIMAPLogin(t, proxyAddr, account.Email, account.Password)
	if hosts := waitForSessions(t, proxyServer, func(h []string) bool { return len(h) == 1 }, "rerouted session"); hosts[0] == hostX {
		t.Fatalf("login routed to %s, which is in maintenance", hostX)
	}
	fmt.Fprint(conn2, "a2 LOGOUT\r\n")
	conn2.Close()
	waitForSessions(t, proxyServer, func(h []string) bool { return len(h) == 0 }, "second session to end")

	// 5. Maintenance off: the user's consistent-hash backend is X again.
	if existed, err := rdb.ClearBackendMaintenanceWithRetry(ctx, hostX); err != nil || !existed {
		t.Fatalf("clear maintenance: existed=%v err=%v", existed, err)
	}
	if err := poller.Refresh(ctx); err != nil {
		t.Fatalf("poller refresh: %v", err)
	}
	rawIMAPLogin(t, proxyAddr, account.Email, account.Password)
	if hosts := waitForSessions(t, proxyServer, func(h []string) bool { return len(h) == 1 }, "session after maintenance"); hosts[0] != hostX {
		t.Fatalf("after maintenance ended, login routed to %s, want %s", hosts[0], hostX)
	}
}
