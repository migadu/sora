//go:build integration

package managesieve

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"maps"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieve"
)

// setupManageSievePerUserPerIPBehindProxy starts a ManageSieve backend that
// accepts PROXY headers from 127.0.0.1 and tracks connections in the returned
// tracker, with a per-user-per-IP limit of perIP.
func setupManageSievePerUserPerIPBehindProxy(t *testing.T, perIP int) (string, common.TestAccount, *server.ConnectionTracker) {
	t.Helper()
	_, address, account, tracker := setupManageSieveConnLimitsBehindProxy(t, 100, perIP)
	return address, account, tracker
}

// setupManageSieveConnLimitsBehindProxy starts a ManageSieve backend that
// accepts PROXY headers from 127.0.0.1 and tracks connections in the returned
// tracker, with max_connections_per_user perUser and
// max_connections_per_user_per_ip perIP (0: no limit).
func setupManageSieveConnLimitsBehindProxy(t *testing.T, perUser, perIP int) (*managesieve.ManageSieveServer, string, common.TestAccount, *server.ConnectionTracker) {
	t.Helper()
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	srv, err := managesieve.New(context.Background(), "test", "localhost", address, rdb,
		managesieve.ManageSieveServerOptions{
			InsecureAuth:                true,
			ProxyProtocol:               true,
			ProxyProtocolTimeout:        "5s",
			ProxyProtocolTrustedProxies: []string{"127.0.0.0/8", "::1/128"},
			TrustedNetworks:             []string{"127.0.0.0/8", "::1/128"},
			SupportedExtensions:         []string{"fileinto"},
		})
	if err != nil {
		t.Fatalf("managesieve.New: %v", err)
	}
	tracker := server.NewConnectionTracker("ManageSieve", "test", "localhost", "test-instance", nil, perUser, perIP, 0, false)
	srv.SetConnTracker(tracker)

	errChan := make(chan error, 1)
	go srv.Start(errChan)
	t.Cleanup(srv.Close)
	time.Sleep(100 * time.Millisecond)
	return srv, address, account, tracker
}

type proxiedSieveConn struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

// dialProxiedManageSieve connects to addr as a trusted proxy (127.0.0.1)
// relaying the client at clientIP.
func dialProxiedManageSieve(t *testing.T, addr, clientIP string) *proxiedSieveConn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	family, dst := "TCP4", "127.0.0.1"
	if strings.Contains(clientIP, ":") {
		family, dst = "TCP6", "::1"
	}
	fmt.Fprintf(conn, "PROXY %s %s %s 51000 4190\r\n", family, clientIP, dst)
	c := &proxiedSieveConn{t: t, conn: conn, r: bufio.NewReader(conn)}
	if resp := c.readResp(); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("greeting: %q", resp)
	}
	return c
}

// readResp reads up to and including the OK/NO/BYE line and returns that line.
func (c *proxiedSieveConn) readResp() string {
	c.t.Helper()
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			c.t.Fatalf("read: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if up := strings.ToUpper(line); strings.HasPrefix(up, "OK") || strings.HasPrefix(up, "NO") || strings.HasPrefix(up, "BYE") {
			return line
		}
	}
}

func (c *proxiedSieveConn) do(cmd string) string {
	c.t.Helper()
	fmt.Fprintf(c.conn, "%s\r\n", cmd)
	return c.readResp()
}

// tryLogin sends AUTHENTICATE PLAIN and returns the response.
func (c *proxiedSieveConn) tryLogin(account common.TestAccount) string {
	c.t.Helper()
	creds := base64.StdEncoding.EncodeToString([]byte("\x00" + account.Email + "\x00" + account.Password))
	return c.do(fmt.Sprintf(`AUTHENTICATE "PLAIN" "%s"`, creds))
}

func (c *proxiedSieveConn) login(account common.TestAccount) {
	c.t.Helper()
	if resp := c.tryLogin(account); !strings.HasPrefix(resp, "OK") {
		c.t.Fatalf("AUTHENTICATE: %q", resp)
	}
}

// trackedPerIP returns the tracker's connection counts by client IP.
func trackedPerIP(tracker *server.ConnectionTracker) map[string]int {
	counts := map[string]int{}
	for _, info := range tracker.GetAllConnections() {
		for _, perIP := range info.PerIPCountByInstance {
			for ip, n := range perIP {
				if n != 0 {
					counts[ip] += n
				}
			}
		}
	}
	return counts
}

func expectTrackedPerIP(t *testing.T, tracker *server.ConnectionTracker, want map[string]int) {
	t.Helper()
	if got := trackedPerIP(tracker); !maps.Equal(got, want) {
		t.Fatalf("tracked connections by client IP = %v, want %v", got, want)
	}
}

// waitTrackedEmpty waits for every session to be unregistered; the session's
// close runs after the LOGOUT response.
func waitTrackedEmpty(t *testing.T, tracker *server.ConnectionTracker) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if len(trackedPerIP(tracker)) == 0 {
			return
		}
	}
	t.Fatalf("tracked connections after every session logged out: %v, want none", trackedPerIP(tracker))
}

// Behind a proxy, max_connections_per_user_per_ip counted the proxy's address,
// the TCP peer, so every client of the user shared one count (#404).
func TestManageSieve_PerUserPerIPLimitCountsProxiedClientAddress(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	addr, account, tracker := setupManageSievePerUserPerIPBehindProxy(t, 1)

	var sessions []*proxiedSieveConn
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		c := dialProxiedManageSieve(t, addr, ip)
		c.login(account)
		sessions = append(sessions, c)
	}
	expectTrackedPerIP(t, tracker, map[string]int{"198.51.100.1": 1, "198.51.100.2": 1})

	// Each session is released under the address it was counted by.
	for _, s := range sessions {
		if resp := s.do("LOGOUT"); !strings.HasPrefix(resp, "OK") {
			t.Fatalf("LOGOUT: %q", resp)
		}
	}
	waitTrackedEmpty(t, tracker)

	// The limit still holds per client address: a second session from
	// 198.51.100.1 is refused and not counted.
	dialProxiedManageSieve(t, addr, "198.51.100.1").login(account)
	over := dialProxiedManageSieve(t, addr, "198.51.100.1")
	if resp := over.tryLogin(account); !strings.HasPrefix(resp, "NO (TRYLATER)") {
		t.Fatalf("login over max_connections_per_user_per_ip = %q, want NO (TRYLATER)", resp)
	}
	expectTrackedPerIP(t, tracker, map[string]int{"198.51.100.1": 1})

	// Closing the session that was not counted must not release the count
	// of the one that was.
	if resp := over.do("LOGOUT"); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("LOGOUT: %q", resp)
	}
	if _, err := io.ReadAll(over.r); err != nil {
		t.Fatalf("waiting for the server to close the session: %v", err)
	}
	for end := time.Now().Add(500 * time.Millisecond); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		expectTrackedPerIP(t, tracker, map[string]int{"198.51.100.1": 1})
	}
}

// IPv6 client addresses are told apart, not cut at their last colon.
func TestManageSieve_PerUserPerIPLimitSeparatesIPv6Clients(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	addr, account, tracker := setupManageSievePerUserPerIPBehindProxy(t, 1)

	for _, ip := range []string{"2001:db8::1", "2001:db8::2"} {
		dialProxiedManageSieve(t, addr, ip).login(account)
	}
	expectTrackedPerIP(t, tracker, map[string]int{"2001:db8::1": 1, "2001:db8::2": 1})
}
