//go:build integration

package pop3

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"maps"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/storage"
)

// setupPOP3PerUserPerIPBehindProxy starts a POP3 backend that accepts PROXY
// headers from 127.0.0.1 and tracks connections in the returned tracker, with
// a per-user-per-IP limit of perIP. A refused registration is only logged on
// this backend (#345), so the tests read the tracker instead of the login
// response.
func setupPOP3PerUserPerIPBehindProxy(t *testing.T, perIP int) (string, common.TestAccount, *server.ConnectionTracker) {
	t.Helper()
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	srv, err := pop3.New(context.Background(), "test", "localhost", address, &storage.S3Storage{}, rdb, nil, nil,
		pop3.POP3ServerOptions{
			InsecureAuth:         true,
			ProxyProtocol:        true,
			ProxyProtocolTimeout: "5s",
			TrustedNetworks:      []string{"127.0.0.0/8", "::1/128"},
		})
	if err != nil {
		t.Fatalf("pop3.New: %v", err)
	}
	tracker := server.NewConnectionTracker("POP3", "test", "localhost", "test-instance", nil, 100, perIP, 0, false)
	srv.SetConnTracker(tracker)

	errChan := make(chan error, 1)
	go srv.Start(errChan)
	t.Cleanup(srv.Close)
	time.Sleep(100 * time.Millisecond)
	return address, account, tracker
}

type proxiedPOP3Conn struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

// dialProxiedPOP3 connects to addr as a trusted proxy (127.0.0.1) relaying
// the client at clientIP.
func dialProxiedPOP3(t *testing.T, addr, clientIP string) *proxiedPOP3Conn {
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
	fmt.Fprintf(conn, "PROXY %s %s %s 51000 110\r\n", family, clientIP, dst)
	c := &proxiedPOP3Conn{t: t, conn: conn, r: bufio.NewReader(conn)}
	if line := c.readLine(); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("greeting: %q", line)
	}
	return c
}

func (c *proxiedPOP3Conn) readLine() string {
	c.t.Helper()
	line, err := c.r.ReadString('\n')
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

func (c *proxiedPOP3Conn) do(cmd string) string {
	c.t.Helper()
	fmt.Fprintf(c.conn, "%s\r\n", cmd)
	return c.readLine()
}

// tryLogin sends USER and PASS and returns the PASS response.
func (c *proxiedPOP3Conn) tryLogin(account common.TestAccount) string {
	c.t.Helper()
	if resp := c.do("USER " + account.Email); !strings.HasPrefix(resp, "+OK") {
		c.t.Fatalf("USER: %q", resp)
	}
	return c.do("PASS " + account.Password)
}

func (c *proxiedPOP3Conn) login(account common.TestAccount) {
	c.t.Helper()
	if resp := c.tryLogin(account); !strings.HasPrefix(resp, "+OK") {
		c.t.Fatalf("PASS: %q", resp)
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
// close runs after the QUIT response.
func waitTrackedEmpty(t *testing.T, tracker *server.ConnectionTracker) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if len(trackedPerIP(tracker)) == 0 {
			return
		}
	}
	t.Fatalf("tracked connections after every session quit: %v, want none", trackedPerIP(tracker))
}

// Behind a proxy, max_connections_per_user_per_ip counted the proxy's address,
// the TCP peer, so every client of the user shared one count (#404).
func TestPOP3_PerUserPerIPLimitCountsProxiedClientAddress(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	addr, account, tracker := setupPOP3PerUserPerIPBehindProxy(t, 1)

	var sessions []*proxiedPOP3Conn
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		c := dialProxiedPOP3(t, addr, ip)
		c.login(account)
		sessions = append(sessions, c)
	}
	expectTrackedPerIP(t, tracker, map[string]int{"198.51.100.1": 1, "198.51.100.2": 1})

	// Each session is released under the address it was counted by.
	for _, s := range sessions {
		if resp := s.do("QUIT"); !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("QUIT: %q", resp)
		}
	}
	waitTrackedEmpty(t, tracker)

	// The limit still holds per client address: a second session from
	// 198.51.100.1 is not counted (whether its login is refused is #345).
	dialProxiedPOP3(t, addr, "198.51.100.1").login(account)
	over := dialProxiedPOP3(t, addr, "198.51.100.1")
	over.tryLogin(account)
	expectTrackedPerIP(t, tracker, map[string]int{"198.51.100.1": 1})

	// Closing the session that was not counted must not release the count
	// of the one that was.
	if resp := over.do("QUIT"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("QUIT: %q", resp)
	}
	if _, err := io.ReadAll(over.r); err != nil {
		t.Fatalf("waiting for the server to close the session: %v", err)
	}
	for end := time.Now().Add(500 * time.Millisecond); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		expectTrackedPerIP(t, tracker, map[string]int{"198.51.100.1": 1})
	}
}

// IPv6 client addresses are told apart, not cut at their last colon.
func TestPOP3_PerUserPerIPLimitSeparatesIPv6Clients(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	addr, account, tracker := setupPOP3PerUserPerIPBehindProxy(t, 1)

	for _, ip := range []string{"2001:db8::1", "2001:db8::2"} {
		dialProxiedPOP3(t, addr, ip).login(account)
	}
	expectTrackedPerIP(t, tracker, map[string]int{"2001:db8::1": 1, "2001:db8::2": 1})
}

// A trusted proxy that forwards the client address with XCLIENT before login
// (as pop3_proxy does) gets the same per-client count.
func TestPOP3_PerUserPerIPLimitCountsXCLIENTForwardedClientAddress(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	addr, account, tracker := setupPOP3PerUserPerIPBehindProxy(t, 1)

	var sessions []*proxiedPOP3Conn
	for _, ip := range []string{"198.51.100.7", "198.51.100.8"} {
		c := dialProxiedPOP3(t, addr, "127.0.0.1")
		if resp := c.do(fmt.Sprintf("XCLIENT ADDR=%s PORT=51000 TTL=5", ip)); !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("XCLIENT: %q", resp)
		}
		c.login(account)
		sessions = append(sessions, c)
	}
	expectTrackedPerIP(t, tracker, map[string]int{"198.51.100.7": 1, "198.51.100.8": 1})

	for _, s := range sessions {
		if resp := s.do("QUIT"); !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("QUIT: %q", resp)
		}
	}
	waitTrackedEmpty(t, tracker)
}

// Behind a layer-4 load balancer that sends PROXY headers, an XCLIENT is the
// client's own: it cannot replace the address the header gave, so a client
// cannot claim a fresh address for each connection and escape the per-IP
// count (#540). It is still answered +OK, as for a pop3_proxy that sends a
// PROXY header and XCLIENT together.
func TestPOP3_PerUserPerIPLimitIgnoresXCLIENTFromProxiedClient(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	addr, account, tracker := setupPOP3PerUserPerIPBehindProxy(t, 1)

	for i := 1; i <= 2; i++ {
		c := dialProxiedPOP3(t, addr, "198.51.100.66")
		if resp := c.do(fmt.Sprintf("XCLIENT ADDR=203.0.113.%d PORT=51000 TTL=5", i)); !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("XCLIENT from 198.51.100.66 behind the load balancer: %q", resp)
		}
		c.tryLogin(account)
	}
	expectTrackedPerIP(t, tracker, map[string]int{"198.51.100.66": 1})
}
