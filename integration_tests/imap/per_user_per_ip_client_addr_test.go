//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	imapserver "github.com/migadu/sora/server/imap"
)

// proxiedIMAPConn is a raw connection to a backend that arrived through a
// trusted proxy (127.0.0.1) for the client at clientIP.
type proxiedIMAPConn struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
	n    int
}

func dialProxiedIMAP(t *testing.T, addr, clientIP string) *proxiedIMAPConn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	family := "TCP4"
	if strings.Contains(clientIP, ":") {
		family = "TCP6"
	}
	dst := "127.0.0.1"
	if family == "TCP6" {
		dst = "::1"
	}
	fmt.Fprintf(conn, "PROXY %s %s %s 51000 143\r\n", family, clientIP, dst)
	c := &proxiedIMAPConn{t: t, conn: conn, r: bufio.NewReader(conn)}
	if _, err := c.r.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	return c
}

// do sends cmd and returns the tagged response line.
func (c *proxiedIMAPConn) do(cmd string) string {
	c.t.Helper()
	c.n++
	tag := fmt.Sprintf("p%d", c.n)
	fmt.Fprintf(c.conn, "%s %s\r\n", tag, cmd)
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			c.t.Fatalf("read (waiting for %s): %v", tag, err)
		}
		if strings.HasPrefix(line, tag+" ") {
			return strings.TrimRight(line, "\r\n")
		}
	}
}

func (c *proxiedIMAPConn) login(account common.TestAccount) string {
	c.t.Helper()
	return c.do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
}

func setupPerUserPerIPBehindProxy(t *testing.T, perIP int) (*common.TestServer, common.TestAccount) {
	t.Helper()
	server, account := common.SetupIMAPServerWithPROXYOptions(t, func(o *imapserver.IMAPServerOptions) {
		o.MaxConnectionsPerUser = 100
		o.MaxConnectionsPerUserPerIP = perIP
	})
	t.Cleanup(server.Close)
	return server, account
}

// Behind a proxy, max_connections_per_user_per_ip counted the proxy's address,
// the TCP peer, so every client of the user shared one count (#332).
func TestIMAP_PerUserPerIPLimitCountsProxiedClientAddress(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := setupPerUserPerIPBehindProxy(t, 2)

	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "203.0.113.5"} {
		if resp := dialProxiedIMAP(t, server.Address, ip).login(account); !strings.Contains(resp, " OK ") {
			t.Fatalf("LOGIN from %s (first from that address): %s", ip, resp)
		}
	}
	// The limit still holds per client address.
	if resp := dialProxiedIMAP(t, server.Address, "198.51.100.1").login(account); !strings.Contains(resp, " OK ") {
		t.Fatalf("second LOGIN from 198.51.100.1: %s", resp)
	}
	if resp := dialProxiedIMAP(t, server.Address, "198.51.100.1").login(account); !strings.Contains(resp, " NO [LIMIT]") {
		t.Fatalf("third LOGIN from 198.51.100.1 with a limit of 2: %s, want NO [LIMIT]", resp)
	}
}

// IPv6 client addresses are told apart, not cut at their last colon.
func TestIMAP_PerUserPerIPLimitSeparatesIPv6Clients(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := setupPerUserPerIPBehindProxy(t, 1)

	for _, ip := range []string{"2001:db8::1", "2001:db8::2"} {
		if resp := dialProxiedIMAP(t, server.Address, ip).login(account); !strings.Contains(resp, " OK ") {
			t.Fatalf("LOGIN from %s (first from that address): %s", ip, resp)
		}
	}
	if resp := dialProxiedIMAP(t, server.Address, "2001:db8::1").login(account); !strings.Contains(resp, " NO [LIMIT]") {
		t.Fatalf("second LOGIN from 2001:db8::1 with a limit of 1: %s, want NO [LIMIT]", resp)
	}
}

// A trusted proxy that forwards the client address with ID (x-originating-ip)
// before LOGIN gets the same per-client count.
func TestIMAP_PerUserPerIPLimitCountsIDForwardedClientAddress(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := setupPerUserPerIPBehindProxy(t, 1)

	for _, ip := range []string{"198.51.100.7", "198.51.100.8"} {
		c := dialProxiedIMAP(t, server.Address, "127.0.0.1")
		if resp := c.do(fmt.Sprintf(`ID ("x-originating-ip" "%s" "x-proxy-ttl" "5")`, ip)); !strings.Contains(resp, " OK ") {
			t.Fatalf("ID: %s", resp)
		}
		if resp := c.login(account); !strings.Contains(resp, " OK ") {
			t.Fatalf("LOGIN forwarded for %s (first from that address): %s", ip, resp)
		}
	}
}

// Behind a layer-4 load balancer that sends PROXY headers, an ID is the client's own:
// it cannot replace the address the header gave, so a client cannot claim a fresh
// address for each connection and escape the per-IP count (#540).
func TestIMAP_PerUserPerIPLimitIgnoresIDFromProxiedClient(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := setupPerUserPerIPBehindProxy(t, 1)

	for i, want := range []string{" OK ", " NO [LIMIT]", " NO [LIMIT]"} {
		claimed := fmt.Sprintf("203.0.113.%d", i+1)
		c := dialProxiedIMAP(t, server.Address, "198.51.100.66")
		if resp := c.do(fmt.Sprintf(`ID ("x-originating-ip" "%s" "x-proxy-ttl" "5")`, claimed)); !strings.Contains(resp, " OK ") {
			t.Fatalf("ID: %s", resp)
		}
		if resp := c.login(account); !strings.Contains(resp, want) {
			t.Fatalf("LOGIN %d from 198.51.100.66 claiming %s: %s, want %s", i+1, claimed, resp, want)
		}
	}
}

// The connection is unregistered under the address it was registered with,
// even when an ID after LOGIN changed the session's client address; otherwise
// the first address keeps a connection that is gone.
func TestIMAP_PerUserPerIPLimitReleasedUnderRegisteredAddress(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := setupPerUserPerIPBehindProxy(t, 1)

	c := dialProxiedIMAP(t, server.Address, "198.51.100.20")
	if resp := c.login(account); !strings.Contains(resp, " OK ") {
		t.Fatalf("LOGIN: %s", resp)
	}
	if resp := c.do(`ID ("x-originating-ip" "203.0.113.20" "x-proxy-ttl" "5")`); !strings.Contains(resp, " OK ") {
		t.Fatalf("ID after LOGIN: %s", resp)
	}
	c.do("LOGOUT")
	c.conn.Close()

	// The session's close runs after the tagged LOGOUT response.
	var resp string
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if resp = dialProxiedIMAP(t, server.Address, "198.51.100.20").login(account); strings.Contains(resp, " OK ") {
			return
		}
	}
	t.Fatalf("LOGIN from 198.51.100.20 after its only session logged out: %s, want OK", resp)
}
