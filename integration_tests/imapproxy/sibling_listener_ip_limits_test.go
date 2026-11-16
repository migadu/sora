//go:build integration

package imapproxy_test

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

func TestIMAPProxySiblingListenersShareIPLimitAcrossNodes(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	backend, account := common.SetupIMAPServerWithMaster(t)
	defer backend.Close()
	newNode := func(name string, peers []string) *cluster.Manager {
		node, err := cluster.New(config.ClusterConfig{Enabled: true, Addr: "127.0.0.1:0", NodeID: name,
			Peers: peers, SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { node.Shutdown() })
		return node
	}
	nodeA := newNode("wire-ip-a", nil)
	var peer string
	for _, member := range nodeA.GetMembers() {
		peer = net.JoinHostPort(member.Addr, strconv.Itoa(int(member.Port)))
	}
	nodeB := newNode("wire-ip-b", []string{peer})
	type endpoint struct {
		addr   string
		server *imapproxy.Server
	}
	start := func(name string, node *cluster.Manager, tls bool) endpoint {
		addr := common.GetRandomAddress(t)
		proxy := setupIMAPProxyWithRateLimiting(t, backend.ResilientDB, addr, []string{backend.Address},
			server.AuthRateLimiterConfig{Enabled: false}, func(o *imapproxy.ServerOptions) {
				o.Name = name
				o.ClusterManager = node
				o.MaxConnectionsPerIP = 3
				o.ProxyProtocol = true
				o.ProxyProtocolTimeout = "5s"
				o.TrustedNetworks = []string{"127.0.0.0/8"}
				o.TrustedProxies = []string{"127.0.0.0/8"}
				if tls {
					cert, key, _ := common.GenerateTestTLSCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
					o.TLS = true
					o.TLSCertFile = cert
					o.TLSKeyFile = key
				}
			})
		return endpoint{addr, proxy.Server.(*imapproxy.Server)}
	}
	a1, a2 := start("wire-ip-a1", nodeA, false), start("wire-ip-a2", nodeA, false)
	b1, b2 := start("wire-ip-b1", nodeB, false), start("wire-ip-b2", nodeB, false)
	endpoints := []endpoint{a1, a2, b1, b2}
	const ip = "192.0.2.1"
	waitCounts := func(want int64) {
		t.Helper()
		for deadline := time.Now().Add(8 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			good := true
			counts := make([]int64, len(endpoints))
			for i, p := range endpoints {
				counts[i] = p.server.GetLimiter().GetStats().IPConnections[ip]
				good = good && counts[i] == want
			}
			if good {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("per-IP counts=%v, want all %d", counts, want)
			}
		}
	}
	dial := func(p endpoint, clientIP string) net.Conn {
		t.Helper()
		c, err := net.DialTimeout("tcp", p.addr, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(10 * time.Second))
		family, destination := "TCP4", "127.0.0.1"
		if strings.Contains(clientIP, ":") {
			family, destination = "TCP6", "::1"
		}
		if _, err := fmt.Fprintf(c, "PROXY %s %s %s 50000 143\r\n", family, clientIP, destination); err != nil {
			t.Fatal(err)
		}
		return c
	}
	accept := func(p endpoint, clientIP string, login bool) net.Conn {
		t.Helper()
		c := dial(p, clientIP)
		r := bufio.NewReader(c)
		line, err := r.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "* OK ") {
			t.Fatalf("greeting=%q, %v", line, err)
		}
		if login {
			fmt.Fprintf(c, "a LOGIN %q %q\r\n", account.Email, account.Password)
			for {
				line, err = r.ReadString('\n')
				if err != nil {
					t.Fatal(err)
				}
				if strings.HasPrefix(line, "a ") {
					if !strings.HasPrefix(line, "a OK ") {
						t.Fatalf("login=%q", line)
					}
					break
				}
			}
		}
		return c
	}
	refuse := func(p endpoint) {
		t.Helper()
		c := dial(p, "::ffff:192.0.2.1")
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		var b [1]byte
		n, err := c.Read(b[:])
		if n != 0 || err == nil {
			t.Fatalf("refused greeting=%q err=%v", b[:n], err)
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("refusal did not close the socket")
		}
		c.Close()
	}
	// Registered and pre-authenticated sessions on sibling listeners share the same IP cap.
	first := accept(a1, ip, true)
	second := accept(a2, ip, false)
	waitCounts(2)
	third := accept(b1, ip, false)
	waitCounts(3)
	refuse(a1)
	refuse(a2)
	refuse(b1)
	refuse(b2)
	other := accept(b2, "192.0.2.2", false)
	other.Close()
	waitCounts(3) // Different IP and rejected sockets must not add a charge.
	second.Close()
	waitCounts(2)
	replacement := accept(b2, "::ffff:192.0.2.1", false)
	waitCounts(3)
	first.Close()
	waitCounts(2)
	// Drain closes a pre-authentication session and frees its slot on both nodes.
	if err := b1.server.Stop(); err != nil {
		t.Fatal(err)
	}
	waitCounts(1)
	third.Close() // Already closed by Stop: must not release any other connection.
	replacement.Close()
	waitCounts(0)
	// Failed TLS initialization also releases its pre-admission slot on siblings.
	tlsListener := start("wire-ip-a-tls", nodeA, true)
	stalled := dial(tlsListener, ip)
	waitCounts(1)
	if _, err := stalled.Write([]byte("XXXXX")); err != nil {
		t.Fatal(err)
	}
	stalled.Close()
	waitCounts(0)
	accept(a2, ip, false).Close()
	waitCounts(0)
}
