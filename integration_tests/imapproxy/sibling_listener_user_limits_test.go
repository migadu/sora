//go:build integration

package imapproxy_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

// Real logins must share their user slots across listeners, including forwarded
// canonical IPs, and a closed session must free capacity on its sibling.
func TestIMAPProxySiblingListenersShareUserLimits(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	backend, account := common.SetupIMAPServerWithPROXY(t)
	defer backend.Close()
	accountID, err := backend.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatal(err)
	}
	other := common.CreateTestAccountWithEmail(t, backend.ResilientDB,
		fmt.Sprintf("sibling-other-%d@example.com", time.Now().UnixNano()), "other-pw")

	for _, tc := range []struct {
		name           string
		maxUser, maxIP int
		first, refused string
	}{
		{"per user", 1, 0, "2001:db8::1", "2001:db8::2"},
		{"canonical IPv6", 0, 1, "2001:db8::1", "2001:0DB8:0:0:0:0:0:1"},
		{"mapped IPv4", 0, 1, "::ffff:192.0.2.1", "192.0.2.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node, err := cluster.New(config.ClusterConfig{Enabled: true, Addr: "127.0.0.1:0",
				NodeID:    fmt.Sprintf("sibling-%d", time.Now().UnixNano()),
				SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { node.Shutdown() })
			start := func(name string) (string, *server.ConnectionTracker) {
				addr := common.GetRandomAddress(t)
				proxy := setupIMAPProxyWithRateLimiting(t, backend.ResilientDB, addr,
					[]string{backend.Address}, server.AuthRateLimiterConfig{Enabled: false},
					func(o *imapproxy.ServerOptions) {
						o.Name = name
						o.RemoteUseProxyProtocol = true
						o.ProxyProtocol = true
						o.ProxyProtocolTimeout = "5s"
						o.TrustedNetworks = []string{"127.0.0.0/8"}
						o.TrustedProxies = []string{"127.0.0.0/8"}
					})
				tracker := server.NewConnectionTracker("IMAP", name, "mail", name, node,
					tc.maxUser, tc.maxIP, 0, false)
				proxy.Server.(*imapproxy.Server).SetConnectionTracker(tracker)
				return addr, tracker
			}
			a, trackerA := start("sibling-a")
			b, _ := start("sibling-b")
			login := func(addr, ip string, user common.TestAccount) (*imapclient.Client, error) {
				t.Helper()
				conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				conn.SetDeadline(time.Now().Add(15 * time.Second))
				family, dst := "TCP6", "::1"
				if net.ParseIP(ip).To4() != nil && ip[0] != ':' {
					family, dst = "TCP4", "127.0.0.1"
				}
				if _, err := fmt.Fprintf(conn, "PROXY %s %s %s 51000 143\r\n", family, ip, dst); err != nil {
					conn.Close()
					t.Fatal(err)
				}
				client := imapclient.New(conn, nil)
				t.Cleanup(func() { client.Close() })
				return client, client.Login(user.Email, user.Password).Wait()
			}
			first, err := login(a, tc.first, account)
			if err != nil {
				t.Fatalf("first listener login: %v", err)
			}
			_, err = login(b, tc.refused, account)
			var imapErr *imap.Error
			if !errors.As(err, &imapErr) || imapErr.Code != imap.ResponseCodeLimit {
				t.Fatalf("sibling listener login = %v, want NO [LIMIT]", err)
			}
			if _, err := login(b, tc.refused, other); err != nil {
				t.Fatalf("another account must have its own limit: %v", err)
			}
			if err := first.Logout().Wait(); err != nil {
				t.Fatal(err)
			}
			for deadline := time.Now().Add(5 * time.Second); trackerA.GetConnectionCount(accountID) != 0; {
				if time.Now().After(deadline) {
					t.Fatal("first listener retained the logged-out session")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if _, err := login(b, tc.refused, account); err != nil {
				t.Fatalf("sibling capacity was not released after logout: %v", err)
			}
		})
	}
}
