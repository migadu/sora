//go:build integration

package imapproxy_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
	"github.com/migadu/sora/server/proxy"
)

// failoverFixture is one IMAP proxy in front of pool sora1 (backends A and B) and pool
// sora0 (backend C), with the production wiring for stickiness: a cluster-backed affinity
// manager and backend health checks. Every backend advertises its own capability tag,
// which the proxy relays after login, so a client can tell which machine served it.
type failoverFixture struct {
	t         *testing.T
	proxyAddr string
	a, b, c   string
	tag, name map[string]string
	alive     map[string]*common.TestServer
	rdb       *resilient.ResilientDatabase
	start     func(addr string)
}

// sora1Group: users of sora1 that all landed on the same backend (primary) at their first
// login, plus the other member of the pool (secondary).
type sora1Group struct {
	users              []common.TestAccount
	primary, secondary string
}

func newFailoverFixture(t *testing.T) (*failoverFixture, *poolLookup) {
	t.Helper()
	rdb := common.SetupTestDatabase(t)
	f := &failoverFixture{
		t:   t,
		rdb: rdb,
		a:   common.GetRandomAddress(t), b: common.GetRandomAddress(t), c: common.GetRandomAddress(t),
		alive: map[string]*common.TestServer{},
	}
	f.tag = map[string]string{f.a: "X-POOLTEST-A", f.b: "X-POOLTEST-B", f.c: "X-POOLTEST-C"}
	f.name = map[string]string{f.a: "A", f.b: "B", f.c: "C"}
	f.start = func(addr string) {
		f.alive[addr] = common.SetupIMAPServerWithPROXYAt(t, rdb, addr, []string{f.tag[addr]})
		waitAccepting(t, addr)
	}
	t.Cleanup(func() {
		for addr := range f.alive {
			f.stop(addr)
		}
	})
	for _, addr := range []string{f.a, f.b, f.c} {
		f.start(addr)
	}

	lookup, lookupURL := newPoolLookup(t)
	clusterMgr, err := cluster.New(config.ClusterConfig{
		Enabled:   true,
		Addr:      fmt.Sprintf("127.0.0.1:%d", getRandomPort(t)),
		NodeID:    "failover-test-node",
		SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
	})
	if err != nil {
		t.Fatalf("cluster.New: %v", err)
	}
	t.Cleanup(func() { clusterMgr.Shutdown() })
	affinityMgr := server.NewAffinityManager(clusterMgr, true, time.Hour, 10*time.Minute)

	pool := func(name string, addrs ...string) proxy.PoolSpec {
		return proxy.PoolSpec{Name: name, Backends: addrs, Settings: proxy.BackendSettings{UseProxyProtocol: true}}
	}
	f.proxyAddr = common.GetRandomAddress(t)
	proxyServer, err := imapproxy.New(context.Background(), rdb, "test-proxy-failover", imapproxy.ServerOptions{
		Name:                     "test-proxy-failover",
		Addr:                     f.proxyAddr,
		Pools:                    []proxy.PoolSpec{pool("sora1", f.a, f.b), pool("sora0", f.c)},
		RemotePort:               143,
		MasterSASLUsername:       "proxyuser",
		MasterSASLPassword:       "proxypass",
		ConnectTimeout:           5 * time.Second,
		AuthIdleTimeout:          30 * time.Second,
		EnableAffinity:           true,
		EnableBackendHealthCheck: true, // remote_health_checks defaults to true in config
		AuthRateLimit:            server.AuthRateLimiterConfig{Enabled: false},
		TrustedProxies:           []string{"127.0.0.0/8", "::1/128"},
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:                true,
			URL:                    lookupURL,
			Timeout:                "5s",
			RemoteUseProxyProtocol: true,
		},
	})
	if err != nil {
		t.Fatalf("imapproxy.New: %v", err)
	}
	proxyServer.GetConnectionManager().SetAffinityManager(affinityMgr)
	go func() {
		if err := proxyServer.Start(); err != nil {
			t.Logf("proxy: %v", err)
		}
	}()
	t.Cleanup(func() { proxyServer.Stop() })
	waitAccepting(t, f.proxyAddr)

	return f, lookup
}

func (f *failoverFixture) stop(addr string) {
	f.alive[addr].Close()
	delete(f.alive, addr)
}

// account creates a user whose lookup answer names pool.
func (f *failoverFixture) account(lookup *poolLookup, label, pool string) common.TestAccount {
	f.t.Helper()
	acct := common.CreateTestAccountWithEmail(f.t, f.rdb, fmt.Sprintf("%s-%d@example.com", label, time.Now().UnixNano()), "pw-"+label)
	lookup.set(acct.Email, answer(f.t, acct, pool))
	return acct
}

// servedBy logs in through the proxy and returns which backend served the session.
func (f *failoverFixture) servedBy(account common.TestAccount) (string, error) {
	f.t.Helper()
	c, err := imapclient.DialInsecure(f.proxyAddr, nil)
	if err != nil {
		f.t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		return "", err
	}
	caps, err := c.Capability().Wait()
	if err != nil {
		f.t.Fatalf("CAPABILITY after login: %v", err)
	}
	_ = c.Logout().Wait()
	var found []string
	for addr, tag := range f.tag {
		if caps.Has(imap.Cap(tag)) {
			found = append(found, addr)
		}
	}
	if len(found) != 1 {
		f.t.Fatalf("cannot tell which backend served the login: %d backend tags in %v", len(found), caps)
	}
	return found[0], nil
}

func (f *failoverFixture) mustServe(step string, account common.TestAccount, want string) {
	f.t.Helper()
	got, err := f.servedBy(account)
	if err != nil {
		f.t.Fatalf("%s: login failed: %v", step, err)
	}
	if got != want {
		f.t.Fatalf("%s: served by %s, want %s", step, f.name[got], f.name[want])
	}
}

// pickGroup logs in 2*need-1 sora1 users once each. With two members in the pool, at least
// need of them share a backend (pigeonhole): that backend is the primary.
func (f *failoverFixture) pickGroup(lookup *poolLookup, need int) sora1Group {
	f.t.Helper()
	byBackend := map[string][]common.TestAccount{}
	for i := 0; i < 2*need-1; i++ {
		acct := f.account(lookup, fmt.Sprintf("sora1-user%d", i), "sora1")
		got, err := f.servedBy(acct)
		if err != nil {
			f.t.Fatalf("first login of a sora1 user: %v", err)
		}
		if got != f.a && got != f.b {
			f.t.Fatalf("a sora1 user was served by %s, which is not in sora1", f.name[got])
		}
		byBackend[got] = append(byBackend[got], acct)
	}
	for backend, users := range byBackend {
		if len(users) >= need {
			g := sora1Group{users: users[:need], primary: backend, secondary: f.b}
			if backend == f.b {
				g.secondary = f.a
			}
			f.t.Logf("primary %s (%d users), secondary %s", f.name[g.primary], need, f.name[g.secondary])
			return g
		}
	}
	panic("unreachable: pigeonhole")
}

// TestIMAPProxyStickyFailoverWithinPool: what an operator expects from affinity inside a
// named pool after a brief outage of one member.
//  1. A user keeps landing on the same member of the pool across logins.
//  2. When that member dies, the user lands on the other member of the pool, never on
//     another pool's backend.
//  3. Once the member is back and in rotation again (a user of the same pool who did not
//     log in during the outage lands on it), the failed-over user stays where failover put
//     them: recovery does not bounce users back.
//  4. With every member of the pool down, the pool's users are refused with
//     NO [UNAVAILABLE], while the other pool's backend is alive and serves its own users.
func TestIMAPProxyStickyFailoverWithinPool(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	f, lookup := newFailoverFixture(t)
	g := f.pickGroup(lookup, 2)
	failover, control := g.users[0], g.users[1] // control never logs in during the outage
	sora0User := f.account(lookup, "sora0-user", "sora0")

	// 1.
	f.mustServe("second login, all healthy", failover, g.primary)

	// 2. One login during the outage.
	f.stop(g.primary)
	f.mustServe("login with its backend down", failover, g.secondary)

	// 3.
	f.start(g.primary)
	f.mustServe("control user after the backend came back (backend in rotation)", control, g.primary)
	for i := 1; i <= 3; i++ {
		f.mustServe(fmt.Sprintf("failed-over user, login %d after recovery", i), failover, g.secondary)
	}

	// 4.
	f.stop(f.a)
	f.stop(f.b)
	for _, u := range []common.TestAccount{failover, control} {
		_, err := f.servedBy(u)
		expectUnavailable(t, "sora1 user with every member of sora1 down", err)
	}
	f.mustServe("sora0 user while sora1 is down", sora0User, f.c)
}

// TestIMAPProxyStickyFailoverSurvivesQuarantine: the same promise after a long outage, the
// common production case. Many of the member's users log in while it is down, so the proxy
// takes it out of rotation; about a minute after the last failure it is put back for new
// routing. From then on a user without a failover history lands on it again, but the users
// who failed over stay on the member that served them during the outage.
//
// Waits out the proxy's one-minute quarantine, so it takes a little over a minute.
func TestIMAPProxyStickyFailoverSurvivesQuarantine(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	f, lookup := newFailoverFixture(t)
	g := f.pickGroup(lookup, 4)
	failovers, control := g.users[:3], g.users[3]

	// Three of the member's users log in during the outage: each fails over.
	f.stop(g.primary)
	for i, u := range failovers {
		f.mustServe(fmt.Sprintf("user %d with its backend down", i+1), u, g.secondary)
	}
	f.start(g.primary)

	// Premise: the proxy has taken the member out of rotation. A user of it who did not log
	// in during the outage is kept off it although it is up again.
	f.mustServe("control user right after the backend came back (quarantined)", control, g.secondary)

	time.Sleep(65 * time.Second)

	// The member is back in rotation: some fresh user of the pool lands on it again.
	var fresh string
	for i := 0; fresh == ""; i++ {
		if i == 20 {
			t.Fatalf("no fresh sora1 user landed on %s after the quarantine: the backend did not come back into rotation", f.name[g.primary])
		}
		acct := f.account(lookup, fmt.Sprintf("sora1-fresh%d", i), "sora1")
		got, err := f.servedBy(acct)
		if err != nil {
			t.Fatalf("fresh sora1 user: %v", err)
		}
		if got == g.primary {
			fresh = acct.Email
		}
	}
	t.Logf("fresh user %s landed on the recovered %s", fresh, f.name[g.primary])

	// ...while every user who failed over, the control included, stays put.
	for i, u := range append(failovers, control) {
		f.mustServe(fmt.Sprintf("failed-over user %d after the quarantine", i+1), u, g.secondary)
	}
}

// waitAccepting waits until addr accepts TCP connections.
func waitAccepting(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s does not accept connections: %v", addr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
