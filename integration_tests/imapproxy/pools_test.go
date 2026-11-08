//go:build integration

package imapproxy_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
	"github.com/migadu/sora/server/proxy"
	"golang.org/x/crypto/bcrypt"
)

// poolLookup is a remote-lookup API whose answer per user the test can change.
type poolLookup struct {
	mu      sync.Mutex
	answers map[string]map[string]any
	calls   atomic.Int64 // lookups served (every status)
}

func (l *poolLookup) set(email string, answer map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.answers[email] = answer
}

func newPoolLookup(t *testing.T) (*poolLookup, string) {
	t.Helper()
	l := &poolLookup{answers: map[string]map[string]any{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.calls.Add(1)
		l.mu.Lock()
		answer, ok := l.answers[r.URL.Query().Get("email")]
		l.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(answer)
	}))
	t.Cleanup(srv.Close)
	return l, srv.URL + "/lookup?email=$email"
}

func hashOf(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func imapLogin(t *testing.T, proxyAddr string, account common.TestAccount) error {
	t.Helper()
	c, err := imapclient.DialInsecure(proxyAddr, nil)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		return err
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		return fmt.Errorf("SELECT after login: %w", err)
	}
	return c.Logout().Wait()
}

// lastSuccess returns when the proxy last connected to backend, from its health view.
func lastSuccess(t *testing.T, cm *proxy.ConnectionManager, backend string) (time.Time, string) {
	t.Helper()
	for _, st := range cm.GetBackendHealthStatuses() {
		if st.Address == backend {
			return st.LastSuccess, st.Pool
		}
	}
	t.Fatalf("backend %s not in the proxy's health view", backend)
	return time.Time{}, ""
}

// TestIMAPProxyPools drives the whole pool path through a real proxy: a lookup answer
// naming a pool lands the login on that pool's backend; when the answer changes to the
// other pool, the next uncached login lands there although the cluster affinity still
// pointed at the old backend; an unknown pool, or no pool where none is the default, is
// a temporary failure rather than a wrong password; an explicit server keeps pinning.
func TestIMAPProxyPools(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backendA, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendA.Close()
	backendB, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendB.Close()
	rdb := backendA.ResilientDB

	stamp := time.Now().UnixNano()
	mover := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("pool-mover-%d@example.com", stamp), "pw-mover")
	unknown := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("pool-unknown-%d@example.com", stamp), "pw-unknown")
	nopool := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("pool-none-%d@example.com", stamp), "pw-none")
	pinned := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("pool-pinned-%d@example.com", stamp), "pw-pinned")

	lookup, lookupURL := newPoolLookup(t)
	lookup.set(mover.Email, map[string]any{"address": mover.Email, "password_hash": hashOf(t, mover.Password), "pool": "sora-a"})
	lookup.set(unknown.Email, map[string]any{"address": unknown.Email, "password_hash": hashOf(t, unknown.Password), "pool": "sora-missing"})
	lookup.set(nopool.Email, map[string]any{"address": nopool.Email, "password_hash": hashOf(t, nopool.Password)})
	lookup.set(pinned.Email, map[string]any{"address": pinned.Email, "password_hash": hashOf(t, pinned.Password), "server": backendB.Address, "pool": "sora-missing"})

	// A real, cluster-backed affinity manager: the production path for sticky routing.
	clusterMgr, err := cluster.New(config.ClusterConfig{
		Enabled:   true,
		Addr:      fmt.Sprintf("127.0.0.1:%d", getRandomPort(t)),
		NodeID:    "pools-test-node",
		SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
	})
	if err != nil {
		t.Fatalf("cluster.New: %v", err)
	}
	defer clusterMgr.Shutdown()
	affinityMgr := server.NewAffinityManager(clusterMgr, true, time.Hour, 10*time.Minute)

	proxyAddr := common.GetRandomAddress(t)
	proxyServer, err := imapproxy.New(context.Background(), rdb, "test-proxy-pools", imapproxy.ServerOptions{
		Name: "test-proxy-pools",
		Addr: proxyAddr,
		Pools: []proxy.PoolSpec{
			{Name: "sora-a", Backends: []string{backendA.Address}, Settings: proxy.BackendSettings{UseProxyProtocol: true}},
			{Name: "sora-b", Backends: []string{backendB.Address}, Settings: proxy.BackendSettings{UseProxyProtocol: true}},
		},
		RemotePort:         143,
		MasterSASLUsername: "proxyuser",
		MasterSASLPassword: "proxypass",
		ConnectTimeout:     5 * time.Second,
		AuthIdleTimeout:    30 * time.Second,
		EnableAffinity:     true,
		AuthRateLimit:      server.AuthRateLimiterConfig{Enabled: false},
		TrustedProxies:     []string{"127.0.0.0/8", "::1/128"},
		// A short positive TTL so a changed lookup answer is picked up within the test.
		LookupCache: &config.LookupCacheConfig{Enabled: true, PositiveTTL: "1s", NegativeTTL: "1s", CleanupInterval: "1s", MaxSize: 100},
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
	cm := proxyServer.GetConnectionManager()
	cm.SetAffinityManager(affinityMgr)
	go func() {
		if err := proxyServer.Start(); err != nil {
			t.Logf("proxy: %v", err)
		}
	}()
	defer proxyServer.Stop()
	time.Sleep(200 * time.Millisecond)

	// The health view lists every backend under its pool.
	if _, pool := lastSuccess(t, cm, backendA.Address); pool != "sora-a" {
		t.Errorf("backend A reported in pool %q, want sora-a", pool)
	}
	if _, pool := lastSuccess(t, cm, backendB.Address); pool != "sora-b" {
		t.Errorf("backend B reported in pool %q, want sora-b", pool)
	}

	// 1. Pool sora-a: the login lands on backend A, and only there.
	t0 := time.Now()
	if err := imapLogin(t, proxyAddr, mover); err != nil {
		t.Fatalf("login into pool sora-a: %v", err)
	}
	if ts, _ := lastSuccess(t, cm, backendA.Address); !ts.After(t0) {
		t.Fatalf("backend A did not serve the login (last success %v, login at %v)", ts, t0)
	}
	if ts, _ := lastSuccess(t, cm, backendB.Address); ts.After(t0) {
		t.Fatalf("backend B was dialed for a sora-a user")
	}
	if got, ok := affinityMgr.GetBackend(mover.Email, "imap"); !ok || got != backendA.Address {
		t.Fatalf("affinity after first login = %q, %v; want %s", got, ok, backendA.Address)
	}

	// 2. The lookup moves the user to sora-b. Once the cached answer expires, the next
	// login lands on B: the affinity still pointing at A is outside the new pool and is
	// dropped, not followed.
	lookup.set(mover.Email, map[string]any{"address": mover.Email, "password_hash": hashOf(t, mover.Password), "pool": "sora-b"})
	time.Sleep(1500 * time.Millisecond)
	t1 := time.Now()
	if err := imapLogin(t, proxyAddr, mover); err != nil {
		t.Fatalf("login after the move to sora-b: %v", err)
	}
	if ts, _ := lastSuccess(t, cm, backendB.Address); !ts.After(t1) {
		t.Fatalf("backend B did not serve the login after the move (last success %v, login at %v)", ts, t1)
	}
	if ts, _ := lastSuccess(t, cm, backendA.Address); ts.After(t1) {
		t.Fatalf("backend A was dialed after the user moved to sora-b (stale affinity followed)")
	}
	if got, ok := affinityMgr.GetBackend(mover.Email, "imap"); !ok || got != backendB.Address {
		t.Fatalf("affinity after the move = %q, %v; want %s", got, ok, backendB.Address)
	}

	// 3. An unknown pool and an answer without a pool (no default) are temporary
	// failures, not authentication failures: the password was right.
	for name, account := range map[string]common.TestAccount{"unknown pool": unknown, "no pool, no default": nopool} {
		t2 := time.Now()
		err := imapLogin(t, proxyAddr, account)
		if err == nil {
			t.Errorf("%s: login succeeded; the user was routed into another pool", name)
			continue
		}
		var ie *imap.Error
		if !errors.As(err, &ie) || ie.Code != imap.ResponseCodeUnavailable {
			t.Errorf("%s: login error = %v; want NO [UNAVAILABLE]", name, err)
		}
		for _, b := range []string{backendA.Address, backendB.Address} {
			if ts, _ := lastSuccess(t, cm, b); ts.After(t2) {
				t.Errorf("%s: backend %s was dialed", name, b)
			}
		}
	}

	// 4. An explicit server in the answer still pins, whatever "pool" says next to it.
	t3 := time.Now()
	if err := imapLogin(t, proxyAddr, pinned); err != nil {
		t.Fatalf("login with an explicit server: %v", err)
	}
	if ts, _ := lastSuccess(t, cm, backendB.Address); !ts.After(t3) {
		t.Errorf("explicit server %s was not the backend dialed", backendB.Address)
	}
}
