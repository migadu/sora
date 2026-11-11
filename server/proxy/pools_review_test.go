package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
)

// failingLookup is a routing lookup that always fails, as a lookup service outage does.
type failingLookup struct{ calls atomic.Int32 }

func (f *failingLookup) LookupUserRoute(ctx context.Context, email, password string) (*UserRoutingInfo, AuthResult, error) {
	return f.LookupUserRouteWithOptions(ctx, email, password, true)
}
func (f *failingLookup) LookupUserRouteWithOptions(context.Context, string, string, bool) (*UserRoutingInfo, AuthResult, error) {
	f.calls.Add(1)
	return nil, AuthTemporarilyUnavailable, errors.New("lookup service unavailable")
}
func (f *failingLookup) LookupUserRouteWithClientIP(ctx context.Context, email, password, _ string, routeOnly bool) (*UserRoutingInfo, AuthResult, error) {
	return f.LookupUserRouteWithOptions(ctx, email, password, routeOnly)
}
func (f *failingLookup) Close() error { return nil }

// A pool with remote_tls and remote_tls_use_starttls (what LMTP and ManageSieve need)
// gives IMAP and POP3, which cannot STARTTLS to a backend, an implicit-TLS backend leg,
// never a plaintext one. The same pool keeps the STARTTLS meaning for the protocols that
// upgrade the connection themselves.
func TestPools_ImplicitTLSOnlyProtocolsNeverDialPlaintext(t *testing.T) {
	backend := httptest.NewUnstartedServer(http.NotFoundHandler())
	backend.StartTLS()
	t.Cleanup(backend.Close)
	addr := backend.Listener.Addr().String()

	specs := []PoolSpec{{Name: "tls", Backends: []string{addr}, Default: true,
		Settings: BackendSettings{TLS: true, TLSUseStartTLS: true, TLSVerify: false}}}

	for _, c := range []struct {
		name         string
		implicitOnly bool
		wantTLS      bool
	}{
		{"IMAP/POP3 proxy (implicit TLS only)", true, true},
		{"LMTP/ManageSieve proxy (STARTTLS after connect)", false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			cm, err := NewConnectionManagerFromOptions(ManagerOptions{
				Pools: specs, RemotePort: 143, ConnectTimeout: 2 * time.Second,
				ServerName: "tls-test", DisableHealthCheck: true, ImplicitTLSOnly: c.implicitOnly,
			})
			if err != nil {
				t.Fatal(err)
			}
			res, err := routeFor(t, cm, &UserRoutingInfo{PoolName: "tls"}, nil)
			if err != nil {
				t.Fatalf("DetermineRoute: %v", err)
			}
			conn, _, err := cm.ConnectWithProxy(context.Background(), res.PreferredAddr, "", 0, "", 0, res.RoutingInfo)
			if err != nil {
				t.Fatalf("ConnectWithProxy: %v", err)
			}
			defer conn.Close()
			tlsConn, isTLS := conn.(*tls.Conn)
			if isTLS != c.wantTLS {
				t.Fatalf("backend leg is TLS = %v, want %v", isTLS, c.wantTLS)
			}
			if isTLS && !tlsConn.ConnectionState().HandshakeComplete {
				t.Fatal("TLS handshake with the backend did not complete")
			}
		})
	}
}

// With named pools a routing lookup that fails is a refusal, not a route into the default
// pool (where the account need not live), and the user's affinity in their real pool is
// left alone. A flat list keeps routing as before pools.
func TestPools_FailedRoutingLookupIsRefused(t *testing.T) {
	lookup := &failingLookup{}
	cm, err := NewConnectionManagerWithPools(testPoolSpecs(), 143, time.Second, lookup, "pools-test", true)
	if err != nil {
		t.Fatal(err)
	}
	aff := &poolAffinityStub{found: true, backend: "10.0.1.2:143", protocol: "lmtp"}
	cm.SetAffinityManager(aff)
	_, err = DetermineRoute(RouteParams{
		Ctx: context.Background(), Username: "user@example.com", Protocol: "lmtp",
		ConnManager: cm, EnableAffinity: true, ProxyName: "test",
	})
	if !errors.Is(err, ErrRouteLookupFailed) {
		t.Fatalf("named pools: err = %v, want ErrRouteLookupFailed", err)
	}
	if lookup.calls.Load() == 0 {
		t.Fatal("the routing lookup was never asked")
	}
	if len(aff.deleted) != 0 {
		t.Fatalf("a failed lookup deleted the user's affinity: %v", aff.deleted)
	}

	flat, err := NewConnectionManagerWithRouting([]string{"10.0.0.1:24"}, 24, false, false, false, time.Second, &failingLookup{}, "flat")
	if err != nil {
		t.Fatal(err)
	}
	res, err := DetermineRoute(RouteParams{
		Ctx: context.Background(), Username: "user@example.com", Protocol: "lmtp",
		ConnManager: flat, ProxyName: "test",
	})
	if err != nil || res.PreferredAddr != "10.0.0.1:24" {
		t.Fatalf("flat list: route %q, err %v; want the list's backend, as before pools", res.PreferredAddr, err)
	}
}

// A lookup pin whose backend cannot be dialed is a failure, never a round-robin into the
// default pool: the pin names no pool, and the default pool need not hold the account.
func TestPools_PinnedBackendNeverFallsBackIntoAPool(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	live := ln.Addr().String()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	dead := "127.0.0.1:1"
	cm := newPoolsCM(t, []PoolSpec{
		{Name: "default", Backends: []string{live}, Default: true},
		{Name: "pinned", Backends: []string{dead}},
	})
	// A pin as a lookup-cache hit rebuilds it: IsRemoteLookupAccount is not carried, so
	// the dial sees a plain preference that may fall back.
	pin := &UserRoutingInfo{ServerAddress: dead}
	conn, addr, err := cm.ConnectWithProxy(context.Background(), dead, "", 0, "", 0, pin)
	if err == nil {
		conn.Close()
		t.Fatalf("connected to %q, want a failure for the unreachable pin", addr)
	}
	time.Sleep(50 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Fatalf("the default pool's backend took %d connections for a pinned user", n)
	}
}

// Before bouncing a recipient its own database does not know, the LMTP proxy asks whether
// a backend could know better. With named pools that is the default pool only, where a
// local user lives; another pool being healthy does not make a bounce safe.
func TestPools_HealthyPoolBackendsMeansTheDefaultPool(t *testing.T) {
	cm, err := NewConnectionManagerWithPools(testPoolSpecs(), 143, time.Second, nil, "pools-test", false)
	if err != nil {
		t.Fatal(err)
	}
	if !cm.HasHealthyPoolBackends() {
		t.Fatal("fresh manager reports no healthy default-pool backend")
	}
	for _, addr := range []string{"10.0.0.1:143", "10.0.0.2:143"} { // sora0, the default
		for i := 0; i < 3; i++ {
			cm.RecordConnectionFailure(addr)
		}
	}
	if cm.HasHealthyPoolBackends() {
		t.Fatal("every default-pool backend is down, yet a bounce is considered safe because another pool is up")
	}

	specs := testPoolSpecs()
	specs[0].Default = false
	noDefault, err := NewConnectionManagerWithPools(specs, 143, time.Second, nil, "pools-test", false)
	if err != nil {
		t.Fatal(err)
	}
	if noDefault.HasHealthyPoolBackends() {
		t.Fatal("without a default pool no backend can vouch for a local user, yet a bounce is considered safe")
	}
}

// A re-resolution that moves an address from one pool's name to another's moves it
// between the pools, even when the union of all addresses stays the same.
func TestPools_ReResolutionMovesAddressesBetweenPools(t *testing.T) {
	cm := newPoolsCM(t, []PoolSpec{
		{Name: "a", Backends: []string{"a.internal:143"}, Default: true},
		{Name: "b", Backends: []string{"b.internal:143"}},
	})
	union := []string{"10.0.0.1:143", "10.0.0.2:143"}
	cm.installResolvedAddrs(union, map[string][]string{"a.internal:143": {"10.0.0.1:143"}, "b.internal:143": {"10.0.0.2:143"}})
	if !cm.PoolHasBackend("a", "10.0.0.1:143") || !cm.PoolHasBackend("b", "10.0.0.2:143") {
		t.Fatal("setup: first resolution not installed")
	}
	cm.installResolvedAddrs(union, map[string][]string{"a.internal:143": {"10.0.0.2:143"}, "b.internal:143": {"10.0.0.1:143"}})
	if !cm.PoolHasBackend("a", "10.0.0.2:143") || cm.PoolHasBackend("a", "10.0.0.1:143") {
		t.Fatal("pool a kept the address its name no longer resolves to")
	}
	if got := cm.GetBackendByConsistentHashInPool("b", "user@example.com"); got != "10.0.0.1:143" {
		t.Fatalf("pool b hashes to %q, want its new member 10.0.0.1:143", got)
	}
}

// A pool name the lookup API made up is counted under one "unknown" series, not one series
// per name; configured pools keep their own label.
func TestPools_UnknownPoolNamesShareOneMetricSeries(t *testing.T) {
	cm := newPoolsCM(t, testPoolSpecs())
	before := testutil.ToFloat64(metrics.ProxyPoolRoute.WithLabelValues("imap", "unknown", "unknown_pool"))
	for _, name := range []string{"made-up-1", "made-up-2"} {
		if _, err := routeFor(t, cm, &UserRoutingInfo{PoolName: name}, nil); !errors.Is(err, ErrUnknownPool) {
			t.Fatalf("pool %q: err = %v, want ErrUnknownPool", name, err)
		}
	}
	if got := testutil.ToFloat64(metrics.ProxyPoolRoute.WithLabelValues("imap", "unknown", "unknown_pool")) - before; got != 2 {
		t.Fatalf("unknown-pool routes counted %v under pool=\"unknown\", want 2", got)
	}
	if n := testutil.CollectAndCount(metrics.ProxyPoolRoute); n == 0 {
		t.Fatal("no series at all")
	}
	for _, name := range []string{"made-up-1", "made-up-2"} {
		if v := testutil.ToFloat64(metrics.ProxyPoolRoute.WithLabelValues("imap", name, "unknown_pool")); v != 0 {
			t.Fatalf("a series was made for the made-up pool name %q", name)
		}
	}
}

// Every key of a [[pool]] block reaches the routing layer: loaded from a real file and
// converted the way cmd/sora does, nothing is dropped or taken from the [[server]] block.
func TestPools_ConfigFileToPoolSpecs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pools.toml")
	toml := `
[[pool]]
name = "all-on"
backends = ["10.0.0.1", "10.0.0.2:1143"]
default = true
remote_tls = true
remote_tls_use_starttls = true
remote_tls_verify = false
remote_use_proxy_protocol = true
remote_use_id_command = true
remote_use_xclient = true
remote_use_utf8 = true

[[pool]]
name = "all-off"
backends = ["10.0.1.1"]

[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = ":1143"
remote_port = 143
remote_tls = true
remote_tls_verify = false
remote_use_proxy_protocol = true
remote_use_id_command = true
[server.remote_lookup]
enabled = true
url = "https://lookup.example.com/?email=$email"
`
	if err := os.WriteFile(path, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.NewDefaultConfig()
	if err := config.LoadConfigFromFile(path, &cfg); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := cfg.ValidatePools(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	specs := PoolSpecsFromConfig(cfg.Pools)
	if len(specs) != 2 {
		t.Fatalf("got %d specs, want 2", len(specs))
	}
	on, off := specs[0], specs[1]
	if on.Name != "all-on" || !on.Default || strings.Join(on.Backends, ",") != "10.0.0.1,10.0.0.2:1143" {
		t.Errorf("all-on decoded wrong: %+v", on)
	}
	if want := (BackendSettings{TLS: true, TLSUseStartTLS: true, TLSVerify: false, UseProxyProtocol: true, UseIDCommand: true, UseXCLIENT: true, UseUTF8: true}); on.Settings != want {
		t.Errorf("all-on settings = %+v, want %+v", on.Settings, want)
	}
	// Nothing comes from the [[server]] block, whose settings are all on; verify defaults on.
	if want := (BackendSettings{TLSVerify: true}); off.Name != "all-off" || off.Default || off.Settings != want {
		t.Errorf("all-off = %+v, want only remote_tls_verify on (its default)", off)
	}
}
