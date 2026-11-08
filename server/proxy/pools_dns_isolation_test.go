package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"testing"

	"github.com/migadu/sora/config"
)

// A hostname and a literal IP pass lexical validation, but DNS may make them the
// same destination. Neither pool may then borrow the other's CA, even on a pin or
// STARTTLS connection that was selected before the resolution changed.
func TestPools_DNSCollisionRefusesRoutingAndTLS(t *testing.T) {
	a, b := newTestCA(t), newTestCA(t)
	cert := a.leaf(t, []string{"localhost"}, loopbackIPs)
	port := tlsBackendOnEveryAddress(t, cert)
	alias := net.JoinHostPort("localhost", strconv.Itoa(port))
	resolved := resolvePoolEntries(alias, nil)
	if len(resolved) == 0 {
		t.Fatal("localhost did not resolve")
	}
	addr := resolved[0]
	cfg := &config.Config{Pools: []config.PoolConfig{
		{Name: "a", Default: true, Backends: []string{addr}, RemoteTLS: true, RemoteTLSCAFile: a.file},
		{Name: "b", Backends: []string{alias}, RemoteTLS: true, RemoteTLSCAFile: b.file},
	}}
	if err := cfg.ValidatePools(); err != nil {
		t.Fatal(err)
	}
	cm := newPoolsCM(t, PoolSpecsFromConfig(cfg.Pools))
	if err := cm.ResolveAddresses(); !errors.Is(err, ErrAmbiguousBackendPool) {
		t.Fatalf("DNS overlap: %v", err)
	}
	for _, pool := range []string{"", "a", "b"} {
		if route, err := routeFor(t, cm, &UserRoutingInfo{PoolName: pool}, nil); !errors.Is(err, ErrAmbiguousBackendPool) {
			t.Fatalf("pool %q: route %+v, err %v; want ambiguous pool refusal", pool, route, err)
		}
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{addr, alias} {
		if cm.AllowRemoteLookupBackend(target) || cm.PoolOfBackend(target) != "" {
			t.Fatalf("ambiguous lookup pin allowed: %s", target)
		}
		if err := cm.RefuseMaintenanceDial("tcp", target, nil); !errors.Is(err, ErrAmbiguousBackendPool) {
			t.Fatalf("dial %s: %v", target, err)
		}
		for _, verify := range []bool{true, false} {
			cfg := cm.BackendClientTLS(verify, target)
			if cfg.VerifyConnection == nil {
				t.Fatal("ambiguous TLS config has no refusal check")
			}
			if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}); !errors.Is(err, ErrAmbiguousBackendPool) {
				t.Fatalf("TLS for %s, verify=%v trusted another pool's certificate: %v", target, verify, err)
			}
			conn, err := tls.Dial("tcp", addr, cfg)
			if conn != nil {
				conn.Close()
			}
			if !errors.Is(err, ErrAmbiguousBackendPool) {
				t.Fatalf("TLS handshake for %s, verify=%v: %v", target, verify, err)
			}
		}
	}
}

// Cover re-resolution, including unchanged union, unrelated pools, a cached route,
// and recovery. None of the ownership checks may depend on a changed union or on
// the first startup DNS answer being the only answer the process will ever see.
func TestPools_DNSCollisionRefreshAndRecovery(t *testing.T) {
	dns := startFakeDNS(t, "pool-b.test.", net.ParseIP("127.0.0.2"))
	cm := newPoolsCM(t, []PoolSpec{
		{Name: "a", Default: true, Backends: []string{"127.0.0.1:143"}},
		{Name: "b", Backends: []string{"pool-b.test:143"}},
		{Name: "c", Backends: []string{"127.0.0.2:143", "127.0.0.3:143"}},
	})
	// Start with b separated from a and c.
	dns.setIPs(net.ParseIP("127.0.0.4"))
	if err := cm.ResolveAddresses(); err != nil {
		t.Fatal(err)
	}
	stale, err := routeFor(t, cm, &UserRoutingInfo{PoolName: "a"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dns.setIPs(net.ParseIP("127.0.0.1"))
	if err := cm.ResolveAddresses(); !errors.Is(err, ErrAmbiguousBackendPool) {
		t.Fatalf("overlap not reported: %v", err)
	}
	for i := 0; i < 5; i++ {
		if i > 0 { // The union is now unchanged; the refusal must survive another refresh.
			if err := cm.ResolveAddresses(); !errors.Is(err, ErrAmbiguousBackendPool) {
				t.Fatal(err)
			}
		}
		for _, pool := range []string{"a", "b"} {
			if _, err := cm.ResolvePool(pool); !errors.Is(err, ErrAmbiguousBackendPool) {
				t.Fatalf("pool %s: %v", pool, err)
			}
		}
		if conn, _, err := cm.ConnectWithProxy(context.Background(), stale.PreferredAddr, "", 0, "", 0, stale.RoutingInfo); err == nil {
			conn.Close()
			t.Fatal("cached route dialed a pool after its ownership became ambiguous")
		}
		if _, err := routeFor(t, cm, &UserRoutingInfo{PoolName: "c"}, nil); err != nil {
			t.Fatalf("unrelated pool refused: %v", err)
		}
	}
	cm.healthMu.RLock()
	failures := cm.backendHealth[stale.PreferredAddr].FailureCount
	cm.healthMu.RUnlock()
	if failures != 0 {
		t.Fatalf("DNS overlap counted as %d backend failures", failures)
	}
	dns.setIPs(net.ParseIP("127.0.0.4"))
	if err := cm.ResolveAddresses(); err != nil {
		t.Fatal(err)
	}
	for _, pool := range []string{"a", "b", "c"} {
		if _, err := routeFor(t, cm, &UserRoutingInfo{PoolName: pool}, nil); err != nil {
			t.Fatalf("pool %s did not recover: %v", pool, err)
		}
	}
	if err := cm.RefuseMaintenanceDial("tcp", stale.PreferredAddr, nil); err != nil {
		t.Fatalf("resolved ownership left a stale dial refusal: %v", err)
	}
}
