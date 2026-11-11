package proxy

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
	"time"
)

// poolAffinityStub is an AffinityManager with one scripted answer and a record of deletes.
type poolAffinityStub struct {
	backend  string
	protocol string
	found    bool
	deleted  []string
	set      map[string]string
}

func (a *poolAffinityStub) GetBackend(username, protocol string) (string, bool) {
	if a.found && a.protocol == protocol {
		return a.backend, true
	}
	return "", false
}

func (a *poolAffinityStub) GetBackendAcrossProtocols(username, protocol string) (string, string, bool) {
	if !a.found {
		return "", "", false
	}
	return a.backend, a.protocol, true
}

func (a *poolAffinityStub) SetBackend(username, backend, protocol string) {
	if a.set == nil {
		a.set = map[string]string{}
	}
	a.set[username+":"+protocol] = backend
}

func (a *poolAffinityStub) UpdateBackend(username, oldBackend, newBackend, protocol string) {
	a.SetBackend(username, newBackend, protocol)
}

func (a *poolAffinityStub) DeleteBackend(username, protocol string) {
	a.deleted = append(a.deleted, username+":"+protocol)
	a.found = false
}

func testPoolSpecs() []PoolSpec {
	return []PoolSpec{
		{Name: "sora0", Backends: []string{"10.0.0.1", "10.0.0.2"}, Default: true,
			Settings: BackendSettings{UseProxyProtocol: true, UseIDCommand: true, TLSVerify: true}},
		{Name: "sora1", Backends: []string{"10.0.1.1:143", "10.0.1.2"},
			Settings: BackendSettings{TLS: true, TLSVerify: true, UseXCLIENT: true}},
		{Name: "dovecot1", Backends: []string{"10.0.2.1"}},
	}
}

func newPoolsCM(t *testing.T, specs []PoolSpec) *ConnectionManager {
	t.Helper()
	cm, err := NewConnectionManagerWithPools(specs, 143, time.Second, nil, "pools-test", true)
	if err != nil {
		t.Fatalf("NewConnectionManagerWithPools: %v", err)
	}
	return cm
}

func routeFor(t *testing.T, cm *ConnectionManager, info *UserRoutingInfo, affinity AffinityManager) (RouteResult, error) {
	t.Helper()
	cm.SetAffinityManager(affinity)
	return DetermineRoute(RouteParams{
		Ctx:            context.Background(),
		Username:       "user@example.com",
		Protocol:       "imap",
		RoutingInfo:    info,
		ConnManager:    cm,
		EnableAffinity: affinity != nil,
		ProxyName:      "test",
	})
}

func TestPools_ConstructorNormalizesAndValidates(t *testing.T) {
	cm := newPoolsCM(t, testPoolSpecs())
	if !cm.HasNamedPools() {
		t.Fatal("expected named pools")
	}
	if got := cm.PoolNames(); !slices.Equal(got, []string{"sora0", "sora1", "dovecot1"}) {
		t.Errorf("PoolNames = %v", got)
	}
	for _, want := range []string{"10.0.0.1:143", "10.0.0.2:143"} {
		if !cm.PoolHasBackend("sora0", want) {
			t.Errorf("sora0 lacks %s (port completion from remote_port)", want)
		}
	}
	if !cm.PoolHasBackend("sora1", "10.0.1.1:143") || !cm.PoolHasBackend("sora1", "10.0.1.2:143") {
		t.Errorf("sora1 members wrong")
	}
	if cm.PoolHasBackend("sora1", "10.0.0.1:143") {
		t.Errorf("sora0's member must not be in sora1")
	}
	if cm.PoolHasBackend("nope", "10.0.0.1:143") {
		t.Errorf("unknown pool has no members")
	}
	// The union still knows every backend (health, restrict_to_pool).
	for _, addr := range []string{"10.0.0.1:143", "10.0.1.2:143", "10.0.2.1:143"} {
		if !cm.HasBackend(addr) {
			t.Errorf("union lacks %s", addr)
		}
	}
	if info, err := cm.ResolvePool(""); err != nil || info.Name != "sora0" || !info.Default || !info.Settings.UseProxyProtocol {
		t.Errorf("ResolvePool(\"\") = %+v, %v; want default sora0", info, err)
	}

	bad := []struct {
		name  string
		specs []PoolSpec
		want  string
	}{
		{"host in two pools", []PoolSpec{{Name: "a", Backends: []string{"h:143"}}, {Name: "b", Backends: []string{"h"}}}, "in pool"},
		{"two defaults", []PoolSpec{{Name: "a", Backends: []string{"h1"}, Default: true}, {Name: "b", Backends: []string{"h2"}, Default: true}}, "both default"},
		{"no backends", []PoolSpec{{Name: "a"}}, "no backends"},
		{"no name", []PoolSpec{{Backends: []string{"h1"}}}, "without a name"},
		{"declared twice", []PoolSpec{{Name: "a", Backends: []string{"h1"}}, {Name: "a", Backends: []string{"h2"}}}, "declared twice"},
		{"none", nil, "no backend pools"},
	}
	for _, tc := range bad {
		if _, err := NewConnectionManagerWithPools(tc.specs, 143, time.Second, nil, "t", true); err == nil || !contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", tc.name, err, tc.want)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestPools_ConsistentHashConfinedToPool(t *testing.T) {
	cm := newPoolsCM(t, testPoolSpecs())
	users := []string{"a@example.com", "b@example.com", "c@example.com", "d@example.com", "e@example.com", "f@example.com", "g@example.com", "h@example.com"}
	for _, u := range users {
		if b := cm.GetBackendByConsistentHashInPool("sora1", u); !cm.PoolHasBackend("sora1", b) {
			t.Errorf("hash(sora1, %s) = %q, not a sora1 member", u, b)
		}
		if b := cm.GetBackendByConsistentHashInPool("dovecot1", u); b != "10.0.2.1:143" {
			t.Errorf("hash(dovecot1, %s) = %q, want the single member", u, b)
		}
		if b := cm.GetBackendByConsistentHash(u); !cm.PoolHasBackend("sora0", b) {
			t.Errorf("hash(default, %s) = %q, not a sora0 member", u, b)
		}
		if b := cm.GetBackendByConsistentHashInPool("nope", u); b != "" {
			t.Errorf("hash(unknown pool) = %q, want empty", b)
		}
	}
}

func TestPools_DetermineRouteConfinedToPoolAndStampsSettings(t *testing.T) {
	cm := newPoolsCM(t, testPoolSpecs())

	info := &UserRoutingInfo{PoolName: "sora1", IsRemoteLookupAccount: true, RemoteUseProxyProtocol: true}
	res, err := routeFor(t, cm, info, nil)
	if err != nil {
		t.Fatalf("route: %v", err)
	}
	if res.Pool != "sora1" || !cm.PoolHasBackend("sora1", res.PreferredAddr) || res.RoutingMethod != "consistent_hash" {
		t.Errorf("result = %+v", res)
	}
	if res.IsRemoteLookupRoute {
		t.Errorf("a pool route is not a hard pin")
	}
	// The pool's settings replace whatever the lookup client put on the info.
	if !info.RemoteTLS || !info.RemoteTLSVerify || info.RemoteUseProxyProtocol || !info.RemoteUseXCLIENT || info.RemoteUseIDCommand {
		t.Errorf("sora1 settings not stamped: %+v", info)
	}

	// No pool named → the default pool, with ITS settings.
	info = &UserRoutingInfo{AuthOnlyMode: true, IsRemoteLookupAccount: true}
	res, err = routeFor(t, cm, info, nil)
	if err != nil {
		t.Fatalf("route default: %v", err)
	}
	if res.Pool != "sora0" || !cm.PoolHasBackend("sora0", res.PreferredAddr) || info.PoolName != "sora0" || !info.RemoteUseProxyProtocol || !info.RemoteUseIDCommand {
		t.Errorf("default route = %+v info=%+v", res, info)
	}

	// A nil routing info (no lookup configured) still lands in the default pool.
	res, err = routeFor(t, cm, nil, nil)
	if err != nil || res.Pool != "sora0" || res.RoutingInfo == nil || res.RoutingInfo.PoolName != "sora0" {
		t.Errorf("nil info route = %+v, %v", res, err)
	}

	// Unknown pool: an error, and no address — never another pool's backend.
	res, err = routeFor(t, cm, &UserRoutingInfo{PoolName: "sora9"}, nil)
	if !errors.Is(err, ErrUnknownPool) {
		t.Fatalf("unknown pool err = %v, want ErrUnknownPool", err)
	}
	if res.PreferredAddr != "" {
		t.Errorf("unknown pool must not pick an address, got %q", res.PreferredAddr)
	}

	// An explicit server wins over everything, pool checks included.
	res, err = routeFor(t, cm, &UserRoutingInfo{ServerAddress: "10.0.2.1:143", PoolName: "sora9", IsRemoteLookupAccount: true}, nil)
	if err != nil || !res.IsRemoteLookupRoute || res.PreferredAddr != "10.0.2.1:143" {
		t.Errorf("explicit server route = %+v, %v", res, err)
	}
}

func TestPools_NoDefaultRefusesUnnamedRoute(t *testing.T) {
	specs := testPoolSpecs()
	specs[0].Default = false
	cm := newPoolsCM(t, specs)

	for _, info := range []*UserRoutingInfo{nil, {AuthOnlyMode: true}, {PoolName: ""}} {
		res, err := routeFor(t, cm, info, nil)
		if !errors.Is(err, ErrNoDefaultPool) {
			t.Errorf("info=%+v: err = %v, want ErrNoDefaultPool", info, err)
		}
		if res.PreferredAddr != "" {
			t.Errorf("must not pick an address without a pool, got %q", res.PreferredAddr)
		}
	}
	if b := cm.GetBackendByConsistentHash("user@example.com"); b != "" {
		t.Errorf("default-pool hash without a default = %q, want empty", b)
	}
	// Named routes still work.
	if res, err := routeFor(t, cm, &UserRoutingInfo{PoolName: "dovecot1"}, nil); err != nil || res.PreferredAddr != "10.0.2.1:143" {
		t.Errorf("dovecot1 route = %+v, %v", res, err)
	}
}

func TestPools_LegacyListIgnoresPoolName(t *testing.T) {
	cm, err := NewConnectionManager([]string{"backend1:143", "backend2:143"}, 143, true, false, true, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if cm.HasNamedPools() {
		t.Fatal("a flat list is not named pools")
	}
	info := &UserRoutingInfo{PoolName: "sora1", RemoteTLS: false, RemoteUseProxyProtocol: false}
	res, err := routeFor(t, cm, info, nil)
	if err != nil {
		t.Fatalf("legacy route with a pool name must not fail: %v", err)
	}
	if res.Pool != "" || info.PoolName != "" || !cm.HasBackend(res.PreferredAddr) {
		t.Errorf("legacy route = %+v info=%+v", res, info)
	}
	// Legacy never stamps: the info keeps what the lookup client set.
	if info.RemoteTLS || info.RemoteUseProxyProtocol {
		t.Errorf("legacy must not stamp pool settings: %+v", info)
	}
}

func TestPools_AffinityOutsidePoolIsDropped(t *testing.T) {
	cm := newPoolsCM(t, testPoolSpecs())

	// Affinity points at a sora0 host; the lookup now says sora1 (the user moved).
	aff := &poolAffinityStub{backend: "10.0.0.1:143", protocol: "imap", found: true}
	res, err := routeFor(t, cm, &UserRoutingInfo{PoolName: "sora1"}, aff)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(aff.deleted, "user@example.com:imap") {
		t.Errorf("out-of-pool affinity must be deleted, deletes=%v", aff.deleted)
	}
	if !cm.PoolHasBackend("sora1", res.PreferredAddr) || res.RoutingMethod != "consistent_hash" {
		t.Errorf("user must be rerouted inside sora1: %+v", res)
	}

	// Affinity inside the pool is honored.
	aff = &poolAffinityStub{backend: "10.0.1.2:143", protocol: "imap", found: true}
	res, err = routeFor(t, cm, &UserRoutingInfo{PoolName: "sora1"}, aff)
	if err != nil {
		t.Fatal(err)
	}
	if res.PreferredAddr != "10.0.1.2:143" || res.RoutingMethod != "affinity" || len(aff.deleted) != 0 {
		t.Errorf("in-pool affinity not honored: %+v deletes=%v", res, aff.deleted)
	}
}

func TestPools_CrossProtocolAffinityResolvedWithinPool(t *testing.T) {
	cm := newPoolsCM(t, testPoolSpecs())

	// POP3 landed the user on 10.0.1.1 (port 110); IMAP in sora1 resolves it to :143.
	aff := &poolAffinityStub{backend: "10.0.1.1:110", protocol: "pop3", found: true}
	res, err := routeFor(t, cm, &UserRoutingInfo{PoolName: "sora1"}, aff)
	if err != nil {
		t.Fatal(err)
	}
	if res.PreferredAddr != "10.0.1.1:143" || res.RoutingMethod != "affinity_cross_protocol" {
		t.Errorf("cross-protocol affinity = %+v", res)
	}

	// The same POP3 affinity is useless for a user routed to sora0: skipped, hashed in sora0.
	aff = &poolAffinityStub{backend: "10.0.1.1:110", protocol: "pop3", found: true}
	res, err = routeFor(t, cm, &UserRoutingInfo{PoolName: "sora0"}, aff)
	if err != nil {
		t.Fatal(err)
	}
	if !cm.PoolHasBackend("sora0", res.PreferredAddr) || res.RoutingMethod != "consistent_hash" {
		t.Errorf("out-of-pool cross-protocol affinity must be skipped: %+v", res)
	}
}

// acceptAll accepts and closes connections so a dial succeeds.
func acceptAll(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln, ln.Addr().String()
}

func TestPools_RoundRobinStaysInsidePool(t *testing.T) {
	_, a := acceptAll(t)
	_, b := acceptAll(t)
	cm := newPoolsCM(t, []PoolSpec{
		{Name: "a", Backends: []string{a}},
		{Name: "b", Backends: []string{b}},
	})

	ctx := context.Background()
	// No preferred address (every hash member unhealthy, say): round-robin must pick
	// inside the route's pool.
	conn, addr, err := cm.ConnectWithProxy(ctx, "", "", 0, "", 0, &UserRoutingInfo{PoolName: "a"})
	if err != nil {
		t.Fatalf("pool a: %v", err)
	}
	conn.Close()
	if addr != a {
		t.Errorf("pool a routed to %s, want %s", addr, a)
	}
	conn, addr, err = cm.ConnectWithProxy(ctx, "", "", 0, "", 0, &UserRoutingInfo{PoolName: "b"})
	if err != nil {
		t.Fatalf("pool b: %v", err)
	}
	conn.Close()
	if addr != b {
		t.Errorf("pool b routed to %s, want %s", addr, b)
	}
	// Unknown pool and no default: refused, nothing dialed.
	if _, _, err := cm.ConnectWithProxy(ctx, "", "", 0, "", 0, &UserRoutingInfo{PoolName: "zzz"}); !errors.Is(err, ErrUnknownPool) {
		t.Errorf("unknown pool err = %v", err)
	}
	if _, _, err := cm.ConnectWithProxy(ctx, "", "", 0, "", 0, nil); !errors.Is(err, ErrNoDefaultPool) {
		t.Errorf("no default err = %v", err)
	}
	// A preferred address from affinity that fails falls back INSIDE the pool, not to b.
	conn, addr, err = cm.ConnectWithProxy(ctx, "127.0.0.1:1", "", 0, "", 0, &UserRoutingInfo{PoolName: "a"})
	if err != nil {
		t.Fatalf("fallback: %v", err)
	}
	conn.Close()
	if addr != a {
		t.Errorf("fallback routed to %s, want %s", addr, a)
	}
}

func TestPools_ResolutionRebuildsEachPool(t *testing.T) {
	cm := newPoolsCM(t, []PoolSpec{
		{Name: "sora0", Backends: []string{"a.internal"}, Default: true},
		{Name: "sora1", Backends: []string{"b.internal"}},
	})
	cm.installResolvedAddrs(
		[]string{"10.0.0.5:143", "10.0.0.6:143", "10.0.1.5:143"},
		map[string][]string{
			"a.internal:143": {"10.0.0.5:143", "10.0.0.6:143"},
			"b.internal:143": {"10.0.1.5:143"},
		},
	)
	for _, u := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		if b := cm.GetBackendByConsistentHashInPool("sora0", u); b != "10.0.0.5:143" && b != "10.0.0.6:143" {
			t.Errorf("sora0 hash after resolution = %q", b)
		}
		if b := cm.GetBackendByConsistentHashInPool("sora1", u); b != "10.0.1.5:143" {
			t.Errorf("sora1 hash after resolution = %q", b)
		}
	}
	if cm.PoolHasBackend("sora1", "10.0.0.5:143") || !cm.PoolHasBackend("sora1", "10.0.1.5:143") {
		t.Errorf("sora1 membership after resolution wrong")
	}
	if cm.PoolHasBackend("sora0", "a.internal:143") {
		t.Errorf("configured name must be replaced by its addresses")
	}

	byAddr := map[string]string{}
	for _, st := range cm.GetBackendHealthStatuses() {
		byAddr[st.Address] = st.Pool
	}
	want := map[string]string{"10.0.0.5:143": "sora0", "10.0.0.6:143": "sora0", "10.0.1.5:143": "sora1"}
	for addr, pool := range want {
		if byAddr[addr] != pool {
			t.Errorf("health status pool for %s = %q, want %q", addr, byAddr[addr], pool)
		}
	}
	if len(byAddr) != len(want) {
		t.Errorf("health statuses = %v", byAddr)
	}
}

// After a connection the user's affinity records the backend reached; a route whose pool
// is gone records nothing.
func TestPools_UpdateAffinityRecordsTheBackendReached(t *testing.T) {
	cm := newPoolsCM(t, testPoolSpecs())
	aff := &poolAffinityStub{}
	cm.SetAffinityManager(aff)
	info := &UserRoutingInfo{PoolName: "sora1"}
	UpdateAffinityAfterConnection(RouteParams{
		Username: "user@example.com", Protocol: "imap", RoutingInfo: info, ConnManager: cm, EnableAffinity: true, ProxyName: "test",
	}, "10.0.1.2:143", false)
	if aff.set["user@example.com:imap"] != "10.0.1.2:143" {
		t.Errorf("affinity not set: %v", aff.set)
	}
	// An unresolvable pool records nothing rather than hashing in the wrong pool.
	aff = &poolAffinityStub{}
	cm.SetAffinityManager(aff)
	UpdateAffinityAfterConnection(RouteParams{
		Username: "user@example.com", Protocol: "imap", RoutingInfo: &UserRoutingInfo{PoolName: "gone"}, ConnManager: cm, EnableAffinity: true,
	}, "10.0.1.2:143", false)
	if len(aff.set) != 0 {
		t.Errorf("affinity set for an unknown pool: %v", aff.set)
	}
}
