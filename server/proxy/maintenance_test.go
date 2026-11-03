package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMaintenance_ContainsMatchesHostOfAnyPort(t *testing.T) {
	m := NewMaintenance()
	m.Set([]string{"Storage1.Example.com.", "10.0.0.5", "[2001:db8::1]"})

	cases := []struct {
		addr string
		want bool
	}{
		{"storage1.example.com:143", true}, // case and trailing dot ignored
		{"storage1.example.com:24", true},  // one entry covers every protocol port
		{"storage1.example.com", true},     // bare host
		{"10.0.0.5:4190", true},
		{"[2001:db8:0::1]:143", true}, // IPv6 spelled differently
		{"2001:db8::1", true},
		{"storage2.example.com:143", false},
		{"10.0.0.50:143", false},
		{"", false},
	}
	for _, c := range cases {
		if got := m.Contains(c.addr); got != c.want {
			t.Errorf("Contains(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestMaintenance_NilIsEmpty(t *testing.T) {
	var m *Maintenance
	if m.Contains("10.0.0.5:143") {
		t.Fatal("a nil Maintenance must contain nothing")
	}
}

func TestMaintenance_SetReportsNewlyEnteredHosts(t *testing.T) {
	m := NewMaintenance()
	if got := m.Set([]string{"a.example.com"}); len(got) != 1 || got[0] != "a.example.com" {
		t.Fatalf("first Set entered = %v, want [a.example.com]", got)
	}
	if got := m.Set([]string{"a.example.com", "B.example.com"}); len(got) != 1 || got[0] != "b.example.com" {
		t.Fatalf("second Set entered = %v, want [b.example.com]", got)
	}
	if got := m.Set(nil); len(got) != 0 {
		t.Fatalf("clearing entered = %v, want none", got)
	}
	if m.Contains("a.example.com:143") {
		t.Fatal("cleared set still contains a host")
	}
}

func TestMaintenance_ListenersRunOnEveryNonEmptySet(t *testing.T) {
	m := NewMaintenance()
	var calls atomic.Int32
	m.OnUpdate(func() { calls.Add(1) })

	m.Set([]string{"a.example.com"})
	m.Set([]string{"a.example.com"}) // unchanged, still swept: a session may have connected since
	m.Set(nil)                       // empty: nothing to sweep
	if got := calls.Load(); got != 2 {
		t.Fatalf("listener calls = %d, want 2", got)
	}
}

func TestMaintenancePoller_AddsResolvedAddressesOfHostnames(t *testing.T) {
	m := NewMaintenance()
	p := NewMaintenancePoller(m, func(context.Context) ([]string, error) {
		return []string{"storage1.example.com", "10.0.0.9"}, nil
	})
	m.lookupHost = func(_ context.Context, host string) ([]string, error) {
		if host != "storage1.example.com" {
			t.Errorf("looked up %q; IP literals must not be resolved", host)
		}
		return []string{"10.0.0.5", "2001:db8::5"}, nil
	}

	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	for _, addr := range []string{"storage1.example.com:143", "10.0.0.5:143", "[2001:db8::5]:24", "10.0.0.9:110"} {
		if !m.Contains(addr) {
			t.Errorf("Contains(%q) = false after refresh", addr)
		}
	}
}

func TestMaintenancePoller_KeepsLastKnownStateOnFailure(t *testing.T) {
	m := NewMaintenance()
	var loadErr error
	p := NewMaintenancePoller(m, func(context.Context) ([]string, error) {
		return []string{"storage1.example.com"}, loadErr
	})
	var dnsErr error
	m.lookupHost = func(context.Context, string) ([]string, error) {
		return []string{"10.0.0.5"}, dnsErr
	}
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// DNS failing: the name stays in maintenance with the addresses it last resolved to.
	dnsErr = errors.New("SERVFAIL")
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh with DNS failure: %v", err)
	}
	if !m.Contains("10.0.0.5:143") {
		t.Fatal("a DNS failure dropped the last known address from maintenance")
	}

	// The list failing to load (database down): maintenance must NOT end, or a drained
	// backend would silently return to rotation.
	loadErr = errors.New("database unavailable")
	if err := p.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh must report a load failure")
	}
	if !m.Contains("storage1.example.com:143") || !m.Contains("10.0.0.5:143") {
		t.Fatal("a load failure cleared maintenance")
	}
}

// fakeDrainSession is a proxied session as the drainer sees it.
type fakeDrainSession struct {
	backend string
	closed  atomic.Int32
}

func TestSessionDrainer_ClosesOnlySessionsOnMaintenanceBackends(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sessions := []*fakeDrainSession{
		{backend: "10.0.0.5:143"},
		{backend: "10.0.0.6:143"},
		{backend: "10.0.0.5:143"},
		{backend: ""}, // not yet routed
	}
	targets := func() []DrainTarget {
		out := make([]DrainTarget, 0, len(sessions))
		for _, s := range sessions {
			out = append(out, DrainTarget{Backend: s.backend, Close: func() { s.closed.Add(1) }})
		}
		return out
	}

	m := NewMaintenance()
	StartSessionDrainer(ctx, m, 1000, targets, nil, "test")
	m.Set([]string{"10.0.0.5"})

	waitFor(t, func() bool { return sessions[0].closed.Load() > 0 && sessions[2].closed.Load() > 0 })
	if sessions[1].closed.Load() != 0 || sessions[3].closed.Load() != 0 {
		t.Fatal("drainer closed a session that is not on a backend in maintenance")
	}
}

func TestSessionDrainer_PacesClosesAndStopsWhenMaintenanceEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const n = 20
	var mu sync.Mutex
	var closedAt []time.Time
	targets := func() []DrainTarget {
		out := make([]DrainTarget, n)
		for i := range out {
			out[i] = DrainTarget{Backend: "10.0.0.5:143", Close: func() {
				mu.Lock()
				closedAt = append(closedAt, time.Now())
				mu.Unlock()
			}}
		}
		return out
	}

	m := NewMaintenance()
	StartSessionDrainer(ctx, m, 20, targets, nil, "test") // one close per 50ms
	m.Set([]string{"10.0.0.5"})

	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(closedAt) >= 3 })
	m.Set(nil) // operator turned maintenance off mid-drain
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(closedAt) >= n {
		t.Fatalf("drainer kept closing after maintenance ended: %d of %d closed", len(closedAt), n)
	}
	for i := 1; i < len(closedAt); i++ {
		if gap := closedAt[i].Sub(closedAt[i-1]); gap < 30*time.Millisecond {
			t.Fatalf("closes %d and %d were %v apart; rate 20/s must space them ~50ms", i-1, i, gap)
		}
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 5s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// --- Routing ---

func newMaintenanceTestManager(t *testing.T, backends ...string) (*ConnectionManager, *Maintenance) {
	t.Helper()
	cm, err := NewConnectionManager(backends, 143, false, false, false, time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}
	m := NewMaintenance()
	m.Set(nil) // loaded, nothing in maintenance
	cm.SetMaintenance(m)
	return cm, m
}

func TestConsistentHash_SkipsBackendsInMaintenance(t *testing.T) {
	cm, m := newMaintenanceTestManager(t, "backend1:143", "backend2:143", "backend3:143")

	// Find users hashed onto backend1 before maintenance, so the test exercises the skip.
	var users []string
	for i := 0; len(users) < 20 && i < 10000; i++ {
		u := "user" + string(rune('a'+i%26)) + time.Duration(i).String() + "@example.com"
		if cm.GetBackendByConsistentHash(u) == "backend1:143" {
			users = append(users, u)
		}
	}
	if len(users) == 0 {
		t.Fatal("no user hashed to backend1")
	}

	m.Set([]string{"backend1"})
	moved := map[string]bool{}
	for _, u := range users {
		b := cm.GetBackendByConsistentHash(u)
		if b == "" || b == "backend1:143" {
			t.Fatalf("user %s routed to %q while backend1 is in maintenance", u, b)
		}
		moved[b] = true
	}
	if len(moved) < 2 {
		t.Errorf("backend1's users all moved to %v; the ring should spread them", moved)
	}

	m.Set([]string{"backend1", "backend2", "backend3"})
	if b := cm.GetBackendByConsistentHash(users[0]); b != "" {
		t.Fatalf("every backend in maintenance, hash returned %q", b)
	}
}

func TestDetermineRoute_AffinityToMaintenanceBackendIsDropped(t *testing.T) {
	cm, m := newMaintenanceTestManager(t, "backend1:143", "backend2:143")
	am := &MockAffinityManager{backends: map[string]string{"alice@example.com:imap": "backend1:143"}}
	cm.SetAffinityManager(am)
	m.Set([]string{"backend1"})

	res, err := DetermineRoute(RouteParams{
		Ctx: context.Background(), Username: "alice@example.com", Protocol: "imap",
		ConnManager: cm, EnableAffinity: true, ProxyName: "test",
	})
	if err != nil {
		t.Fatalf("DetermineRoute: %v", err)
	}
	if res.PreferredAddr != "backend2:143" {
		t.Fatalf("routed to %q, want backend2:143", res.PreferredAddr)
	}
	if _, ok := am.GetBackend("alice@example.com", "imap"); ok {
		t.Fatal("affinity to the backend in maintenance was not deleted")
	}
}

func TestDetermineRoute_RemoteLookupRouteToMaintenanceBackendFallsBack(t *testing.T) {
	cm, m := newMaintenanceTestManager(t, "backend1:143", "backend2:143")
	m.Set([]string{"backend1"})

	ri := &UserRoutingInfo{ServerAddress: "backend1:143", IsRemoteLookupAccount: true, RemoteUseIDCommand: true}
	res, err := DetermineRoute(RouteParams{
		Ctx: context.Background(), Username: "bob@example.com", Protocol: "imap",
		IsRemoteLookupAccount: true, RoutingInfo: ri, ConnManager: cm, ProxyName: "test",
	})
	if err != nil {
		t.Fatalf("DetermineRoute: %v", err)
	}
	if res.IsRemoteLookupRoute {
		t.Fatal("a remote-lookup route to a backend in maintenance must not stay authoritative")
	}
	if res.PreferredAddr != "backend2:143" {
		t.Fatalf("routed to %q, want backend2:143", res.PreferredAddr)
	}
	if res.RoutingInfo.ServerAddress != "" || !res.RoutingInfo.AuthOnlyMode || !res.RoutingInfo.RemoteUseIDCommand {
		t.Fatalf("routing info = %+v, want an auth-only copy keeping the other fields", res.RoutingInfo)
	}
	if ri.ServerAddress != "backend1:143" {
		t.Fatal("the caller's routing info was mutated; it may be a shared cache entry")
	}
}

// acceptOn accepts and holds connections on ln, counting them, standing in for a backend.
func acceptOn(t *testing.T, ln net.Listener, accepted *atomic.Int32) {
	t.Helper()
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			t.Cleanup(func() { c.Close() })
		}
	}()
}

// listen starts a backend on 127.0.0.1 and returns its address.
func listen(t *testing.T) (addr string, accepted *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	accepted = &atomic.Int32{}
	acceptOn(t, ln, accepted)
	return ln.Addr().String(), accepted
}

// listenLocalhost starts a backend addressed as "localhost:<port>", listening on both
// loopback families so that a dial through either is counted, whatever "localhost"
// resolves to on this machine.
func listenLocalhost(t *testing.T) (addr string, accepted *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	accepted = &atomic.Int32{}
	acceptOn(t, ln, accepted)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if ln6, err := net.Listen("tcp", net.JoinHostPort("::1", port)); err == nil {
		acceptOn(t, ln6, accepted)
	}
	return net.JoinHostPort("localhost", port), accepted
}

func TestConnectWithProxy_NeverDialsBackendInMaintenance(t *testing.T) {
	// Two distinct backend hosts on one machine: "localhost" (drained) and "127.0.0.1".
	drained, drainedAccepts := listenLocalhost(t)
	live, _ := listen(t)

	cm, m := newMaintenanceTestManager(t, drained, live)
	m.Set([]string{"localhost"})

	// Preferred (affinity-style) and round-robin attempts alike land on the live backend.
	for i := 0; i < 6; i++ {
		preferred := ""
		if i%2 == 0 {
			preferred = drained
		}
		conn, addr, err := cm.ConnectWithProxy(context.Background(), preferred, "192.0.2.1", 1234, "192.0.2.2", 143, nil)
		if err != nil {
			t.Fatalf("ConnectWithProxy: %v", err)
		}
		conn.Close()
		if addr != live {
			t.Fatalf("connected to %q, want %q", addr, live)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := drainedAccepts.Load(); n != 0 {
		t.Fatalf("backend in maintenance accepted %d connections", n)
	}

	// Maintenance is not a failure: the backend keeps a clean record for when it returns.
	found := false
	for _, h := range cm.GetBackendHealthStatuses() {
		if h.Address != drained {
			continue
		}
		found = true
		if !h.IsHealthy || h.FailureCount != 0 {
			t.Fatalf("skipping a backend in maintenance recorded failures: %+v", h)
		}
		if !h.InMaintenance {
			t.Fatal("health status does not report the backend in maintenance")
		}
	}
	if !found {
		t.Fatal("backend in maintenance missing from health statuses")
	}
}

func TestConnectWithProxy_AllBackendsInMaintenanceFailsClosed(t *testing.T) {
	a, aAccepts := listen(t)
	cm, m := newMaintenanceTestManager(t, a)
	m.Set([]string{"127.0.0.1"})

	if conn, addr, err := cm.ConnectWithProxy(context.Background(), "", "192.0.2.1", 1234, "192.0.2.2", 143, nil); err == nil {
		conn.Close()
		t.Fatalf("connected to %q although every backend is in maintenance", addr)
	}
	time.Sleep(50 * time.Millisecond)
	if n := aAccepts.Load(); n != 0 {
		t.Fatalf("backend in maintenance accepted %d connections", n)
	}
}

// Run polls on its interval, bounds every poll with a deadline (a stuck query must not
// hold the poller), keeps maintenance through failures, and follows the list once it loads
// again.
func TestMaintenancePoller_RunFollowsTheList(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	hosts, loadErr := []string{"10.0.0.5"}, error(nil)
	noDeadline := false
	m := NewMaintenance()
	p := NewMaintenancePoller(m, func(ctx context.Context) ([]string, error) {
		if _, ok := ctx.Deadline(); !ok {
			mu.Lock()
			noDeadline = true
			mu.Unlock()
		}
		mu.Lock()
		defer mu.Unlock()
		return hosts, loadErr
	})
	go p.Run(ctx, 10*time.Millisecond)

	waitFor(t, func() bool { return m.Contains("10.0.0.5:143") })

	mu.Lock()
	hosts, loadErr = nil, errors.New("database unavailable")
	mu.Unlock()
	time.Sleep(50 * time.Millisecond) // several failed polls
	if !m.Contains("10.0.0.5:143") {
		t.Fatal("failed polls ended maintenance")
	}

	mu.Lock()
	hosts, loadErr = []string{"10.0.0.6"}, nil
	mu.Unlock()
	waitFor(t, func() bool { return m.Contains("10.0.0.6:143") && !m.Contains("10.0.0.5:143") })

	mu.Lock()
	defer mu.Unlock()
	if noDeadline {
		t.Fatal("a poll ran without a deadline")
	}
}

// userOn returns a user the consistent hash places on backend.
func userOn(t *testing.T, cm *ConnectionManager, backend string) string {
	t.Helper()
	for i := 0; i < 10000; i++ {
		u := fmt.Sprintf("user%d@example.com", i)
		if cm.GetBackendByConsistentHash(u) == backend {
			return u
		}
	}
	t.Fatalf("no user hashed to %s", backend)
	return ""
}

// Leaving maintenance: a user routed only by consistent hash goes back to the backend at
// the next login.
func TestDetermineRoute_BackAfterMaintenanceWithoutAffinity(t *testing.T) {
	cm, m := newMaintenanceTestManager(t, "backend1:143", "backend2:143")
	user := userOn(t, cm, "backend1:143")
	route := func() string {
		res, err := DetermineRoute(RouteParams{Ctx: context.Background(), Username: user, Protocol: "imap", ConnManager: cm, ProxyName: "test"})
		if err != nil {
			t.Fatalf("DetermineRoute: %v", err)
		}
		return res.PreferredAddr
	}

	m.Set([]string{"backend1"})
	if got := route(); got != "backend2:143" {
		t.Fatalf("in maintenance: routed to %q, want backend2:143", got)
	}
	m.Set(nil)
	if got := route(); got != "backend1:143" {
		t.Fatalf("after maintenance: routed to %q, want backend1:143", got)
	}
}

// Leaving maintenance with affinity: users moved during maintenance stay where they were
// moved (their affinity) instead of all returning at once; the backend gets new users.
func TestDetermineRoute_AffinityKeepsMovedUsersAfterMaintenance(t *testing.T) {
	cm, m := newMaintenanceTestManager(t, "backend1:143", "backend2:143")
	am := &MockAffinityManager{backends: map[string]string{}}
	cm.SetAffinityManager(am)
	moved := userOn(t, cm, "backend1:143")
	params := func(user string) RouteParams {
		return RouteParams{Ctx: context.Background(), Username: user, Protocol: "imap", ConnManager: cm, EnableAffinity: true, ProxyName: "test"}
	}

	m.Set([]string{"backend1"})
	res, err := DetermineRoute(params(moved))
	if err != nil || res.PreferredAddr != "backend2:143" {
		t.Fatalf("in maintenance: routed to %q (err %v), want backend2:143", res.PreferredAddr, err)
	}
	UpdateAffinityAfterConnection(params(moved), res.PreferredAddr, false) // the session connected there

	m.Set(nil)
	if res, _ := DetermineRoute(params(moved)); res.PreferredAddr != "backend2:143" {
		t.Fatalf("after maintenance a moved user went to %q; want backend2:143 (its affinity)", res.PreferredAddr)
	}

	// A user never moved (no affinity) whose hash is backend1 lands on it again.
	var fresh string
	for i := 0; i < 10000 && fresh == ""; i++ {
		if u := fmt.Sprintf("fresh%d@example.com", i); cm.GetBackendByConsistentHash(u) == "backend1:143" {
			fresh = u
		}
	}
	if res, _ := DetermineRoute(params(fresh)); res.PreferredAddr != "backend1:143" {
		t.Fatalf("after maintenance a new user went to %q, want backend1:143", res.PreferredAddr)
	}
}

func TestMaintenanceHosts_Sorted(t *testing.T) {
	m := NewMaintenance()
	m.Set([]string{"b.example.com", "a.example.com"})
	got := m.Hosts()
	if !sort.StringsAreSorted(got) || len(got) != 2 {
		t.Fatalf("Hosts() = %v, want 2 sorted hosts", got)
	}
}

// fakeResolver answers lookups from a table the test changes, and counts them.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]string
	lookups int
}

func (r *fakeResolver) set(name string, addrs ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers[name] = addrs
}

func (r *fakeResolver) lookup(_ context.Context, host string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups++
	if addrs, ok := r.answers[host]; ok && addrs != nil {
		return append([]string(nil), addrs...), nil
	}
	return nil, fmt.Errorf("lookup %s: no such host", host)
}

func (r *fakeResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lookups
}

// A route by name matches an entry made by address: the name is in maintenance if what it
// resolves to is. Names are resolved only while something is in maintenance, once each,
// and re-resolved by the poller, which keeps the last answer when a lookup fails.
func TestMaintenance_ContainsMatchesANameByItsAddresses(t *testing.T) {
	m := NewMaintenance()
	r := &fakeResolver{answers: map[string][]string{
		"storage2.example.com": {"10.0.0.2"},
		"storage3.example.com": {"10.0.0.3"},
	}}
	m.lookupHost = r.lookup

	m.Set(nil)
	if m.Contains("storage2.example.com:143") {
		t.Fatal("in maintenance with nothing in maintenance")
	}
	if r.count() != 0 {
		t.Fatalf("%d lookups with nothing in maintenance, want none", r.count())
	}

	m.Set([]string{"10.0.0.2", "10.0.0.3"})
	for _, addr := range []string{"storage2.example.com:143", "STORAGE2.example.com.:993", "storage3.example.com"} {
		if !m.Contains(addr) {
			t.Errorf("%s resolves to an address in maintenance but is not in it", addr)
		}
	}
	if m.Contains("unresolvable.example.com:143") {
		t.Error("a name that does not resolve is in maintenance")
	}
	lookups := r.count()
	m.Contains("storage2.example.com:143")
	if r.count() != lookups {
		t.Error("a name already resolved was looked up again")
	}

	// storage2 moves off the address in maintenance; storage3's lookup starts failing.
	r.set("storage2.example.com", "10.0.0.20")
	r.set("storage3.example.com")
	p := NewMaintenancePoller(m, func(context.Context) ([]string, error) { return []string{"10.0.0.2", "10.0.0.3"}, nil })
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if m.Contains("storage2.example.com:143") {
		t.Error("a name that moved off the address in maintenance is still in it after a poll")
	}
	if !m.Contains("storage3.example.com:143") {
		t.Error("a failed re-resolution dropped the name's last known address")
	}
}

// The review's reproduction: the pool ([::1]) in maintenance by address, and a
// remote-lookup route naming the same host "localhost". The route is routed as auth-only,
// nothing outside maintenance is left, and the connection is refused without a dial.
func TestConnectWithProxy_RouteByNameOfBackendInMaintenance(t *testing.T) {
	named, accepted := listenLocalhost(t)
	_, port, _ := net.SplitHostPort(named)
	if ln, err := net.Listen("tcp", "[::1]:0"); err != nil {
		t.Skip("no IPv6 loopback")
	} else {
		ln.Close()
	}
	cm, m := newMaintenanceTestManager(t, net.JoinHostPort("::1", port))
	m.Set([]string{"::1"})

	routing := &UserRoutingInfo{IsRemoteLookupAccount: true, ServerAddress: named}
	res, err := DetermineRoute(RouteParams{
		Ctx: context.Background(), Username: "alice@example.com", Protocol: "imap",
		IsRemoteLookupAccount: true, RoutingInfo: routing, ConnManager: cm, ProxyName: "test",
	})
	if err != nil {
		t.Fatalf("DetermineRoute: %v", err)
	}
	if res.IsRemoteLookupRoute {
		t.Fatalf("kept the remote-lookup route %q to a name of a backend in maintenance", res.PreferredAddr)
	}
	if conn, addr, err := cm.ConnectWithProxy(context.Background(), res.PreferredAddr, "192.0.2.1", 1234, "192.0.2.2", 143, res.RoutingInfo); err == nil {
		conn.Close()
		t.Fatalf("connected to %q with the whole pool in maintenance", addr)
	}
	// And handed the name directly, as a preferred address.
	if conn, addr, err := cm.ConnectWithProxy(context.Background(), named, "192.0.2.1", 1234, "192.0.2.2", 143, routing); err == nil {
		conn.Close()
		t.Fatalf("connected to %q, a name of a backend in maintenance", addr)
	}
	time.Sleep(50 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Fatalf("backend in maintenance accepted %d connections", n)
	}
}

// The dial itself refuses an address in maintenance, for a name routing could not match
// (here its lookup fails, while the dial's own resolution succeeds): nothing connects, and
// the refusal is no failure of the backend.
func TestConnectWithProxy_DialRefusesAddressInMaintenance(t *testing.T) {
	// The pool entry is the name itself, so both the preferred dial and the round-robin
	// one are refused by the dial alone.
	named, accepted := listenLocalhost(t)
	cm, m := newMaintenanceTestManager(t, named)
	m.lookupHost = (&fakeResolver{answers: map[string][]string{}}).lookup
	m.Set([]string{"127.0.0.1", "::1"})
	if m.Contains(named) {
		t.Fatal("test setup: routing must not match the name")
	}

	if conn, addr, err := cm.ConnectWithProxy(context.Background(), named, "192.0.2.1", 1234, "192.0.2.2", 143, nil); err == nil {
		conn.Close()
		t.Fatalf("connected to %q, which resolves to an address in maintenance", addr)
	}
	time.Sleep(50 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Fatalf("backend in maintenance accepted %d connections", n)
	}
	for _, h := range cm.GetBackendHealthStatuses() {
		if h.FailureCount != 0 || !h.IsHealthy {
			t.Fatalf("a refused dial counted against health: %+v", h)
		}
	}
}

// A set that was never read is not loaded, and contains nothing: routing is not changed by
// what is not known. Nil (maintenance not honored) counts as loaded.
func TestMaintenance_NotLoadedUntilFirstSet(t *testing.T) {
	m := NewMaintenance()
	if m.Loaded() {
		t.Fatal("loaded before the list was read")
	}
	if m.Contains("10.0.0.5:143") || m.Hosts() != nil {
		t.Fatal("a set never read contains something")
	}
	m.Set(nil)
	if !m.Loaded() {
		t.Fatal("not loaded after the list was read (empty)")
	}
	var notHonored *Maintenance
	if !notHonored.Loaded() {
		t.Fatal("nil maintenance must count as loaded")
	}
}

// Until the list is read, no backend is dialed — and routing is left alone meanwhile, so
// an affinity is not dropped over what is not known.
func TestConnectWithProxy_RefusesUntilMaintenanceLoaded(t *testing.T) {
	backend, accepted := listen(t)
	cm, err := NewConnectionManager([]string{backend}, 143, false, false, false, time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}
	m := NewMaintenance()
	cm.SetMaintenance(m)
	am := &MockAffinityManager{backends: map[string]string{"alice@example.com:imap": backend}}
	cm.SetAffinityManager(am)

	res, err := DetermineRoute(RouteParams{
		Ctx: context.Background(), Username: "alice@example.com", Protocol: "imap",
		ConnManager: cm, EnableAffinity: true, ProxyName: "test",
	})
	if err != nil {
		t.Fatalf("DetermineRoute: %v", err)
	}
	if res.PreferredAddr != backend || res.RoutingMethod != "affinity" {
		t.Fatalf("route = %q by %s, want the affinity to %q", res.PreferredAddr, res.RoutingMethod, backend)
	}
	if conn, _, err := cm.ConnectWithProxy(context.Background(), res.PreferredAddr, "192.0.2.1", 1234, "192.0.2.2", 143, nil); !errors.Is(err, errMaintenanceNotLoaded) {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("ConnectWithProxy before the list was read: %v, want errMaintenanceNotLoaded", err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Fatalf("backend accepted %d connections before the maintenance list was read", n)
	}
	if _, ok := am.GetBackend("alice@example.com", "imap"); !ok {
		t.Fatal("affinity dropped while the maintenance list was not read")
	}

	m.Set(nil)
	conn, addr, err := cm.ConnectWithProxy(context.Background(), res.PreferredAddr, "192.0.2.1", 1234, "192.0.2.2", 143, nil)
	if err != nil {
		t.Fatalf("ConnectWithProxy once the list was read: %v", err)
	}
	conn.Close()
	if addr != backend {
		t.Fatalf("connected to %q, want %q", addr, backend)
	}
}

// "Is any backend available" (the LMTP proxy's guard against bouncing a recipient it
// cannot verify) does not count a backend in maintenance, with or without health checks:
// with every backend drained it answers no, and the recipient gets a tempfail, not a 550.
func TestHasHealthyPoolBackends_BackendsInMaintenanceDoNotCount(t *testing.T) {
	for _, healthChecks := range []bool{true, false} {
		cm, err := NewConnectionManagerWithRoutingAndStartTLSAndHealthCheck(
			[]string{"10.0.0.5:24", "10.0.0.6:24"}, 24, false, false, false, false, time.Second, nil, "test", !healthChecks)
		if err != nil {
			t.Fatalf("NewConnectionManager: %v", err)
		}
		m := NewMaintenance()
		cm.SetMaintenance(m)
		m.Set([]string{"10.0.0.5"})
		if !cm.HasHealthyPoolBackends() {
			t.Fatalf("health checks %v: one backend still serves, but none counted", healthChecks)
		}
		m.Set([]string{"10.0.0.5", "10.0.0.6"})
		if cm.HasHealthyPoolBackends() {
			t.Fatalf("health checks %v: every backend in maintenance, yet one counted as available", healthChecks)
		}
	}
}

// A proxy's view of maintenance is visible in its metrics: how many hosts it honors, how
// often it failed to read the list (a proxy that never loaded it dials no backend), and
// how many sessions it closed on backends in maintenance.
func TestMaintenanceMetrics(t *testing.T) {
	m := NewMaintenance()
	var failing atomic.Bool
	failing.Store(true)
	p := NewMaintenancePoller(m, func(context.Context) ([]string, error) {
		if failing.Load() {
			return nil, errors.New("database unavailable")
		}
		return []string{"10.0.0.5", "10.0.0.6"}, nil
	})

	failures := testutil.ToFloat64(metrics.BackendMaintenancePollFailures)
	if err := p.Refresh(context.Background()); err == nil {
		t.Fatal("test setup: Refresh succeeded")
	}
	if got := testutil.ToFloat64(metrics.BackendMaintenancePollFailures); got != failures+1 {
		t.Fatalf("poll failures = %v after a failed read, want %v", got, failures+1)
	}

	failing.Store(false)
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := testutil.ToFloat64(metrics.BackendMaintenanceHosts); got != 2 {
		t.Fatalf("hosts in maintenance = %v, want 2", got)
	}

	closed := testutil.ToFloat64(metrics.BackendMaintenanceSessionsClosed.WithLabelValues("metrics-test"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var closes atomic.Int32
	StartSessionDrainer(ctx, m, 100, func() []DrainTarget {
		if closes.Load() > 0 {
			return nil
		}
		return []DrainTarget{{Backend: "10.0.0.5:143", Close: func() { closes.Add(1) }}}
	}, nil, "metrics-test")
	m.Set(m.Hosts())
	deadline := time.Now().Add(5 * time.Second)
	for testutil.ToFloat64(metrics.BackendMaintenanceSessionsClosed.WithLabelValues("metrics-test")) != closed+1 {
		if time.Now().After(deadline) {
			t.Fatalf("sessions closed = %v, want %v", testutil.ToFloat64(metrics.BackendMaintenanceSessionsClosed.WithLabelValues("metrics-test")), closed+1)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The remote lookup's backend settings are for the backend it named, and only that one.
func TestUserRoutingInfo_LookupRouted(t *testing.T) {
	pinned := &UserRoutingInfo{ServerAddress: "10.0.0.5:24", IsRemoteLookupAccount: true}
	authOnly := &UserRoutingInfo{IsRemoteLookupAccount: true, AuthOnlyMode: true}
	var none *UserRoutingInfo
	for _, c := range []struct {
		r    *UserRoutingInfo
		addr string
		want bool
	}{
		{pinned, "10.0.0.5:24", true},
		{pinned, "10.0.0.6:24", false}, // routed elsewhere (maintenance, failover)
		{authOnly, "10.0.0.5:24", false},
		{authOnly, "", false},
		{none, "10.0.0.5:24", false},
	} {
		if got := c.r.LookupRouted(c.addr); got != c.want {
			t.Errorf("%+v.LookupRouted(%q) = %v, want %v", c.r, c.addr, got, c.want)
		}
	}
}

// Names asked about during one maintenance window are forgotten once nothing is in
// maintenance, so the cache cannot grow across windows, and the next window resolves
// afresh.
func TestMaintenance_ForgetsNamesWhenEmpty(t *testing.T) {
	m := NewMaintenance()
	m.lookupHost = (&fakeResolver{answers: map[string][]string{"storage2.example.com": {"10.0.0.2"}}}).lookup
	m.Set([]string{"10.0.0.9"})
	m.Contains("storage2.example.com:143")
	m.Set(nil)
	m.namesMu.Lock()
	defer m.namesMu.Unlock()
	if len(m.names) != 0 {
		t.Fatalf("names kept after maintenance ended: %v", m.names)
	}
}

// A backend in maintenance by NAME whose first resolution (by the poller) fails is still
// matched: the pool knows the name it resolved each of its entries from. Otherwise the
// maintenance set would hold only the name, the pool only addresses, and the backend would
// be routed to and dialed.
func TestConnectWithProxy_NameInMaintenanceThatDoesNotResolveYet(t *testing.T) {
	named, accepted := listenLocalhost(t) // "localhost:<port>", resolved by the pool to an IP
	cm, m := newMaintenanceTestManager(t, named)
	if err := cm.ResolveAddresses(); err != nil {
		t.Fatalf("ResolveAddresses: %v", err)
	}
	m.lookupHost = (&fakeResolver{answers: map[string][]string{}}).lookup // maintenance DNS fails
	p := NewMaintenancePoller(m, func(context.Context) ([]string, error) { return []string{"localhost"}, nil })
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	if conn, addr, err := cm.ConnectWithProxy(context.Background(), "", "192.0.2.1", 1234, "192.0.2.2", 143, nil); err == nil {
		conn.Close()
		t.Fatalf("connected to %q, resolved by the pool from a name in maintenance", addr)
	}
	time.Sleep(50 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Fatalf("backend in maintenance accepted %d connections", n)
	}
	for _, h := range cm.GetBackendHealthStatuses() {
		if !h.InMaintenance {
			t.Fatalf("pool entry %s not reported in maintenance", h.Address)
		}
	}
}

// Change listeners run when the set of hosts changes, not on every poll.
func TestMaintenance_OnChangeRunsWhenTheSetChanges(t *testing.T) {
	m := NewMaintenance()
	var changes atomic.Int32
	m.OnChange(func() { changes.Add(1) })
	m.Set(nil)
	m.Set([]string{"10.0.0.5"})
	m.Set([]string{"10.0.0.5"})
	m.Set([]string{"10.0.0.5", "10.0.0.6"})
	m.Set(nil)
	m.Set(nil)
	if got := changes.Load(); got != 3 {
		t.Fatalf("change listeners ran %d times, want 3 (on, add, off)", got)
	}
}

// The drain asks the check it is given (the proxy server's InMaintenance, which knows the
// names its pool was resolved from), not only the maintenance list.
func TestSessionDrainer_UsesTheGivenMaintenanceCheck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewMaintenance()
	var closes atomic.Int32
	StartSessionDrainer(ctx, m, 100, func() []DrainTarget {
		return []DrainTarget{{Backend: "10.0.0.7:143", Close: func() { closes.Add(1) }}}
	}, func(addr string) bool { return addr == "10.0.0.7:143" }, "check-test")
	m.Set([]string{"storage7.example.com"}) // a name the list could not resolve
	deadline := time.Now().Add(5 * time.Second)
	for closes.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("session on a backend the given check reports in maintenance was not closed")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
