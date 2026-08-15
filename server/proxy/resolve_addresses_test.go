package proxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeDNS answers A and AAAA queries for one name, from an address set the test
// can change between resolutions. Everything else is answered NOERROR with no
// records, so the resolver moves on to the next name in its search list.
type fakeDNS struct {
	conn *net.UDPConn
	name string // FQDN, with the trailing dot

	mu  sync.Mutex
	ips []net.IP // empty = the name has no address records
}

// startFakeDNS starts a DNS responder on loopback and points net.DefaultResolver
// at it for the duration of the test.
func startFakeDNS(t *testing.T, name string, ips ...net.IP) *fakeDNS {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("failed to start fake DNS server: %v", err)
	}

	f := &fakeDNS{conn: conn, name: name, ips: ips}
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.serve()
	}()

	serverAddr := conn.LocalAddr().String()
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", serverAddr)
		},
	}

	t.Cleanup(func() {
		net.DefaultResolver = previous
		conn.Close()
		<-done
	})

	return f
}

func (f *fakeDNS) setIPs(ips ...net.IP) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ips = ips
}

func (f *fakeDNS) currentIPs() []net.IP {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ips
}

func (f *fakeDNS) serve() {
	buf := make([]byte, 512)
	for {
		n, addr, err := f.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		resp, err := f.answer(buf[:n])
		if err != nil {
			continue
		}
		if _, err := f.conn.WriteTo(resp, addr); err != nil {
			return
		}
	}
}

func (f *fakeDNS) answer(query []byte) ([]byte, error) {
	var p dnsmessage.Parser
	header, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	question, err := p.Question()
	if err != nil {
		return nil, err
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 header.ID,
		Response:           true,
		Authoritative:      true,
		RecursionAvailable: true,
	})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(question); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}

	if question.Name.String() == f.name {
		for _, ip := range f.currentIPs() {
			var err error
			switch v4 := ip.To4(); {
			case v4 != nil && question.Type == dnsmessage.TypeA:
				var a [4]byte
				copy(a[:], v4)
				err = b.AResource(dnsmessage.ResourceHeader{
					Name:  question.Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   1,
				}, dnsmessage.AResource{A: a})
			case v4 == nil && question.Type == dnsmessage.TypeAAAA:
				var aaaa [16]byte
				copy(aaaa[:], ip.To16())
				err = b.AAAAResource(dnsmessage.ResourceHeader{
					Name:  question.Name,
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
					TTL:   1,
				}, dnsmessage.AAAAResource{AAAA: aaaa})
			}
			if err != nil {
				return nil, err
			}
		}
	}

	return b.Finish()
}

// TestResolveAddressesPicksUpAChangedBackendAddress covers PROXY-4(a): a backend
// whose address changes while the proxy runs (VM recreated, DNS failover). The
// first resolution rewrites the pool to the IPs it produced, so a later
// resolution that starts from that pool looks up IP literals and returns them
// unchanged — the proxy keeps dialling the address the backend no longer has.
func TestResolveAddressesPicksUpAChangedBackendAddress(t *testing.T) {
	dns := startFakeDNS(t, "backend.test.", net.IPv4(10, 0, 0, 1))

	cm, err := NewConnectionManager([]string{"backend.test:143"}, 143, false, false, false, time.Second)
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}

	if err := cm.ResolveAddresses(); err != nil {
		t.Fatalf("initial resolution failed: %v", err)
	}
	if got := cm.remoteAddrs; len(got) != 1 || got[0] != "10.0.0.1:143" {
		t.Fatalf("pool after the initial resolution = %v, want [10.0.0.1:143]", got)
	}

	dns.setIPs(net.IPv4(10, 0, 0, 2))

	if err := cm.ResolveAddresses(); err != nil {
		t.Fatalf("re-resolution failed: %v", err)
	}
	if got := cm.remoteAddrs; len(got) != 1 || got[0] != "10.0.0.2:143" {
		t.Errorf("pool after the backend's address changed = %v, want [10.0.0.2:143]", got)
	}
	if got := cm.consistentHash.GetBackend("user@example.com"); got != "10.0.0.2:143" {
		t.Errorf("consistent hash still routes to %q, want 10.0.0.2:143", got)
	}
	if !cm.IsBackendHealthy("10.0.0.2:143") {
		t.Error("the new address has no health entry")
	}
}

// TestStalePoolIsReResolvedByARoutingDecision covers the other half of
// PROXY-4(a): nothing calls ResolveAddresses after startup, so a resolution that
// stands still is a proxy dialling a dead address until it is restarted.
func TestStalePoolIsReResolvedByARoutingDecision(t *testing.T) {
	dns := startFakeDNS(t, "backend.test.", net.IPv4(10, 0, 0, 1))

	cm, err := NewConnectionManager([]string{"backend.test:143"}, 143, false, false, false, time.Second)
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}
	if err := cm.ResolveAddresses(); err != nil {
		t.Fatalf("initial resolution failed: %v", err)
	}

	dns.setIPs(net.IPv4(10, 0, 0, 2))

	// A pool this fresh is used as it is: routing must not pay for a DNS lookup.
	resolvedAt := cm.resolvedAt.Load()
	cm.GetBackendByConsistentHash("user@example.com")
	if cm.resolvedAt.Load() != resolvedAt {
		t.Fatal("a pool resolved moments ago was re-resolved")
	}

	cm.resolvedAt.Store(time.Now().Add(-2 * DefaultResolveRefreshInterval).UnixNano())
	cm.GetBackendByConsistentHash("user@example.com")

	deadline := time.Now().Add(5 * time.Second)
	for !cm.HasBackend("10.0.0.2:143") {
		if time.Now().After(deadline) {
			t.Fatal("a routing decision on a stale pool did not re-resolve it")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cm.HasBackend("10.0.0.1:143") {
		t.Error("the address the backend no longer has is still in the pool")
	}
}

// TestResolveRefreshIntervalIsConfigurable pins both ends of remote_dns_refresh: a
// shorter interval re-resolves sooner, and 0 pins the pool to the startup resolution
// (the escape hatch back to the pre-re-resolution behavior).
func TestResolveRefreshIntervalIsConfigurable(t *testing.T) {
	newManager := func(t *testing.T, refresh time.Duration) *ConnectionManager {
		t.Helper()
		cm, err := NewConnectionManager([]string{"backend.test:143"}, 143, false, false, false, time.Second)
		if err != nil {
			t.Fatalf("failed to create connection manager: %v", err)
		}
		cm.SetResolveRefreshInterval(refresh)
		if err := cm.ResolveAddresses(); err != nil {
			t.Fatalf("initial resolution failed: %v", err)
		}
		return cm
	}

	t.Run("shorter interval re-resolves sooner", func(t *testing.T) {
		dns := startFakeDNS(t, "backend.test.", net.IPv4(10, 0, 0, 1))
		cm := newManager(t, 10*time.Millisecond)

		dns.setIPs(net.IPv4(10, 0, 0, 2))

		deadline := time.Now().Add(5 * time.Second)
		for !cm.HasBackend("10.0.0.2:143") {
			if time.Now().After(deadline) {
				t.Fatal("a 10ms refresh interval never re-resolved the pool")
			}
			cm.GetBackendByConsistentHash("user@example.com")
			time.Sleep(10 * time.Millisecond)
		}
	})

	t.Run("zero pins the pool to the startup resolution", func(t *testing.T) {
		dns := startFakeDNS(t, "backend.test.", net.IPv4(10, 0, 0, 1))
		cm := newManager(t, 0)

		dns.setIPs(net.IPv4(10, 0, 0, 2))
		cm.resolvedAt.Store(time.Now().Add(-24 * time.Hour).UnixNano())

		for i := 0; i < 10; i++ {
			cm.GetBackendByConsistentHash("user@example.com")
			time.Sleep(10 * time.Millisecond)
		}
		if !cm.HasBackend("10.0.0.1:143") || cm.HasBackend("10.0.0.2:143") {
			t.Errorf("remote_dns_refresh=0 still re-resolved the pool: %v", cm.remoteAddrs)
		}
	})
}

// TestUnresolvableBackendKeepsItsLastKnownAddress covers what re-resolution must
// not do: a name that stops resolving keeps the addresses that last worked,
// rather than dropping the backend out of the pool over a transient SERVFAIL.
func TestUnresolvableBackendKeepsItsLastKnownAddress(t *testing.T) {
	dns := startFakeDNS(t, "backend.test.", net.IPv4(10, 0, 0, 1))

	cm, err := NewConnectionManager([]string{"backend.test:143"}, 143, false, false, false, time.Second)
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}
	if err := cm.ResolveAddresses(); err != nil {
		t.Fatalf("initial resolution failed: %v", err)
	}

	dns.setIPs() // the name stops resolving

	if err := cm.ResolveAddresses(); err != nil {
		t.Fatalf("re-resolution failed: %v", err)
	}
	if got := cm.remoteAddrs; len(got) != 1 || got[0] != "10.0.0.1:143" {
		t.Errorf("pool after the name stopped resolving = %v, want the last known [10.0.0.1:143]", got)
	}
}

// TestResolveAddressesGivesADualStackBackendOnePoolEntry covers PROXY-4(b): the
// A and AAAA records of one name are two routes to the same machine, so
// admitting both gives that machine two health entries and twice its share of
// the consistent hash ring.
func TestResolveAddressesGivesADualStackBackendOnePoolEntry(t *testing.T) {
	startFakeDNS(t, "backend.test.", net.IPv4(10, 0, 0, 1), net.ParseIP("2001:db8::1"))

	cm, err := NewConnectionManager([]string{"backend.test:143"}, 143, false, false, false, time.Second)
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}
	if err := cm.ResolveAddresses(); err != nil {
		t.Fatalf("resolution failed: %v", err)
	}

	if got := len(cm.remoteAddrs); got != 1 {
		t.Errorf("one dual-stack backend became %d pool entries (%v), want 1", got, cm.remoteAddrs)
	}
	if got := len(cm.backendHealth); got != 1 {
		t.Errorf("one dual-stack backend has %d health entries, want 1", got)
	}
	if got := cm.consistentHash.Size(); got != 1 {
		t.Errorf("one dual-stack backend takes %d places in the hash ring, want 1", got)
	}

	// Several addresses of ONE family are distinct machines and must stay distinct.
	startFakeDNS(t, "pool.test.", net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2))

	multi, err := NewConnectionManager([]string{"pool.test:143"}, 143, false, false, false, time.Second)
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}
	if err := multi.ResolveAddresses(); err != nil {
		t.Fatalf("resolution failed: %v", err)
	}
	if got := multi.remoteAddrs; len(got) != 2 {
		t.Errorf("two A records became %d pool entries (%v), want 2", len(got), got)
	}
}
