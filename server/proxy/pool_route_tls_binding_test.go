package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"
	"time"
)

func TestPoolSTARTTLSTrustStaysWithOriginalRoute(t *testing.T) {
	for _, withSocket := range []bool{false, true} {
		t.Run(fmt.Sprintf("socket=%v", withSocket), func(t *testing.T) { testPoolSTARTTLSTrust(t, withSocket) })
	}
}

func testPoolSTARTTLSTrust(t *testing.T, withSocket bool) {
	caA, caB := newTestCA(t), newTestCA(t)
	port := tlsBackendOnEveryAddress(t, caB.leaf(t, []string{"b.example"}, nil))
	target, other := fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("127.0.0.2:%d", port)
	nameA, nameB := fmt.Sprintf("a.example:%d", port), fmt.Sprintf("b.example:%d", port)
	cm := newPoolsCM(t, []PoolSpec{
		{Name: "a", Backends: []string{nameA}, Settings: BackendSettings{TLS: true, TLSUseStartTLS: true, TLSVerify: true, TLSCAFile: caA.file}},
		{Name: "b", Backends: []string{nameB}, Settings: BackendSettings{TLS: true, TLSUseStartTLS: true, TLSVerify: true, TLSCAFile: caB.file}},
	})
	installA := func() {
		cm.installResolvedAddrs([]string{target, other}, map[string][]string{nameA: {target}, nameB: {other}})
	}
	installA()
	route, err := routeFor(t, cm, &UserRoutingInfo{PoolName: "a"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, addr, err := cm.ConnectWithProxy(context.Background(), route.PreferredAddr, "", 0, "", 0, route.RoutingInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	// An ownership change while reading a STARTTLS greeting must never select
	// B's CA, including through the socket binding used by production proxies.
	cm.installResolvedAddrs([]string{other, target}, map[string][]string{nameA: {other}, nameB: {target}})
	cfg := cm.BackendStartTLSConfig(route.RoutingInfo, addr)
	if withSocket {
		cfg = cm.BackendStartTLSConfig(route.RoutingInfo, addr, conn)
	}
	if cfg == nil {
		t.Fatal("missing STARTTLS config")
	}
	secure := tls.Client(conn, cfg)
	if err := secure.Handshake(); err == nil {
		t.Fatal("pool A's STARTTLS leg accepted a certificate issued by pool B's CA")
	}
}

func TestPoolTLSRechecksOwnershipDuringHandshake(t *testing.T) {
	for _, verify := range []bool{false, true} {
		t.Run(fmt.Sprintf("verify=%v", verify), func(t *testing.T) {
			ca := newTestCA(t)
			refresh := make(chan func(), 1)
			port := tlsBackendOnEveryAddress(t, ca.leaf(t, []string{"a.example"}, nil), func(*tls.ClientHelloInfo) (*tls.Config, error) {
				(<-refresh)()
				return nil, nil
			})
			target, other := fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("127.0.0.2:%d", port)
			nameA, nameB := fmt.Sprintf("a.example:%d", port), fmt.Sprintf("b.example:%d", port)
			cm := newPoolsCM(t, []PoolSpec{
				{Name: "a", Backends: []string{nameA}, Settings: BackendSettings{TLS: true, TLSUseStartTLS: true, TLSVerify: verify, TLSCAFile: ca.file}},
				{Name: "b", Backends: []string{nameB}},
			})
			cm.installResolvedAddrs([]string{target, other}, map[string][]string{nameA: {target}, nameB: {other}})
			route, err := routeFor(t, cm, &UserRoutingInfo{PoolName: "a"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			conn, addr, err := cm.ConnectWithProxy(context.Background(), route.PreferredAddr, "", 0, "", 0, route.RoutingInfo)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			cfg := cm.BackendStartTLSConfig(route.RoutingInfo, addr, conn)
			// The server refreshes ownership after receiving ClientHello, while
			// the client is waiting to validate its certificate.
			refresh <- func() {
				cm.installResolvedAddrs([]string{other, target}, map[string][]string{nameA: {other}, nameB: {target}})
			}
			if err := tls.Client(conn, cfg).Handshake(); err == nil {
				t.Fatal("TLS accepted a destination no longer owned by the route's pool")
			}
		})
	}
}
