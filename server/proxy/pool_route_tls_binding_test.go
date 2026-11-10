package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"
)

func TestPoolSTARTTLSTrustStaysWithOriginalRoute(t *testing.T) {
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
	// An ownership change while reading a STARTTLS greeting must never select
	// B's CA. Restoring membership before the handshake must not rescue that
	// wrong trust snapshot either.
	cm.installResolvedAddrs([]string{other, target}, map[string][]string{nameA: {other}, nameB: {target}})
	cfg := cm.BackendStartTLSConfig(route.RoutingInfo, addr)
	if cfg == nil {
		t.Fatal("missing STARTTLS config")
	}
	installA()
	secure := tls.Client(conn, cfg)
	if err := secure.Handshake(); err == nil {
		t.Fatal("pool A's STARTTLS leg accepted a certificate issued by pool B's CA")
	}
}
