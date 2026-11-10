package proxy

import (
	"context"
	"fmt"
	"net"
	"testing"
)

func TestPoolRouteRefusesAddressReassignedDuringDNSRefresh(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
	}()
	target := ln.Addr().String()
	port := ln.Addr().(*net.TCPAddr).Port
	other := fmt.Sprintf("127.0.0.2:%d", port)
	nameA, nameB := fmt.Sprintf("a.example:%d", port), fmt.Sprintf("b.example:%d", port)
	cm := newPoolsCM(t, []PoolSpec{
		{Name: "a", Backends: []string{nameA}},
		{Name: "b", Backends: []string{nameB}},
	})
	cm.installResolvedAddrs([]string{target, other}, map[string][]string{nameA: {target}, nameB: {other}})
	route, err := routeFor(t, cm, &UserRoutingInfo{PoolName: "a"}, nil)
	if err != nil || route.PreferredAddr != target {
		t.Fatalf("initial route = %+v, %v", route, err)
	}
	cm.installResolvedAddrs([]string{other, target}, map[string][]string{nameA: {other}, nameB: {target}})
	conn, actual, err := cm.ConnectWithProxy(context.Background(), route.PreferredAddr, "", 0, "", 0, route.RoutingInfo)
	if conn != nil {
		conn.Close()
	}
	if err == nil && actual == target {
		t.Fatalf("pool A route connected to pool B address %s after DNS ownership changed", actual)
	}
}
