package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
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

func TestBackendRoutePreservesTCPHalfClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		io.ReadAll(conn)
		io.WriteString(conn, "final reply")
	}()
	cm, err := NewConnectionManagerWithRoutingAndStartTLSAndHealthCheck([]string{ln.Addr().String()}, 143, true, true, false, false, time.Second, nil, "half-close", true)
	if err != nil {
		t.Fatal(err)
	}
	conn, _, err := cm.ConnectWithProxy(context.Background(), ln.Addr().String(), "", 0, "", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	writer, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("backend connection no longer supports half-close")
	}
	if err := writer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(conn)
	if err != nil || string(data) != "final reply" {
		t.Fatalf("reply after half-close = %q, %v", data, err)
	}
}

// The configured hostname may resolve again between the pool refresh and the
// socket dial. The actual destination still needs the selected pool's authority.
func TestPinnedPoolHostnameCannotDialAnotherPoolsAddress(t *testing.T) {
	ln, err := net.Listen("tcp", ":0")
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
	port := ln.Addr().(*net.TCPAddr).Port
	name := net.JoinHostPort("localhost", fmt.Sprint(port))
	ips, err := net.LookupIP("localhost")
	if err != nil || len(ips) == 0 {
		t.Fatalf("localhost lookup: %v", err)
	}
	actual := net.JoinHostPort(ips[0].String(), fmt.Sprint(port))
	previous := net.JoinHostPort("127.0.0.2", fmt.Sprint(port))
	cm := newPoolsCM(t, []PoolSpec{
		{Name: "a", Backends: []string{name}},
		{Name: "b", Backends: []string{actual}},
	})
	cm.installResolvedAddrs([]string{previous, actual}, map[string][]string{name: {previous}, actual: {actual}})
	route, err := routeFor(t, cm, &UserRoutingInfo{ServerAddress: name, IsRemoteLookupAccount: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, _, err := cm.ConnectWithProxy(context.Background(), route.PreferredAddr, "", 0, "", 0, route.RoutingInfo)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatalf("pool A hostname resolved to and connected to pool B's %s", actual)
	}
}
