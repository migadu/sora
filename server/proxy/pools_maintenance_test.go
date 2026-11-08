package proxy

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// maintenanceOn attaches a loaded maintenance set holding hosts to cm.
func maintenanceOn(t *testing.T, cm *ConnectionManager, hosts ...string) {
	t.Helper()
	m := NewMaintenance()
	m.Set(hosts)
	cm.SetMaintenance(m)
}

func routeUser(cm *ConnectionManager, user string, info *UserRoutingInfo) (RouteResult, error) {
	return DetermineRoute(RouteParams{
		Ctx:                   context.Background(),
		Username:              user,
		Protocol:              "imap",
		IsRemoteLookupAccount: true,
		RoutingInfo:           info,
		ConnManager:           cm,
		ProxyName:             "test",
	})
}

// A lookup pin to a backend in maintenance is routed among that backend's own pool
// siblings, with that pool's settings, never into the default pool where the account
// does not live. The pin itself is left intact for when maintenance ends.
func TestPools_LookupPinInMaintenanceStaysInItsPool(t *testing.T) {
	cm := newPoolsCM(t, testPoolSpecs()) // sora0 is the default, sora1 = 10.0.1.1, 10.0.1.2
	maintenanceOn(t, cm, "10.0.1.1")

	for i := 0; i < 50; i++ {
		user := fmt.Sprintf("user%d@example.com", i)
		pin := &UserRoutingInfo{ServerAddress: "10.0.1.1:143", IsRemoteLookupAccount: true}
		res, err := routeUser(cm, user, pin)
		if err != nil {
			t.Fatalf("%s: route around the pin in maintenance: %v", user, err)
		}
		if res.Pool != "sora1" || res.PreferredAddr != "10.0.1.2:143" {
			t.Fatalf("%s: routed to %q in pool %q, want the pinned backend's sibling 10.0.1.2:143 in sora1", user, res.PreferredAddr, res.Pool)
		}
		if res.IsRemoteLookupRoute {
			t.Fatalf("%s: a detour reported as the lookup's own route", user)
		}
		got := res.RoutingInfo
		if !got.UsesRouteSettings(res.PreferredAddr) || !got.RemoteTLS || !got.RemoteUseXCLIENT || got.RemoteUseIDCommand {
			t.Fatalf("%s: detour does not carry sora1's settings: %+v", user, got)
		}
		if pin.ServerAddress != "10.0.1.1:143" || pin.PoolName != "" {
			t.Fatalf("%s: the pin was edited in place (it may be a shared cache entry): %+v", user, pin)
		}
	}
}

// A pin to a backend in maintenance that belongs to no pool has no siblings: it goes to
// the default pool when there is one, and is refused when there is none.
func TestPools_LookupPinInMaintenanceOutsideEveryPool(t *testing.T) {
	cm := newPoolsCM(t, testPoolSpecs())
	maintenanceOn(t, cm, "10.9.9.9")
	res, err := routeUser(cm, "user@example.com", &UserRoutingInfo{ServerAddress: "10.9.9.9:143", IsRemoteLookupAccount: true})
	if err != nil || res.Pool != "sora0" {
		t.Fatalf("with a default pool: pool %q, err %v; want sora0", res.Pool, err)
	}

	specs := testPoolSpecs()
	specs[0].Default = false
	cm = newPoolsCM(t, specs)
	maintenanceOn(t, cm, "10.9.9.9")
	_, err = routeUser(cm, "user@example.com", &UserRoutingInfo{ServerAddress: "10.9.9.9:143", IsRemoteLookupAccount: true})
	if !errors.Is(err, ErrNoDefaultPool) {
		t.Fatalf("without a default pool: err %v, want ErrNoDefaultPool", err)
	}
}

// When every member of the pinned backend's pool is in maintenance, the user is refused
// rather than spilled into another pool.
func TestPools_LookupPinInMaintenanceWholePoolInMaintenance(t *testing.T) {
	cm := newPoolsCM(t, testPoolSpecs())
	maintenanceOn(t, cm, "10.0.1.1", "10.0.1.2")
	res, err := routeUser(cm, "user@example.com", &UserRoutingInfo{ServerAddress: "10.0.1.1:143", IsRemoteLookupAccount: true})
	if err != nil {
		t.Fatalf("DetermineRoute: %v", err)
	}
	if res.Pool != "sora1" || res.PreferredAddr != "" {
		t.Fatalf("routed to %q in pool %q, want no preferred backend in sora1", res.PreferredAddr, res.Pool)
	}
	if _, addr, err := cm.ConnectWithProxy(context.Background(), res.PreferredAddr, "", 0, "", 0, res.RoutingInfo); err == nil {
		t.Fatalf("connected to %q while every backend of the user's pool is in maintenance", addr)
	}
}

// PoolOfBackend matches a member as configured (with or without the default port) and
// names no pool for a stranger or on a flat-list manager.
func TestPools_PoolOfBackend(t *testing.T) {
	cm := newPoolsCM(t, testPoolSpecs())
	for addr, want := range map[string]string{
		"10.0.1.1:143": "sora1",
		"10.0.1.1":     "sora1",
		"10.0.0.2:143": "sora0",
		"10.0.2.1":     "dovecot1",
		"10.0.1.1:993": "",
		"10.9.9.9:143": "",
		"":             "",
	} {
		if got := cm.PoolOfBackend(addr); got != want {
			t.Errorf("PoolOfBackend(%q) = %q, want %q", addr, got, want)
		}
	}
	flat, err := NewConnectionManager([]string{"10.0.0.1:143"}, 143, false, false, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := flat.PoolOfBackend("10.0.0.1:143"); got != "" {
		t.Errorf("flat list: PoolOfBackend = %q, want \"\"", got)
	}
}

// The Remote* fields of a route are the backend-leg settings for the backend the lookup
// named, and for any backend of a pool-confined route; for nothing else.
func TestUserRoutingInfo_UsesRouteSettings(t *testing.T) {
	cases := []struct {
		name       string
		r          *UserRoutingInfo
		addr       string
		want, pool bool
	}{
		{"nil", nil, "10.0.0.1:143", false, false},
		{"pin, its backend", &UserRoutingInfo{ServerAddress: "10.0.0.1:143"}, "10.0.0.1:143", true, false},
		{"pin, another backend", &UserRoutingInfo{ServerAddress: "10.0.0.1:143"}, "10.0.0.2:143", false, false},
		{"pin wins over a pool name", &UserRoutingInfo{ServerAddress: "10.0.0.1:143", PoolName: "sora1"}, "10.0.0.2:143", false, false},
		{"pool route, any member", &UserRoutingInfo{PoolName: "sora1"}, "10.0.1.2:143", true, true},
		{"auth-only, no pool", &UserRoutingInfo{AuthOnlyMode: true}, "10.0.0.1:143", false, false},
	}
	for _, c := range cases {
		if got := c.r.UsesRouteSettings(c.addr); got != c.want {
			t.Errorf("%s: UsesRouteSettings = %v, want %v", c.name, got, c.want)
		}
		if got := c.r.PoolRouted(); got != c.pool {
			t.Errorf("%s: PoolRouted = %v, want %v", c.name, got, c.pool)
		}
	}
}
