package proxy

import (
	"net"
	"strconv"
	"testing"

	"github.com/migadu/sora/config"
)

func TestPools_BareIPv6RetainsEveryAddressGroup(t *testing.T) {
	for _, host := range []string{"2001:db8::10:20", "::1:143", "2001:db8:0:0:0:0:10:20"} {
		for _, port := range []int{143, 993, 4190} {
			cfg := &config.Config{Pools: []config.PoolConfig{{Name: "ipv6", Backends: []string{host}, Default: true}}}
			if err := cfg.ValidatePools(); err != nil {
				t.Fatal(err)
			}
			cm, err := NewConnectionManagerWithPools(PoolSpecsFromConfig(cfg.Pools), port, 0, nil, "ipv6", true)
			if err != nil {
				t.Fatal(err)
			}
			if err := cm.ResolveAddresses(); err != nil {
				t.Fatal(err)
			}
			want := net.JoinHostPort(net.ParseIP(host).String(), strconv.Itoa(port))
			if !cm.PoolHasBackend("ipv6", want) {
				t.Fatalf("host %s, port %d: got %v; want %s", host, port, cm.remoteAddrs, want)
			}
		}
	}
}
