package config

import (
	"fmt"
	"testing"
)

func TestForwardingSkipPolicyDecodesAsExplicitOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled_%t", enabled), func(t *testing.T) {
			line := ""
			if enabled {
				line = "remote_skip_forwarding_with_proxy_protocol = true\n"
			}
			cfg, err := loadPoolsConfig(t, `[[pool]]
name="primary"
backends=["127.0.0.1:143"]
default=true
`+line+`
[[server]]
type="imap_proxy"
name="policy"
addr=":1143"
`+line+`
[server.remote_lookup]
enabled=true
url="http://127.0.0.1/lookup?email=$email"
`+line)
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.DynamicServers) != 1 || len(cfg.Pools) != 1 {
				t.Fatalf("unexpected config: %+v", cfg)
			}
			s := cfg.DynamicServers[0]
			if s.RemoteSkipForwardingWithProxyProtocol != enabled || s.RemoteLookup == nil || s.RemoteLookup.RemoteSkipForwardingWithProxyProtocol != enabled || cfg.Pools[0].RemoteSkipForwardingWithProxyProtocol != enabled {
				t.Fatalf("server, lookup and pool must independently default tofalse and retain explicittrue: server=%+v lookup=%+v pool=%+v", s, s.RemoteLookup, cfg.Pools[0])
			}
		})
	}
}
