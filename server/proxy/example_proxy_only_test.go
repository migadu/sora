package proxy

import (
	"testing"

	"github.com/migadu/sora/config"
)

// config-proxy-only.toml starts a proxy-only node: the configuration checks pass and
// every remote_lookup it enables initializes as its proxy does when it is built. Its
// lookup url was plaintext http:// to a non-loopback host, which the proxy refuses,
// so the example did not start (#809).
func TestProxyOnlyExampleRemoteLookupInitializes(t *testing.T) {
	var cfg config.Config
	if err := config.LoadConfigFromFile("../../config-proxy-only.toml", &cfg); err != nil {
		t.Fatalf("load config-proxy-only.toml: %v", err)
	}
	for _, p := range cfg.Validate() {
		t.Errorf("config-proxy-only.toml: %s: %v", p.Section, p.Err)
	}

	protocols := map[string]string{
		"imap_proxy":        "imap",
		"pop3_proxy":        "pop3",
		"managesieve_proxy": "managesieve",
		"lmtp_proxy":        "lmtp",
		"user_api_proxy":    "userapi",
	}
	enabled := 0
	for _, s := range cfg.GetAllServers() {
		if s.RemoteLookup == nil || !s.RemoteLookup.Enabled {
			continue
		}
		enabled++
		protocol, ok := protocols[s.Type]
		if !ok {
			t.Errorf("server %q: remote_lookup on non-proxy type %q", s.Name, s.Type)
			continue
		}
		remotePort, err := s.GetRemotePort()
		if err != nil {
			t.Errorf("server %q: remote_port: %v", s.Name, err)
			continue
		}
		lookup, err := InitializeRemoteLookup(protocol, s.RemoteLookup, remotePort)
		if err != nil {
			t.Errorf("server %q: %v", s.Name, err)
			continue
		}
		lookup.Close()
	}
	if enabled == 0 {
		t.Fatal("config-proxy-only.toml enables no remote_lookup")
	}
}
