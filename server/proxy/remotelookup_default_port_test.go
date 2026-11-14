package proxy_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/imapproxy"
	"github.com/migadu/sora/server/lmtpproxy"
	"github.com/migadu/sora/server/managesieveproxy"
	"github.com/migadu/sora/server/pop3proxy"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/userapiproxy"
)

// TestRemoteLookupServerWithoutPortGetsTheProxysPort: a lookup answer whose "server"
// has no port is dialed at [server.remote_lookup] remote_port when set, otherwise at
// the proxy's own remote_port (what a port-less pool or remote_addrs backend gets),
// otherwise at the protocol's standard port. It used to be 143 on every proxy, so
// POP3, ManageSieve and LMTP dialed the backend's IMAP port. A bare IPv6 address is
// one host and gets the port as well.
func TestRemoteLookupServerWithoutPortGetsTheProxysPort(t *testing.T) {
	var answer atomic.Value
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"address": "anna@example.com",
			"server":  answer.Load().(string),
		})
	}))
	defer lookup.Close()

	// newProxy builds the named proxy with remote lookup on and returns its lookup client.
	newProxy := func(t *testing.T, protocol string, serverPort int, lookupPort any) proxy.UserRoutingLookup {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		rl := &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", RemotePort: lookupPort}
		rdb := &resilient.ResilientDatabase{}
		pool := []string{"192.0.2.1:9"} // a flat backend list is required; never dialed here
		var cm *proxy.ConnectionManager
		switch protocol {
		case "imap":
			s, err := imapproxy.New(ctx, rdb, "localhost", imapproxy.ServerOptions{Name: "t", Addr: "127.0.0.1:0", RemoteAddrs: pool, RemotePort: serverPort, RemoteLookup: rl, ConnectTimeout: time.Second})
			if err != nil {
				t.Fatalf("imapproxy.New: %v", err)
			}
			cm = s.GetConnectionManager()
		case "pop3":
			s, err := pop3proxy.New(ctx, "localhost", "127.0.0.1:0", rdb, pop3proxy.POP3ProxyServerOptions{Name: "t", RemoteAddrs: pool, RemotePort: serverPort, RemoteLookup: rl, ConnectTimeout: time.Second})
			if err != nil {
				t.Fatalf("pop3proxy.New: %v", err)
			}
			cm = s.GetConnectionManager()
		case "managesieve":
			s, err := managesieveproxy.New(ctx, rdb, "localhost", managesieveproxy.ServerOptions{Name: "t", Addr: "127.0.0.1:0", RemoteAddrs: pool, RemotePort: serverPort, RemoteLookup: rl, ConnectTimeout: time.Second})
			if err != nil {
				t.Fatalf("managesieveproxy.New: %v", err)
			}
			cm = s.GetConnectionManager()
		case "lmtp":
			s, err := lmtpproxy.New(ctx, rdb, "localhost", lmtpproxy.ServerOptions{Name: "t", Addr: "127.0.0.1:0", RemoteAddrs: pool, RemotePort: serverPort, RemoteLookup: rl, ConnectTimeout: time.Second})
			if err != nil {
				t.Fatalf("lmtpproxy.New: %v", err)
			}
			cm = s.GetConnectionManager()
		case "userapi":
			s, err := userapiproxy.New(ctx, rdb, userapiproxy.ServerOptions{Name: "t", Addr: "127.0.0.1:0", RemoteAddrs: pool, RemotePort: serverPort, RemoteLookup: rl, JWTSecret: strings.Repeat("x", 32)})
			if err != nil {
				t.Fatalf("userapiproxy.New: %v", err)
			}
			cm = s.GetConnectionManager()
		}
		if cm == nil || cm.GetRoutingLookup() == nil {
			t.Fatalf("%s proxy has no remote lookup client", protocol)
		}
		return cm.GetRoutingLookup()
	}

	tests := []struct {
		name       string
		protocol   string
		serverPort int
		lookupPort any
		server     string
		want       string
	}{
		// The proxy's own remote_port.
		{"imap server remote_port", "imap", 1143, nil, "backend1.example.com", "backend1.example.com:1143"},
		{"pop3 server remote_port", "pop3", 1110, nil, "backend1.example.com", "backend1.example.com:1110"},
		{"managesieve server remote_port", "managesieve", 14190, nil, "backend1.example.com", "backend1.example.com:14190"},
		{"lmtp server remote_port", "lmtp", 1024, nil, "backend1.example.com", "backend1.example.com:1024"},
		{"userapi server remote_port", "userapi", 8081, nil, "backend1.example.com", "backend1.example.com:8081"},

		// No remote_port anywhere: the protocol's standard port.
		{"imap default", "imap", 0, nil, "backend1.example.com", "backend1.example.com:143"},
		{"pop3 default", "pop3", 0, nil, "backend1.example.com", "backend1.example.com:110"},
		{"managesieve default", "managesieve", 0, nil, "backend1.example.com", "backend1.example.com:4190"},
		{"lmtp default", "lmtp", 0, nil, "backend1.example.com", "backend1.example.com:24"},

		// [server.remote_lookup] remote_port is the most specific setting.
		{"pop3 lookup remote_port wins", "pop3", 1110, 2110, "backend1.example.com", "backend1.example.com:2110"},

		// An explicit port is kept.
		{"pop3 explicit port", "pop3", 1110, nil, "backend1.example.com:995", "backend1.example.com:995"},

		// A bare IPv6 address is a host without a port.
		{"pop3 bare IPv6", "pop3", 0, nil, "2001:db8::21", "[2001:db8::21]:110"},
		{"lmtp bare IPv6 server remote_port", "lmtp", 1024, nil, "2001:db8::21", "[2001:db8::21]:1024"},
		{"imap bracketed IPv6 with port", "imap", 0, nil, "[2001:db8::21]:993", "[2001:db8::21]:993"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			answer.Store(tt.server)
			client := newProxy(t, tt.protocol, tt.serverPort, tt.lookupPort)
			info, result, err := client.LookupUserRouteWithOptions(context.Background(), "anna@example.com", "", true)
			if err != nil || result != proxy.AuthSuccess || info == nil {
				t.Fatalf("lookup: result=%v err=%v info=%+v", result, err, info)
			}
			if info.ServerAddress != tt.want {
				t.Errorf("ServerAddress = %q, want %q", info.ServerAddress, tt.want)
			}
		})
	}
}
