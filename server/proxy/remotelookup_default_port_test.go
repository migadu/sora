package proxy_test

import (
	"context"
	"encoding/json"
	"fmt"
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
		{"pop3 lookup remote_port string", "pop3", 1110, "2110", "backend1.example.com", "backend1.example.com:2110"},

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

// TestRemoteLookupServerWithoutPortImplicitTLSPort: with nothing configured, a port-less
// lookup server is dialed at the protocol's standard port for the backend leg the lookup
// configures. Implicit TLS (remote_tls without remote_tls_use_starttls) has its own
// registered ports for IMAP and POP3 (RFC 8314 §3.1 "pop3s" 995, §3.2 "imaps" 993); the
// plaintext port there makes the proxy start a TLS handshake against a plaintext greeting.
// STARTTLS runs on the plaintext port, and ManageSieve and LMTP have no other port.
func TestRemoteLookupServerWithoutPortImplicitTLSPort(t *testing.T) {
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"address": "anna@example.com", "server": "backend1.example.com"})
	}))
	defer lookup.Close()

	tests := []struct {
		protocol      string
		tls, starttls bool
		want          string
	}{
		{"imap", true, false, "backend1.example.com:993"},
		{"pop3", true, false, "backend1.example.com:995"},
		{"imap", true, true, "backend1.example.com:143"},
		{"pop3", true, true, "backend1.example.com:110"},
		{"managesieve", true, false, "backend1.example.com:4190"},
		{"managesieve", true, true, "backend1.example.com:4190"},
		{"lmtp", true, false, "backend1.example.com:24"},
		{"lmtp", true, true, "backend1.example.com:24"},
	}
	for _, tt := range tests {
		name := tt.protocol + " implicit TLS"
		if tt.starttls {
			name = tt.protocol + " STARTTLS"
		}
		t.Run(name, func(t *testing.T) {
			client, err := proxy.InitializeRemoteLookup(tt.protocol, &config.RemoteLookupConfig{
				Enabled:              true,
				URL:                  lookup.URL + "/lookup?email=$email",
				RemoteTLS:            tt.tls,
				RemoteTLSUseStartTLS: tt.starttls,
			}, 0)
			if err != nil {
				t.Fatalf("InitializeRemoteLookup: %v", err)
			}
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

// TestInitializeRemoteLookupRejectsInvalidRemotePort: an unparsable or wrongly typed
// [server.remote_lookup] remote_port used to be dropped with a Debug log (the backend was
// dialed at a fallback port), and a negative or out-of-range number was used as given
// (-1 left the address port-less, 70000 was dialed). ServerConfig.Validate refuses such a
// config before any proxy is built; this is the constructor's own check behind it (with
// lookup_local_users = true a proxy carries on without the lookup when it fails).
func TestInitializeRemoteLookupRejectsInvalidRemotePort(t *testing.T) {
	for _, port := range []any{"1993x", "-1", "70000", -1, int64(-1), 70000, int64(70000), int64(4294969299), 1993.5, true} {
		t.Run(fmt.Sprintf("%T %v", port, port), func(t *testing.T) {
			client, err := proxy.InitializeRemoteLookup("imap", &config.RemoteLookupConfig{
				Enabled:    true,
				URL:        "http://127.0.0.1:8080/lookup?email=$email",
				RemotePort: port,
			}, 0)
			if err == nil {
				t.Fatalf("InitializeRemoteLookup accepted remote_port %#v (client %T), want an error", port, client)
			}
			if !strings.Contains(err.Error(), "remote_port") {
				t.Errorf("error = %q, want it to name remote_port", err)
			}
		})
	}
}
