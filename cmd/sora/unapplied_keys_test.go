package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/health"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/adminapi"
	"github.com/migadu/sora/server/userapiproxy"
)

// User API affinity now follows enable_affinity, including the startup warning
// when no cluster affinity manager is available.
func TestProxiesWithAffinityIncludesUserAPIProxy(t *testing.T) {
	disabled := false
	cfg := config.Config{DynamicServers: []config.ServerConfig{
		{Type: "user_api_proxy", Name: "api-affinity", EnableAffinity: true},
		{Type: "user_api_proxy", Name: "api-no-affinity"},
		{Type: "user_api_proxy", Name: "api-disabled", EnableAffinity: true, Enabled: &disabled},
	}}
	if names := proxiesWithAffinity(cfg); len(names) != 1 || names[0] != "api-affinity" {
		t.Fatalf("proxies needing the no-manager warning = %v, want [api-affinity]", names)
	}
}

// The LMTP backend's command_timeout is its idle timeout (#290). It was never passed,
// so the server always used its built-in 5 minutes.
func TestBuildLMTPServerOptions_CommandTimeoutIsTheIdleTimeout(t *testing.T) {
	deps := &serverDependencies{}
	tests := []struct {
		name     string
		timeouts *config.ServerTimeoutsConfig
		want     time.Duration
	}{
		{"absent", nil, 5 * time.Minute},
		{"set", &config.ServerTimeoutsConfig{CommandTimeout: "12m"}, 12 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := buildLMTPServerOptions(deps, config.ServerConfig{Type: "lmtp", Name: "lmtp", Addr: "127.0.0.1:24", Timeouts: tt.timeouts})
			if opts.IdleTimeout != tt.want {
				t.Errorf("IdleTimeout = %v, want %v", opts.IdleTimeout, tt.want)
			}
		})
	}
}

// unappliedKeysDeps is what a proxy's start function needs on a node without a database.
func unappliedKeysDeps(cfg config.Config) *serverDependencies {
	return &serverDependencies{
		config:             cfg,
		hostname:           "mail.example.com",
		serverManager:      &serverManager{},
		connectionTrackers: make(map[string]*server.ConnectionTracker),
		proxyServers:       make(map[string]adminapi.ProxyServer),
		healthIntegration:  health.NewHealthIntegration(nil),
	}
}

// startUnappliedKeysProxy runs a proxy's start function and returns once it is
// listening, with the server it registered under key and its address.
func startUnappliedKeysProxy(t *testing.T, deps *serverDependencies, start func(context.Context, *serverDependencies, config.ServerConfig, chan error), serverCfg config.ServerConfig, key string) (adminapi.ProxyServer, string) {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverCfg.Addr = probe.Addr().String()
	probe.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	go start(ctx, deps, serverCfg, errChan)
	t.Cleanup(func() {
		cancel()
		deps.serverManager.Wait()
	})

	for deadline := time.Now().Add(5 * time.Second); ; {
		select {
		case err := <-errChan:
			t.Fatalf("%s: %v", key, err)
		default:
		}
		if conn, err := net.DialTimeout("tcp", serverCfg.Addr, 200*time.Millisecond); err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not start listening on %s", key, serverCfg.Addr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	srv, ok := deps.proxyServersSnapshot()[key]
	if !ok {
		t.Fatalf("%s is not registered", key)
	}
	return srv, serverCfg.Addr
}

// remote_tls_ca_file in a proxy's [[server]] block is what its backends' certificates
// are verified against (#290). Only the POP3 proxy loaded it: on the IMAP, ManageSieve,
// LMTP and User API proxies a backend signed by a private CA failed verification.
func TestProxies_VerifyBackendsAgainstRemoteTLSCAFile(t *testing.T) {
	backend := httptest.NewUnstartedServer(http.NotFoundHandler())
	backend.StartTLS()
	t.Cleanup(backend.Close)
	backendAddr := backend.Listener.Addr().String()
	caFile := filepath.Join(t.TempDir(), "backend-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		serverType string
		key        string
		start      func(context.Context, *serverDependencies, config.ServerConfig, chan error)
	}{
		{"imap_proxy", "IMAP-", startDynamicIMAPProxyServer},
		{"pop3_proxy", "POP3-", startDynamicPOP3ProxyServer},
		{"managesieve_proxy", "ManageSieve-", startDynamicManageSieveProxyServer},
		{"lmtp_proxy", "LMTP-", startDynamicLMTPProxyServer},
		{"user_api_proxy", "UserAPI-", startDynamicUserAPIProxyServer},
	}
	for _, tt := range tests {
		t.Run(tt.serverType, func(t *testing.T) {
			healthChecks := false
			serverCfg := config.ServerConfig{
				Type:               tt.serverType,
				Name:               "ca-290",
				RemoteAddrs:        []string{backendAddr},
				RemoteTLS:          true,
				RemoteTLSVerify:    true,
				RemoteTLSCAFile:    caFile,
				RemoteHealthChecks: &healthChecks,
				JWTSecret:          "a-jwt-secret-of-at-least-32-bytes!!",
			}
			cfg := config.NewDefaultConfig()
			cfg.Servers.TrustedNetworks = nil
			srv, _ := startUnappliedKeysProxy(t, unappliedKeysDeps(cfg), tt.start, serverCfg, tt.key+serverCfg.Name)

			tlsCfg := srv.GetConnectionManager().BackendClientTLS(true, backendAddr)
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", backendAddr, tlsCfg)
			if err != nil {
				t.Fatalf("backend signed by the remote_tls_ca_file CA: %v", err)
			}
			conn.Close()
		})
	}
}

// enable_affinity on a user_api_proxy decides whether it reads and writes cluster
// affinity (#290), as it does on every other proxy. The proxy was always given the
// node's affinity manager.
func TestUserAPIProxy_EnableAffinity(t *testing.T) {
	const (
		user   = "user@example.com"
		secret = "a-jwt-secret-of-at-least-32-bytes!!"
	)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"mailboxes":[]}`))
	}))
	t.Cleanup(backend.Close)
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, userapiproxy.JWTClaims{Email: user, AccountID: 42,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}

	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			mgr, err := cluster.New(config.ClusterConfig{
				Enabled: true, Addr: "127.0.0.1:0", NodeID: "userapi-affinity-290",
				SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = mgr.Shutdown() })
			affinity := server.NewAffinityManager(mgr, true, time.Hour, time.Hour)
			t.Cleanup(affinity.Stop)

			cfg := config.NewDefaultConfig()
			cfg.Servers.TrustedNetworks = nil
			deps := unappliedKeysDeps(cfg)
			deps.clusterManager = mgr
			deps.affinityManager = affinity

			healthChecks := false
			serverCfg := config.ServerConfig{
				Type:               "user_api_proxy",
				Name:               "user-api-proxy",
				RemoteAddrs:        []string{backend.Listener.Addr().String()},
				RemoteHealthChecks: &healthChecks,
				JWTSecret:          secret,
				EnableAffinity:     enabled,
			}
			_, addr := startUnappliedKeysProxy(t, deps, startDynamicUserAPIProxyServer, serverCfg, "UserAPI-user-api-proxy")

			req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/user/mailboxes", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET /user/mailboxes through the proxy: %s", resp.Status)
			}

			if _, found := affinity.GetBackend(user, "userapi"); found != enabled {
				t.Errorf("enable_affinity = %v: affinity written = %v", enabled, found)
			}
		})
	}
}

// allowed_origins in a user_api_proxy's [[server]] block is the CORS policy of the
// responses the proxy writes itself (#377): a 401 for a token it refuses has to carry
// the headers a backend's own 401 would, or a browser page cannot read it.
func TestUserAPIProxy_AllowedOrigins(t *testing.T) {
	const origin = "https://app.example.com"
	cfg := config.NewDefaultConfig()
	cfg.Servers.TrustedNetworks = nil
	healthChecks := false
	serverCfg := config.ServerConfig{
		Type:               "user_api_proxy",
		Name:               "user-api-proxy-cors",
		RemoteAddrs:        []string{"127.0.0.1:1"}, // never dialed: the token is refused first
		RemoteHealthChecks: &healthChecks,
		JWTSecret:          "a-jwt-secret-of-at-least-32-bytes!!",
		AllowedOrigins:     []string{origin},
	}
	_, addr := startUnappliedKeysProxy(t, unappliedKeysDeps(cfg), startDynamicUserAPIProxyServer, serverCfg, "UserAPI-"+serverCfg.Name)

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/user/mailboxes", nil)
	req.Header.Set("Origin", origin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /user/mailboxes without a token: %s, want 401", resp.Status)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, origin)
	}
}
