package main

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/health"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/adminapi"
)

// TestProxyRegistersRemoteLookupHealthChecks: every proxy that resolves users through
// [server.remote_lookup] registers the lookup endpoint's health check and its circuit
// breaker's under the server's name, so a lookup outage shows up in the health data.
// The user_api_proxy used to create its lookup client without registering either (#463).
func TestProxyRegistersRemoteLookupHealthChecks(t *testing.T) {
	proxies := map[string]struct {
		start  func(context.Context, *serverDependencies, config.ServerConfig, chan error)
		greets bool // sends a greeting line on connect
	}{
		"imap_proxy":        {startDynamicIMAPProxyServer, true},
		"pop3_proxy":        {startDynamicPOP3ProxyServer, true},
		"managesieve_proxy": {startDynamicManageSieveProxyServer, true},
		"lmtp_proxy":        {startDynamicLMTPProxyServer, true},
		"user_api_proxy":    {startDynamicUserAPIProxyServer, false},
	}
	for serverType, p := range proxies {
		t.Run(serverType, func(t *testing.T) {
			healthChecks := false
			sc := config.ServerConfig{
				Type: serverType,
				Name: serverType + "-lookup",
				Addr: freeLoopbackAddr(t),
				// Neither the backend nor the lookup API is dialed: the test only
				// starts the proxy.
				RemoteAddrs:        []string{"192.0.2.20:1"},
				RemoteHealthChecks: &healthChecks,
				RemoteLookup:       &config.RemoteLookupConfig{Enabled: true, URL: "http://127.0.0.1:9/lookup?email=$email"},
				JWTSecret:          "test-jwt-secret-0123456789abcdef",
			}

			cfg := config.NewDefaultConfig()
			cfg.DynamicServers = []config.ServerConfig{sc}
			deps := &serverDependencies{
				config:             cfg,
				hostname:           "localhost",
				serverManager:      &serverManager{},
				connectionTrackers: make(map[string]*server.ConnectionTracker),
				proxyServers:       make(map[string]adminapi.ProxyServer),
				healthIntegration:  health.NewHealthIntegration(nil),
			}

			// As in main: the monitor runs before the servers start.
			ctx, cancel := context.WithCancel(context.Background())
			deps.healthIntegration.Start(ctx)
			errChan := make(chan error, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				p.start(ctx, deps, sc, errChan)
			}()
			t.Cleanup(func() {
				cancel()
				deps.healthIntegration.Stop()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Errorf("%s did not stop", serverType)
				}
			})

			// Each proxy registers its checks before it starts listening.
			for deadline := time.Now().Add(5 * time.Second); ; {
				select {
				case err := <-errChan:
					t.Fatalf("%s failed to start: %v", serverType, err)
				default:
				}
				if c, err := net.Dial("tcp", sc.Addr); err == nil {
					if p.greets {
						// The greeting comes from the session the probe opened:
						// waiting for it keeps the shutdown at cleanup from
						// overlapping that session's registration (#615).
						_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
						_, _ = bufio.NewReader(c).ReadString('\n')
					}
					c.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("%s did not listen on %s", serverType, sc.Addr)
				}
				time.Sleep(10 * time.Millisecond)
			}

			monitor := deps.healthIntegration.GetMonitor()
			for _, name := range []string{
				"remotelookup_http_" + sc.Name,
				"circuit_breaker_remotelookup_http_" + sc.Name,
			} {
				if _, ok := monitor.GetCheckStatus(name); !ok {
					t.Errorf("%s with remote_lookup enabled registered no %q health check", serverType, name)
				}
			}
		})
	}
}
