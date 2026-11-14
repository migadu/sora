package main

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/errors"
)

// config-proxy-only.toml is the example for a proxy-only node, one that runs without a
// database. It did not start while its remote_lookup url was plaintext http:// to a
// non-loopback host, which every proxy refuses when it is built (#809). Take it through
// what main does with a file: load it as the server does, the whole-file checks, the
// database decision, the services and the servers' start, and see every listener greet.
func TestProxyOnlyExampleStarts(t *testing.T) {
	cfg, err := readConfigFile("../../config-proxy-only.toml")
	if err != nil {
		t.Fatalf("load config-proxy-only.toml: %v", err)
	}
	for _, p := range cfg.Validate() {
		t.Errorf("config-proxy-only.toml: %s: %v", p.Section, p.Err)
	}
	// The example listens on fixed ports; the test moves every listener to a free one.
	for i := range cfg.DynamicServers {
		cfg.DynamicServers[i].Addr = freeLoopbackAddr(t)
	}
	servers := cfg.GetAllServers()
	if len(servers) == 0 {
		t.Fatal("config-proxy-only.toml enables no server")
	}
	for _, s := range servers {
		if serverNeedsDatabase(s) {
			t.Errorf("server %q (%s) needs the database, which the example does not configure", s.Name, s.Type)
		}
	}
	if t.Failed() {
		// initializeServices exits the process on these problems.
		t.FailNow()
	}

	ctx, cancel := context.WithCancel(context.Background())
	deps, err := initializeServices(ctx, cfg, errors.NewErrorHandler())
	if err != nil {
		cancel()
		t.Fatalf("initializeServices: %v", err)
	}
	errChan := startServers(ctx, deps)
	t.Cleanup(func() {
		cancel()
		done := make(chan struct{})
		go func() {
			deps.serverManager.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("servers did not stop")
		}
		deps.healthIntegration.Stop()
		if deps.affinityManager != nil {
			deps.affinityManager.Stop()
		}
		if deps.authCacheInstance != nil {
			deps.authCacheInstance.Close()
		}
	})

	for _, s := range servers {
		for deadline := time.Now().Add(5 * time.Second); ; {
			select {
			case err := <-errChan:
				t.Fatalf("config-proxy-only.toml: %v", err)
			default:
			}
			if c, err := net.Dial("tcp", s.Addr); err == nil {
				// Wait for the greeting, so the shutdown at cleanup does not overlap the
				// probe session's registration (#615).
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
					t.Errorf("server %q (%s): no greeting: %v", s.Name, s.Type, err)
				}
				c.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("server %q (%s) did not listen on %s", s.Name, s.Type, s.Addr)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}
