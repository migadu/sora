package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// main waits for the servers with serverManager.Wait once ctx is done, and then
// closes the database, cache and affinity store under them. A shutdown signal
// during start-up makes that the moment startServers returns. Each server
// counted itself with Add from its own start goroutine, with no ordering against
// that Wait, which sync.WaitGroup forbids: "calls with a positive delta that
// occur when the counter is zero must happen before a Wait" (#769). Wait
// returned while the servers were still starting.
func TestShutdownDuringStartUpWaitsForEveryServer(t *testing.T) {
	for round := 0; round < 5 && !t.Failed(); round++ {
		cfg := config.NewDefaultConfig()
		var addrs []string
		for _, serverType := range []string{"imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy"} {
			sc := config.ServerConfig{Type: serverType, Name: serverType + "-startup-shutdown", Addr: freeLoopbackAddr(t)}
			withRemoteAddrs(&sc)
			cfg.DynamicServers = append(cfg.DynamicServers, sc)
			addrs = append(addrs, sc.Addr)
		}
		deps := unappliedKeysDeps(cfg)

		ctx, cancel := context.WithCancel(context.Background())
		errChan := startServers(ctx, deps)
		// The shutdown signal, once every server listens: a proxy stopped before
		// its listener exists keeps accepting (#823), which is not what this tests.
		go func() {
			defer cancel()
			for _, addr := range addrs {
				for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
					if c, err := net.Dial("tcp", addr); err == nil {
						c.Close()
						break
					}
				}
			}
		}()
		deps.serverManager.Wait() // as main does once ctx is done

		// Each of these servers registers for reload as it starts, and its start
		// goroutine settles it on return in any case: none may be left unsettled
		// once Wait has returned.
		select {
		case <-deps.serversRegistered():
		default:
			t.Fatalf("round %d: Wait returned while servers were still starting", round)
		}
		select {
		case err := <-errChan:
			t.Fatalf("round %d: server failed: %v", round, err)
		default:
		}
	}
}
