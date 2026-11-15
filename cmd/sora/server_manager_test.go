package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

const serverManagerTestSecret = "0123456789abcdef0123456789abcdef"

func configureServerManagerTestServer(sc *config.ServerConfig) {
	switch sc.Type {
	case "imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy":
		withRemoteAddrs(sc)
	case "user_api_proxy":
		withRemoteAddrs(sc)
		sc.JWTSecret = serverManagerTestSecret
	case "http_admin_api":
		sc.APIKey = serverManagerTestSecret
	case "http_user_api":
		sc.JWTSecret = serverManagerTestSecret
	}
}

// main waits for the servers with serverManager.Wait once ctx is done, and then
// closes the database, cache and affinity store under them. A shutdown signal
// during start-up makes that the moment startServers returns. Each server
// counted itself with Add from its own start goroutine, with no ordering against
// that Wait, which sync.WaitGroup forbids: "calls with a positive delta that
// occur when the counter is zero must happen before a Wait" (#769). Wait
// returned while the servers were still starting; for http_admin_api and
// http_user_api, whose start functions returned after launching a detached
// goroutine, Wait did not wait for them to stop at all.
func TestShutdownDuringStartUpWaitsForEveryServer(t *testing.T) {
	groups := []struct {
		name  string
		types []string
	}{
		{
			name:  "all",
			types: []string{"imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy", "user_api_proxy", "http_admin_api", "http_user_api"},
		},
		{
			name:  "http_apis",
			types: []string{"http_admin_api", "http_user_api"},
		},
	}
	for _, g := range groups {
		t.Run(g.name, func(t *testing.T) {
			for round := 0; round < 5 && !t.Failed(); round++ {
				cfg := config.NewDefaultConfig()
				var addrs []string
				for _, serverType := range g.types {
					sc := config.ServerConfig{Type: serverType, Name: serverType + "-startup-shutdown", Addr: freeLoopbackAddr(t)}
					configureServerManagerTestServer(&sc)
					cfg.DynamicServers = append(cfg.DynamicServers, sc)
					addrs = append(addrs, sc.Addr)
				}
				deps := unappliedKeysDeps(cfg)

				ctx, cancel := context.WithCancel(context.Background())
				errChan := startServers(ctx, deps)
				// The shutdown signal, once every server listens, so that Wait is
				// reached while the servers still run; a shutdown before they listen is
				// TestShutdownBeforeServersListenStopsThem.
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

				if ctx.Err() == nil {
					cancel()
					t.Fatalf("round %d: Wait returned before shutdown was requested", round)
				}

				// Each of these servers registers for reload as it starts, and its start
				// goroutine settles it on return in any case: none may be left unsettled
				// once Wait has returned.
				select {
				case <-deps.serversRegistered():
				default:
					t.Fatalf("round %d: Wait returned while servers were still starting", round)
				}
				for _, addr := range addrs {
					if c, err := net.Dial("tcp", addr); err == nil {
						c.Close()
						t.Fatalf("round %d: %s still accepts connections after Wait returned", round, addr)
					}
				}
				select {
				case err := <-errChan:
					t.Fatalf("round %d: server failed: %v", round, err)
				default:
				}
			}
		})
	}
}

// A shutdown signal during start-up reaches each server's Stop or Close from
// the watcher its start function runs on ctx, and that watcher races the
// server's Start. The IMAP, ManageSieve and LMTP proxies and the LMTP backend
// went on accepting on a listener created after it, so Wait never returned and
// main waited out its server timeout (#823); User API proxy, Admin API and User
// API also bound their listeners without checking ctx, and Admin/User API ran
// outside serverManager.Go so Wait returned before they even bound.
func TestShutdownBeforeServersListenStopsThem(t *testing.T) {
	groups := []struct {
		name  string
		types []string
	}{
		{
			name:  "all",
			types: []string{"imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy", "user_api_proxy", "http_admin_api", "http_user_api", "lmtp"},
		},
		{
			name:  "http_apis",
			types: []string{"http_admin_api", "http_user_api"},
		},
	}
	for _, g := range groups {
		t.Run(g.name, func(t *testing.T) {
			for round := 0; round < 5 && !t.Failed(); round++ {
				cfg := config.NewDefaultConfig()
				var addrs []string
				for _, serverType := range g.types {
					sc := config.ServerConfig{Type: serverType, Name: serverType + "-early-shutdown", Addr: freeLoopbackAddr(t)}
					configureServerManagerTestServer(&sc)
					cfg.DynamicServers = append(cfg.DynamicServers, sc)
					addrs = append(addrs, sc.Addr)
				}
				deps := unappliedKeysDeps(cfg)
				deps.storage = &storage.S3Storage{}
				deps.uploadWorker = &uploader.UploadWorker{}

				ctx, cancel := context.WithCancel(context.Background())
				errChan := startServers(ctx, deps)
				cancel()

				done := make(chan struct{})
				go func() {
					deps.serverManager.Wait() // as main does once ctx is done
					close(done)
				}()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatalf("round %d: servers still running 5s after a shutdown during start-up", round)
				}
				for _, addr := range addrs {
					if c, err := net.Dial("tcp", addr); err == nil {
						c.Close()
						t.Fatalf("round %d: %s still accepts connections after shutdown", round, addr)
					}
				}
				select {
				case err := <-errChan:
					t.Fatalf("round %d: server failed: %v", round, err)
				default:
				}
			}
		})
	}
}
