//go:build race

// Only the race detector sees what this test looks for, so it is built only with -race.

package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/adminapi"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// TestShutdownWhileAcceptingDoesNotRaceSessionDrain shuts each text-protocol
// server down just as it accepts a connection. The servers counted every
// session in a sync.WaitGroup that shutdown waits on, and the accept loop
// registered the new connection with no ordering against that Wait, which
// sync.WaitGroup forbids: "calls with a positive delta that occur when the
// counter is zero must happen before a Wait" (#560 for POP3, #615 for the
// proxies). Shutdown could also stop waiting before that session had started.
// The race detector reports the misuse.
func TestShutdownWhileAcceptingDoesNotRaceSessionDrain(t *testing.T) {
	servers := []struct {
		serverType string
		start      func(context.Context, *serverDependencies, config.ServerConfig, chan error)
		configure  func(*config.ServerConfig)
	}{
		{"imap", startDynamicIMAPServer, nil},
		{"pop3", startDynamicPOP3Server, nil},
		{"managesieve", startDynamicManageSieveServer, nil},
		{"imap_proxy", startDynamicIMAPProxyServer, withRemoteAddrs},
		{"pop3_proxy", startDynamicPOP3ProxyServer, withRemoteAddrs},
		{"managesieve_proxy", startDynamicManageSieveProxyServer, withRemoteAddrs},
		{"lmtp_proxy", startDynamicLMTPProxyServer, withRemoteAddrs},
	}
	for _, s := range servers {
		t.Run(s.serverType, func(t *testing.T) {
			// The window is narrow, so take it several times.
			for round := 0; round < 25 && !t.Failed(); round++ {
				sc := config.ServerConfig{Type: s.serverType, Name: s.serverType + "-drain"}
				if s.configure != nil {
					s.configure(&sc)
				}
				shutdownWhileAccepting(t, s.start, sc)
			}
		})
	}
}

// shutdownWhileAccepting starts sc on a free loopback port, connects, and shuts
// the server down at once, so the server accepts the connection as its
// shutdown begins.
func shutdownWhileAccepting(t *testing.T, start func(context.Context, *serverDependencies, config.ServerConfig, chan error), sc config.ServerConfig) {
	t.Helper()
	sc.Addr = freeLoopbackAddr(t)
	cfg := config.NewDefaultConfig()
	cfg.DynamicServers = []config.ServerConfig{sc}
	deps := &serverDependencies{
		storage:            &storage.S3Storage{},
		resilientDB:        &resilient.ResilientDatabase{},
		uploadWorker:       &uploader.UploadWorker{},
		cacheInstance:      &cache.Cache{},
		hostname:           "localhost",
		config:             cfg,
		serverManager:      &serverManager{},
		connectionTrackers: make(map[string]*server.ConnectionTracker),
		proxyServers:       make(map[string]adminapi.ProxyServer),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errChan := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		start(ctx, deps, sc, errChan)
	}()

	for deadline := time.Now().Add(5 * time.Second); ; {
		select {
		case err := <-errChan:
			t.Fatalf("%s server failed to start: %v", sc.Type, err)
		default:
		}
		if c, err := net.Dial("tcp", sc.Addr); err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s server did not listen on %s", sc.Type, sc.Addr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Let the probe's session end, so the next connection's registration
	// takes the session count from zero, and the accept loop wait in Accept.
	// The connection stays open: its session is still counted when shutdown
	// waits for the sessions.
	time.Sleep(20 * time.Millisecond)
	conn, err := net.Dial("tcp", sc.Addr)
	if err != nil {
		t.Fatalf("dial %s: %v", sc.Addr, err)
	}
	defer conn.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Errorf("%s server did not stop", sc.Type)
	}
}
