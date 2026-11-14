//go:build race

// Only the race detector sees what this test looks for, so it is built only with -race.

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
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

type shutdownHandshakeConn struct {
	net.Conn
	received chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (c *shutdownHandshakeConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.once.Do(func() { close(c.received) })
		<-c.release // Hold the client before it can finish the handshake.
	}
	return n, err
}

// An accepted connection is counted before its TLS handshake, but may not yet
// appear in the server's active-session map. Shutdown must close that socket
// rather than wait for the handshake's ten-second deadline.
func TestShutdownClosesAcceptedTLSHandshake(t *testing.T) {
	for _, srv := range []struct {
		name  string
		start func(context.Context, *serverDependencies, config.ServerConfig, chan error)
	}{
		{"imap", startDynamicIMAPServer},
		{"pop3", startDynamicPOP3Server},
		{"managesieve", startDynamicManageSieveServer},
		{"imap_proxy", startDynamicIMAPProxyServer},
		{"pop3_proxy", startDynamicPOP3ProxyServer},
		{"managesieve_proxy", startDynamicManageSieveProxyServer},
		{"lmtp_proxy", startDynamicLMTPProxyServer},
	} {
		t.Run(srv.name, func(t *testing.T) {
			sc := config.ServerConfig{
				Type: srv.name, Name: srv.name + "-tls-drain", Addr: freeLoopbackAddr(t),
				TLS: true, TLSCertFile: "../../testdata/sora.crt", TLSKeyFile: "../../testdata/sora.key",
			}
			withRemoteAddrs(&sc)
			cfg := config.NewDefaultConfig()
			cfg.Servers.TrustedNetworks = []string{"127.0.0.0/8"}
			cfg.DynamicServers = []config.ServerConfig{sc}
			deps := &serverDependencies{
				storage: &storage.S3Storage{}, resilientDB: &resilient.ResilientDatabase{},
				uploadWorker: &uploader.UploadWorker{}, cacheInstance: &cache.Cache{},
				hostname: "localhost", config: cfg, serverManager: &serverManager{},
				connectionTrackers: make(map[string]*server.ConnectionTracker),
				proxyServers:       make(map[string]adminapi.ProxyServer),
			}
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			errc := make(chan error, 1)
			go srv.start(ctx, deps, sc, errc)
			var raw net.Conn
			for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				select {
				case err := <-errc:
					t.Fatalf("start: %v", err)
				default:
				}
				var err error
				raw, err = net.Dial("tcp", sc.Addr)
				if err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("server did not listen: %v", err)
				}
			}
			gate := &shutdownHandshakeConn{Conn: raw, received: make(chan struct{}), release: make(chan struct{})}
			handshakeDone := make(chan struct{})
			t.Cleanup(func() {
				raw.Close()
				close(gate.release)
				select {
				case <-handshakeDone:
				case <-time.After(2 * time.Second):
					t.Error("client handshake goroutine did not stop")
				}
			})
			client := tls.Client(gate, &tls.Config{InsecureSkipVerify: true})
			go func() { defer close(handshakeDone); _ = client.Handshake() }()
			select {
			case <-gate.received:
			case <-time.After(3 * time.Second):
				t.Fatal("server did not begin the TLS handshake")
			}
			cancel()
			// The gated TLS reader has stopped using the socket; drain any
			// remaining server handshake records and require a prompt EOF.
			raw.SetReadDeadline(time.Now().Add(4 * time.Second))
			if _, err := io.Copy(io.Discard, raw); err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					t.Fatalf("shutdown left the accepted handshake socket open: %v", err)
				}
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
