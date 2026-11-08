package pop3proxy

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
)

// SIGHUP runs ReloadConfig on its own goroutine while sessions run. Two configs that
// differ in every setting the POP3 proxy reloads, alternated.
var reloadRaceConfigs = []config.ServerConfig{
	{
		Name: "reload", Type: "pop3_proxy",
		MasterSASLUsername: "master", MasterSASLPassword: "secret-b",
		AuthIdleTimeout: "90s", Debug: true,
		Limits:   &config.ServerLimitsConfig{MaxAuthErrors: 3},
		Timeouts: &config.ServerTimeoutsConfig{CommandTimeout: "20m", AbsoluteSessionTimeout: "2h", MinBytesPerMinute: 512},
	},
	{
		Name: "reload", Type: "pop3_proxy",
		MasterSASLUsername: "master", MasterSASLPassword: "secret-a",
		AuthIdleTimeout: "2m",
		Timeouts:        &config.ServerTimeoutsConfig{CommandTimeout: "25m", AbsoluteSessionTimeout: "3h"},
	},
}

func newReloadTestProxy(t *testing.T, remote string, opts POP3ProxyServerOptions) (*POP3ProxyServer, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	opts.Name = "reload"
	opts.RemoteAddrs = []string{remote}
	opts.RemotePort = 110
	opts.ConnectTimeout = time.Second
	opts.MaxConnections = 100
	opts.RemoteLookup = &config.RemoteLookupConfig{}
	srv, err := New(ctx, "localhost", addr, &resilient.ResilientDatabase{}, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, addr
}

func startReloadTestProxy(t *testing.T, srv *POP3ProxyServer, addr string) {
	t.Helper()
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Stop() })
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// New sessions log (debug) and are set up while a reload replaces their settings.
func TestReloadConfig_DuringNewSessions(t *testing.T) {
	srv, addr := newReloadTestProxy(t, "127.0.0.1:110", POP3ProxyServerOptions{CommandTimeout: 10 * time.Minute})
	startReloadTestProxy(t, srv, addr)

	reloadWhile(t, srv.ReloadConfig, reloadRaceConfigs, func() {
		for i := 0; i < 20; i++ {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			c.SetDeadline(time.Now().Add(3 * time.Second))
			r := bufio.NewReader(c)
			if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
				t.Errorf("greeting: %q %v", line, err)
			}
			c.Write([]byte("QUIT\r\n"))
			_, _ = r.ReadString('\n')
			c.Close()
		}
	})
}

// The proxy logs in to the backend with the master SASL credentials a reload replaces.
func TestReloadConfig_DuringBackendLogin(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() { // a backend that greets and accepts every AUTH
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.Write([]byte("+OK ready\r\n"))
				r := bufio.NewReader(c)
				for {
					if _, err := r.ReadString('\n'); err != nil {
						return
					}
					c.Write([]byte("+OK authenticated\r\n"))
				}
			}()
		}
	}()
	srv, _ := newReloadTestProxy(t, backend.Addr().String(), POP3ProxyServerOptions{MasterSASLUsername: "master", MasterSASLPassword: "secret-a"})

	client, peer := net.Pipe() // only logged from
	defer client.Close()
	defer peer.Close()
	reloadWhile(t, srv.ReloadConfig, reloadRaceConfigs, func() {
		for i := 0; i < 20; i++ {
			s := &POP3ProxySession{server: srv, clientConn: client, ctx: context.Background(), username: "user@example.com"}
			if err := s.connectToBackend(); err != nil {
				t.Fatalf("connectToBackend: %v", err)
			}
			s.backendConn.Close()
		}
	})
}

// A reloaded command_timeout must reach the connections accepted after the reload. The
// library takes it for new connections; the listener's timeout checker must as well, or
// it keeps closing them at the start-up value.
func TestReloadConfig_CommandTimeoutReachesNewConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out an idle timeout")
	}
	srv, addr := newReloadTestProxy(t, "127.0.0.1:110", POP3ProxyServerOptions{CommandTimeout: 2 * time.Second})
	startReloadTestProxy(t, srv, addr)

	if err := srv.ReloadConfig(config.ServerConfig{
		Name: "reload", Type: "pop3_proxy",
		Timeouts: &config.ServerTimeoutsConfig{CommandTimeout: "1h"},
	}); err != nil {
		t.Fatal(err)
	}

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("greeting: %q %v", line, err)
	}
	time.Sleep(4 * time.Second) // twice the start-up command_timeout
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte("CAPA\r\n"))
	if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("after 4s idle under a 1h command_timeout (reloaded from 2s): %q %v", line, err)
	}
}

// reloadWhile runs ReloadConfig every millisecond, alternating cfgs, until work returns.
func reloadWhile(t *testing.T, reload func(config.ServerConfig) error, cfgs []config.ServerConfig, work func()) {
	t.Helper()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := reload(cfgs[i%len(cfgs)]); err != nil {
				t.Errorf("ReloadConfig: %v", err)
				return
			}
			time.Sleep(time.Millisecond) // still overlapping every reader, without flooding the log
		}
	}()
	work()
	close(stop)
	wg.Wait()
}
