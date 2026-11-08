package imapproxy

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
// differ in every setting the IMAP proxy reloads, alternated.
var reloadRaceConfigs = []config.ServerConfig{
	{
		Name: "reload", Type: "imap_proxy",
		MasterSASLUsername: "master", MasterSASLPassword: "secret-b",
		AuthIdleTimeout: "90s", Debug: true,
		Limits:   &config.ServerLimitsConfig{MaxAuthErrors: 3},
		Timeouts: &config.ServerTimeoutsConfig{CommandTimeout: "20m", AbsoluteSessionTimeout: "2h", MinBytesPerMinute: 512},
	},
	{
		Name: "reload", Type: "imap_proxy",
		MasterSASLUsername: "master", MasterSASLPassword: "secret-a",
		AuthIdleTimeout: "2m",
		Timeouts:        &config.ServerTimeoutsConfig{CommandTimeout: "25m", AbsoluteSessionTimeout: "3h"},
	},
}

func newReloadTestProxy(t *testing.T, opts ServerOptions) (*Server, string) {
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
	opts.Addr = addr
	opts.RemoteAddrs = []string{"127.0.0.1:143"}
	opts.RemotePort = 143
	opts.ConnectTimeout = time.Second
	opts.MaxConnections = 100
	opts.RemoteLookup = &config.RemoteLookupConfig{}
	srv, err := New(ctx, &resilient.ResilientDatabase{}, "localhost", opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, addr
}

func startReloadTestProxy(t *testing.T, srv *Server, addr string) {
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

// A new session reads absolute_session_timeout, auth_idle_timeout and debug while a
// reload replaces them.
func TestReloadConfig_DuringNewSessions(t *testing.T) {
	srv, addr := newReloadTestProxy(t, ServerOptions{CommandTimeout: 30 * time.Minute, AuthIdleTimeout: time.Minute})
	startReloadTestProxy(t, srv, addr)

	reloadWhile(t, srv.ReloadConfig, reloadRaceConfigs, func() {
		for i := 0; i < 20; i++ {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			c.SetDeadline(time.Now().Add(3 * time.Second))
			r := bufio.NewReader(c)
			if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "* OK") {
				t.Errorf("greeting: %q %v", line, err)
			}
			c.Write([]byte("a LOGOUT\r\n"))
			_, _ = r.ReadString('\n')
			c.Close()
		}
	})
}

// The proxy logs in to the backend with the master SASL credentials a reload replaces.
func TestReloadConfig_DuringBackendLogin(t *testing.T) {
	srv, _ := newReloadTestProxy(t, ServerOptions{MasterSASLUsername: "master", MasterSASLPassword: "secret-a"})

	proxyEnd, backendEnd := net.Pipe()
	defer proxyEnd.Close()
	defer backendEnd.Close()
	go func() { // a backend that accepts every AUTHENTICATE
		r := bufio.NewReader(backendEnd)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			tag, _, _ := strings.Cut(line, " ")
			if _, err := backendEnd.Write([]byte(tag + " OK authenticated\r\n")); err != nil {
				return
			}
		}
	}()
	clientEnd, _ := net.Pipe() // only logged from
	defer clientEnd.Close()
	s := &Session{
		server:        srv,
		clientConn:    clientEnd,
		backendConn:   proxyEnd,
		backendReader: bufio.NewReader(proxyEnd),
		backendWriter: bufio.NewWriter(proxyEnd),
		username:      "user@example.com",
		ctx:           context.Background(),
	}

	reloadWhile(t, srv.ReloadConfig, reloadRaceConfigs, func() {
		for i := 0; i < 50; i++ {
			if _, err := s.authenticateToBackend(); err != nil {
				t.Fatalf("authenticateToBackend: %v", err)
			}
		}
	})
}

// A reloaded command_timeout must reach the connections accepted after the reload: the
// listener's timeout checker is the only thing on the proxy that closes an idle client.
func TestReloadConfig_CommandTimeoutReachesNewConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out an idle timeout")
	}
	srv, addr := newReloadTestProxy(t, ServerOptions{CommandTimeout: time.Hour})
	startReloadTestProxy(t, srv, addr)

	if err := srv.ReloadConfig(config.ServerConfig{
		Name: "reload", Type: "imap_proxy",
		Timeouts: &config.ServerTimeoutsConfig{CommandTimeout: "2s"},
	}); err != nil {
		t.Fatal(err)
	}

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(6 * time.Second))
	if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "* OK") {
		t.Fatalf("greeting: %q %v", line, err)
	}
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("no BYE within 6s of a 2s command_timeout (reloaded from 1h): %v", err)
	}
	if !strings.HasPrefix(line, "* BYE Idle timeout") {
		t.Fatalf("got %q, want the idle-timeout BYE", line)
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
