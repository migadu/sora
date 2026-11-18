package pop3proxy

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// libIdleTimeouts returns the idle timeouts the go-pop3 server that new
// connections get will enforce: IdleTimeout and AuthIdleTimeout of its resolved
// options, after the library has filled in its own defaults.
func libIdleTimeouts(t *testing.T, s *POP3ProxyServer) (idle, authIdle time.Duration) {
	t.Helper()
	opts := reflect.ValueOf(s.pop3libServer.Load()).Elem().FieldByName("opts")
	if !opts.IsValid() {
		t.Fatal("pop3server.Server has no opts field; update this test for the go-pop3 version in go.mod")
	}
	for name, dst := range map[string]*time.Duration{"IdleTimeout": &idle, "AuthIdleTimeout": &authIdle} {
		f := opts.FieldByName(name)
		if !f.IsValid() {
			t.Fatalf("pop3server.Options has no %s field; update this test for the go-pop3 version in go.mod", name)
		}
		*dst = time.Duration(f.Int())
	}
	return idle, authIdle
}

// newProxyWithTimeouts builds a POP3 proxy from cfg the way
// startDynamicPOP3ProxyServer does for its timeouts.
func newProxyWithTimeouts(t *testing.T, cfg config.ServerConfig) *POP3ProxyServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s, err := New(ctx, "localhost", "127.0.0.1:0", nil, POP3ProxyServerOptions{
		Name:            cfg.Name,
		RemoteAddrs:     []string{"192.0.2.10:110"},
		AuthIdleTimeout: cfg.GetAuthIdleTimeoutWithDefault(),
		CommandTimeout:  cfg.GetCommandTimeoutWithDefault(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Stop() })
	return s
}

// command_timeout = "0" on pop3_proxy turns the idle timer off, as on the other
// proxies. It must not reach go-pop3 as 0, which the library turns into its own
// 10-minute default; with auth_idle_timeout also 0 that default would close an
// unauthenticated connection after 10 minutes (#1953).
func TestCommandTimeoutZeroDisablesLibraryIdleTimeout(t *testing.T) {
	zero := config.ServerConfig{
		Name: "pop3-proxy-zero", Type: "pop3_proxy",
		AuthIdleTimeout: "0",
		Timeouts:        &config.ServerTimeoutsConfig{CommandTimeout: "0"},
	}

	// Start-up with "0".
	idle, authIdle := libIdleTimeouts(t, newProxyWithTimeouts(t, zero))
	if authIdle > 0 {
		t.Fatalf("auth_idle_timeout = \"0\": library auth idle timeout = %v, want none", authIdle)
	}
	if idle > 0 {
		t.Errorf("start-up with command_timeout = \"0\": library idle timeout = %v, want none", idle)
	}

	// An explicit value passes through, and a SIGHUP to "0" turns it off.
	explicit := zero
	explicit.Timeouts = &config.ServerTimeoutsConfig{CommandTimeout: "7m"}
	s := newProxyWithTimeouts(t, explicit)
	if idle, _ := libIdleTimeouts(t, s); idle != 7*time.Minute {
		t.Fatalf("start-up with command_timeout = \"7m\": library idle timeout = %v, want 7m", idle)
	}
	if err := s.ReloadConfig(zero); err != nil {
		t.Fatal(err)
	}
	if idle, _ := libIdleTimeouts(t, s); idle > 0 {
		t.Errorf("reload to command_timeout = \"0\": library idle timeout = %v, want none", idle)
	}
}
