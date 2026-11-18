package managesieve

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
)

// libIdleTimeout returns the idle timeout the go-managesieve server that new
// connections get will enforce: the IdleTimeout of its resolved options, after
// the library has filled in its own defaults.
func libIdleTimeout(t *testing.T, srv *ManageSieveServer) time.Duration {
	t.Helper()
	opts := reflect.ValueOf(srv.msLibServer.Load()).Elem().FieldByName("opts")
	if !opts.IsValid() {
		t.Fatal("managesieveserver.Server has no opts field; update this test for the go-managesieve version in go.mod")
	}
	idle := opts.FieldByName("IdleTimeout")
	if !idle.IsValid() {
		t.Fatal("managesieveserver.Options has no IdleTimeout field; update this test for the go-managesieve version in go.mod")
	}
	return time.Duration(idle.Int())
}

// newServerWithCommandTimeout builds a ManageSieve server from cfg the way
// startDynamicManageSieveServer does for its command_timeout.
func newServerWithCommandTimeout(t *testing.T, cfg config.ServerConfig) *ManageSieveServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv, err := New(ctx, cfg.Name, "localhost", "127.0.0.1:0", &resilient.ResilientDatabase{}, ManageSieveServerOptions{
		MaxScriptSize:  cfg.GetMaxScriptSizeWithDefault(),
		CommandTimeout: cfg.GetCommandTimeoutWithDefault(),
		MaxConnections: 10,
		Config:         &config.Config{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// command_timeout = "0" on a managesieve server means the ManageSieve default
// (3m), as "0" means the default on the other backends whose idle timer the
// protocol library owns (pop3, lmtp). It must not reach go-managesieve as 0,
// which the library turns into its own 30-minute default (#1905).
func TestCommandTimeoutZeroUsesManageSieveDefault(t *testing.T) {
	zero := config.ServerConfig{
		Name: "sieve-zero", Type: "managesieve",
		Timeouts: &config.ServerTimeoutsConfig{CommandTimeout: "0"},
	}
	want := (&config.ServerConfig{Type: "managesieve"}).GetCommandTimeoutWithDefault()
	if want != 3*time.Minute {
		t.Fatalf("managesieve command_timeout default = %v, want 3m", want)
	}

	// Start-up with "0".
	if got := libIdleTimeout(t, newServerWithCommandTimeout(t, zero)); got != want {
		t.Errorf("start-up with command_timeout = \"0\": library idle timeout = %v, want %v", got, want)
	}

	// An explicit value passes through, and a SIGHUP to "0" gets the default.
	explicit := zero
	explicit.Timeouts = &config.ServerTimeoutsConfig{CommandTimeout: "7m"}
	srv := newServerWithCommandTimeout(t, explicit)
	if got := libIdleTimeout(t, srv); got != 7*time.Minute {
		t.Fatalf("start-up with command_timeout = \"7m\": library idle timeout = %v, want 7m", got)
	}
	if err := srv.ReloadConfig(zero); err != nil {
		t.Fatal(err)
	}
	if got := libIdleTimeout(t, srv); got != want {
		t.Errorf("reload to command_timeout = \"0\": library idle timeout = %v, want %v", got, want)
	}
}
