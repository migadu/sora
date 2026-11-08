package managesieve

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// SIGHUP runs ReloadConfig on its own goroutine while connections log in. Two configs
// that differ in every setting the ManageSieve server reloads, alternated.
var reloadRaceConfigs = []config.ServerConfig{
	{
		Name: "reload", Type: "managesieve",
		MasterSASLUsername: "master", MasterSASLPassword: "secret-b",
		MasterSASLAllowedNetworks: []string{"127.0.0.0/8"},
		MaxScriptSize:             "32kb",
		Timeouts:                  &config.ServerTimeoutsConfig{CommandTimeout: "4m", AbsoluteSessionTimeout: "2h", MinBytesPerMinute: 512},
	},
	{
		Name: "reload", Type: "managesieve",
		MasterSASLUsername: "master", MasterSASLPassword: "secret-a",
		Timeouts: &config.ServerTimeoutsConfig{CommandTimeout: "5m", AbsoluteSessionTimeout: "3h"},
	},
}

// command_timeout's metric is set at start-up and must follow a reload too.
func TestReloadConfig_CommandTimeoutMetric(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := New(ctx, "reload", "localhost", "127.0.0.1:0", &resilient.ResilientDatabase{}, ManageSieveServerOptions{CommandTimeout: 5 * time.Minute, Config: &config.Config{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ReloadConfig(config.ServerConfig{Name: "reload", Type: "managesieve", Timeouts: &config.ServerTimeoutsConfig{CommandTimeout: "17m"}}); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metrics.CommandTimeoutThresholdSeconds.WithLabelValues("managesieve")); got != (17 * time.Minute).Seconds() {
		t.Errorf("command timeout metric after reloading 17m: %v", got)
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

// A master SASL login (AuthenticatePlain) reads the master credentials and network gate
// while a reload replaces them. The master username acting for a user with a wrong
// password is refused before any account lookup, so no database is needed.
func TestReloadConfig_DuringMasterSASLLogin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := New(ctx, "reload", "localhost", "127.0.0.1:0", &resilient.ResilientDatabase{}, ManageSieveServerOptions{
		MasterSASLUsername: "master",
		MasterSASLPassword: "secret-a",
		Config:             &config.Config{},
	})
	if err != nil {
		t.Fatal(err)
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	sctx, scancel := context.WithCancel(ctx)
	defer scancel()
	s := &ManageSieveSession{server: srv, conn: c1, ctx: sctx, cancel: scancel, startTime: time.Now()}
	s.Protocol = "ManageSieve"
	s.RemoteIP = "127.0.0.1"
	s.Id = "sess"
	s.Stats = srv
	s.mutexHelper = server.NewMutexTimeoutHelper(&s.mutex, sctx, "MANAGESIEVE", func(string, ...any) {})

	reloadWhile(t, srv.ReloadConfig, reloadRaceConfigs, func() {
		for i := 0; i < 50; i++ {
			if err := s.AuthenticatePlain(ctx, "user@example.com", "master", "wrong"); err != errAuthFailed {
				t.Fatalf("master SASL login with a wrong password: %v, want errAuthFailed", err)
			}
		}
	})
}
