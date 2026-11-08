package pop3

import (
	"bufio"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// SIGHUP runs ReloadConfig on its own goroutine while connections log in. Two configs
// that differ in every setting the POP3 server reloads, alternated.
var reloadRaceConfigs = []config.ServerConfig{
	{
		Name: "reload", Type: "pop3",
		MasterSASLUsername: "master", MasterSASLPassword: "secret-b",
		MasterSASLAllowedNetworks: []string{"127.0.0.0/8"},
		Limits:                    &config.ServerLimitsConfig{SessionMemoryLimit: "50mb"},
		Timeouts:                  &config.ServerTimeoutsConfig{CommandTimeout: "20m", AbsoluteSessionTimeout: "2h", MinBytesPerMinute: 512},
	},
	{
		Name: "reload", Type: "pop3",
		MasterSASLUsername: "master", MasterSASLPassword: "secret-a",
		Limits:   &config.ServerLimitsConfig{SessionMemoryLimit: "60mb"},
		Timeouts: &config.ServerTimeoutsConfig{CommandTimeout: "25m", AbsoluteSessionTimeout: "3h"},
	},
}

// command_timeout's metric is set at start-up and must follow a reload too.
func TestReloadConfig_CommandTimeoutMetric(t *testing.T) {
	s, _ := newReloadTestServer(t, POP3ServerOptions{CommandTimeout: 10 * time.Minute})
	if err := s.ReloadConfig(config.ServerConfig{Name: "reload", Type: "pop3", Timeouts: &config.ServerTimeoutsConfig{CommandTimeout: "17m"}}); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metrics.CommandTimeoutThresholdSeconds.WithLabelValues("pop3")); got != (17 * time.Minute).Seconds() {
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

func newReloadTestServer(t *testing.T, opts POP3ServerOptions) (*POP3Server, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	opts.MaxConnections = 100
	opts.Config = &config.Config{}
	s, err := New(ctx, "reload", "localhost", addr, &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, addr
}

// The library's NewSession callback reads session_memory_limit for every connection
// while a reload replaces it.
func TestReloadConfig_DuringNewSession(t *testing.T) {
	s, addr := newReloadTestServer(t, POP3ServerOptions{CommandTimeout: 10 * time.Second})
	errChan := make(chan error, 1)
	go s.Start(errChan)
	t.Cleanup(s.Close)
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	reloadWhile(t, s.ReloadConfig, reloadRaceConfigs, func() {
		for i := 0; i < 20; i++ {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
				t.Errorf("greeting: %v", err)
			}
			c.Close()
		}
	})
}

// A master SASL login (authenticateUser) reads the master credentials and network gate
// while a reload replaces them. The master username acting for a user with a wrong
// password is refused before any account lookup, so no database is needed.
func TestReloadConfig_DuringMasterSASLLogin(t *testing.T) {
	srv, _ := newReloadTestServer(t, POP3ServerOptions{
		MasterSASLUsername: "master",
		MasterSASLPassword: "secret-a",
	})
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &POP3Session{server: srv, conn: c1, deleted: make(map[int]bool), ctx: ctx, cancel: cancel}
	s.Protocol = "POP3"
	s.mutexHelper = serverPkg.NewMutexTimeoutHelper(&s.mutex, ctx, "POP3", s.InfoLog)

	reloadWhile(t, srv.ReloadConfig, reloadRaceConfigs, func() {
		for i := 0; i < 50; i++ {
			if err := s.AuthenticatePlain(context.Background(), "user@example.com", "master", "wrong"); err == nil {
				t.Fatal("master SASL login with a wrong password succeeded")
			}
		}
	})
}
