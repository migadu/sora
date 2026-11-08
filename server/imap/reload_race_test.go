package imap

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// SIGHUP runs ReloadConfig on its own goroutine while connections log in. Two configs
// that differ in every setting the IMAP server reloads, alternated.
var reloadRaceConfigs = []config.ServerConfig{
	{
		Name: "reload", Type: "imap",
		MasterSASLUsername: "master", MasterSASLPassword: "secret-b",
		MasterSASLAllowedNetworks: []string{"127.0.0.0/8"},
		Limits:                    &config.ServerLimitsConfig{SessionMemoryLimit: "50mb"},
		Timeouts:                  &config.ServerTimeoutsConfig{CommandTimeout: "20m", AbsoluteSessionTimeout: "2h", MinBytesPerMinute: 512},
	},
	{
		Name: "reload", Type: "imap",
		MasterSASLUsername: "master", MasterSASLPassword: "secret-a",
		Limits:   &config.ServerLimitsConfig{SessionMemoryLimit: "60mb"},
		Timeouts: &config.ServerTimeoutsConfig{CommandTimeout: "25m", AbsoluteSessionTimeout: "3h"},
	},
}

// command_timeout's metric is set at start-up and must follow a reload too.
func TestReloadConfig_CommandTimeoutMetric(t *testing.T) {
	srv, _ := newReloadTestServer(t, IMAPServerOptions{CommandTimeout: 30 * time.Minute})
	if err := srv.ReloadConfig(config.ServerConfig{Name: "reload", Type: "imap", Timeouts: &config.ServerTimeoutsConfig{CommandTimeout: "17m"}}); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metrics.CommandTimeoutThresholdSeconds.WithLabelValues("imap")); got != (17 * time.Minute).Seconds() {
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

func newReloadTestServer(t *testing.T, opts IMAPServerOptions) (*IMAPServer, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	opts.InsecureAuth = true
	opts.AppendLimit = DefaultAppendLimit
	opts.MaxConnections = 100
	opts.Config = &config.Config{}
	srv, err := New(ctx, "reload", "localhost", addr, &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, addr
}

func serveReloadTestServer(t *testing.T, srv *IMAPServer, addr string) {
	t.Helper()
	go func() { _ = srv.Serve(addr) }()
	t.Cleanup(srv.Close)
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func readTagged(t *testing.T, r *bufio.Reader, tag string) string {
	t.Helper()
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("waiting for %q: %v", tag, err)
		}
		if strings.HasPrefix(line, tag) {
			return line
		}
	}
}

// A master SASL login (AUTHENTICATE PLAIN, sasl.go) and the session it starts
// (newSession, session_memory_limit) read what a concurrent reload replaces.
func TestReloadConfig_DuringMasterSASLLogins(t *testing.T) {
	srv, addr := newReloadTestServer(t, IMAPServerOptions{
		MasterSASLUsername: []byte("master"),
		MasterSASLPassword: []byte("secret-a"),
	})
	serveReloadTestServer(t, srv, addr)

	// Authenticated as the master, acting for a user, with a wrong password: refused
	// before any account lookup, so no database is needed.
	plain := base64.StdEncoding.EncodeToString([]byte("user@example.com\x00master\x00wrong"))
	reloadWhile(t, srv.ReloadConfig, reloadRaceConfigs, func() {
		for i := 0; i < 20; i++ {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			c.SetDeadline(time.Now().Add(5 * time.Second))
			r := bufio.NewReader(c)
			readTagged(t, r, "* OK")
			c.Write([]byte("a AUTHENTICATE PLAIN\r\n"))
			readTagged(t, r, "+")
			c.Write([]byte(plain + "\r\n"))
			if line := readTagged(t, r, "a "); !strings.HasPrefix(line, "a NO") {
				t.Errorf("master SASL login with a wrong password: %q, want a NO", line)
			}
			c.Close()
		}
	})
}

// IDLE derives its keepalive from command_timeout (idle.go) while a reload replaces it.
func TestReloadConfig_DuringIdle(t *testing.T) {
	srv, _ := newReloadTestServer(t, IMAPServerOptions{CommandTimeout: 30 * time.Minute})

	// A pre-authenticated session, so IDLE is reachable without a login.
	is := imapserver.New(&imapserver.Options{
		NewSession: func(c *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			sess, _, err := srv.newSession(c)
			if err != nil {
				return nil, nil, err
			}
			return sess, &imapserver.GreetingData{PreAuth: true}, nil
		},
		Logger:       log.New(io.Discard, "", 0),
		InsecureAuth: true,
		Caps:         srv.caps,
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go is.Serve(ln)
	t.Cleanup(func() { is.Close() })

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	readTagged(t, r, "* PREAUTH")
	reloadWhile(t, srv.ReloadConfig, reloadRaceConfigs, func() {
		for i := 0; i < 20; i++ {
			c.Write([]byte("a IDLE\r\n"))
			readTagged(t, r, "+")
			c.Write([]byte("DONE\r\n"))
			if line := readTagged(t, r, "a "); !strings.HasPrefix(line, "a OK") {
				t.Fatalf("IDLE: %q", line)
			}
		}
	})
}

// A reloaded command_timeout must reach the connections accepted after the reload: the
// listener's timeout checker is what closes an idle connection.
func TestReloadConfig_CommandTimeoutReachesNewConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out an idle timeout")
	}
	srv, addr := newReloadTestServer(t, IMAPServerOptions{CommandTimeout: time.Hour})
	serveReloadTestServer(t, srv, addr)

	if err := srv.ReloadConfig(config.ServerConfig{
		Name: "reload", Type: "imap",
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
	readTagged(t, r, "* OK")
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("no BYE within 6s of a 2s command_timeout (reloaded from 1h): %v", err)
	}
	if !strings.HasPrefix(line, "* BYE") || !strings.Contains(line, "Idle timeout") {
		t.Fatalf("got %q, want the idle-timeout BYE", line)
	}
}
