package lmtpproxy

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

// SIGHUP runs ReloadConfig on its own goroutine while sessions run: a session reads
// absolute_session_timeout when it starts, max_message_size for its LHLO reply, and
// debug whenever it logs.
func TestReloadConfig_DuringSessions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	srv, err := New(ctx, &resilient.ResilientDatabase{}, "localhost", ServerOptions{
		Name:                   "reload",
		Addr:                   addr,
		RemoteAddrs:            []string{"127.0.0.1:24"},
		RemotePort:             24,
		ConnectTimeout:         time.Second,
		RemoteLookup:           &config.RemoteLookupConfig{},
		TrustedProxies:         []string{"127.0.0.0/8"},
		AbsoluteSessionTimeout: time.Hour,
		MaxMessageSize:         1 << 20,
		MaxConnections:         100,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Stop() })
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cfgs := []config.ServerConfig{
		{Name: "reload", Type: "lmtp_proxy", MaxMessageSize: "2mb", Debug: true, Timeouts: &config.ServerTimeoutsConfig{AbsoluteSessionTimeout: "2h"}},
		{Name: "reload", Type: "lmtp_proxy", MaxMessageSize: "1mb", Timeouts: &config.ServerTimeoutsConfig{AbsoluteSessionTimeout: "3h"}},
	}
	// lhlo opens a session and returns its LHLO reply.
	lhlo := func() string {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		r := bufio.NewReader(c)
		if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "220") {
			t.Fatalf("greeting: %q %v", line, err)
		}
		c.Write([]byte("LHLO client.example.com\r\n"))
		var reply strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("LHLO: %v", err)
			}
			reply.WriteString(line)
			if strings.HasPrefix(line, "250 ") {
				break
			}
		}
		c.Write([]byte("QUIT\r\n"))
		_, _ = r.ReadString('\n')
		return reply.String()
	}
	reloadWhile(t, srv.ReloadConfig, cfgs, func() {
		for i := 0; i < 20; i++ {
			lhlo()
		}
	})

	// And a reload takes effect for the sessions after it.
	if err := srv.ReloadConfig(config.ServerConfig{Name: "reload", Type: "lmtp_proxy", MaxMessageSize: "3mb"}); err != nil {
		t.Fatal(err)
	}
	if reply := lhlo(); !strings.Contains(reply, "250-SIZE 3145728\r\n") {
		t.Errorf("LHLO after reloading max_message_size = 3mb:\n%s", reply)
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
