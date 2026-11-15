package lmtpproxy

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
)

// An lmtp_proxy with max_message_size "0" advertises SIZE 52428800 in its LHLO reply,
// the 50 MiB a backend with "0" enforces, at start-up and after a reload (#962). Before,
// "0" was stored as 0 and the proxy advertised no SIZE, so an MTA sent a 60 MB message
// in full and the backend refused it after the transfer with a permanent 552. RFC 1870
// section 3 (3): "A parameter value of 0 (zero) indicates that no fixed maximum message
// size is in force. If the parameter is omitted no information is conveyed about the
// server's fixed maximum message size".
func TestLHLOAdvertisesDefaultSizeForZeroMaxMessageSize(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	// As cmd/sora/main.go builds the proxy from its [[server]] block.
	cfg := config.ServerConfig{Name: "size-zero", Type: "lmtp_proxy", MaxMessageSize: "0"}
	srv, err := New(ctx, &resilient.ResilientDatabase{}, "localhost", ServerOptions{
		Name:                   cfg.Name,
		Addr:                   addr,
		RemoteAddrs:            []string{"127.0.0.1:24"},
		RemotePort:             24,
		ConnectTimeout:         time.Second,
		RemoteLookup:           &config.RemoteLookupConfig{},
		TrustedProxies:         []string{"127.0.0.0/8"},
		AbsoluteSessionTimeout: time.Hour,
		MaxMessageSize:         cfg.GetMaxMessageSizeWithDefault(),
		MaxConnections:         10,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Stop() })

	const want = "250-SIZE 52428800\r\n"
	if reply := lhloReply(t, addr); !strings.Contains(reply, want) {
		t.Errorf("LHLO reply with max_message_size = \"0\" lacks %q:\n%s", want, reply)
	}

	for _, reload := range []string{"100mb", "0"} {
		cfg.MaxMessageSize = reload
		if err := srv.ReloadConfig(cfg); err != nil {
			t.Fatal(err)
		}
	}
	if reply := lhloReply(t, addr); !strings.Contains(reply, want) {
		t.Errorf("LHLO reply after reloading max_message_size = \"0\" lacks %q:\n%s", want, reply)
	}
}

// lhloReply opens a session on addr, waiting for the listener, and returns its LHLO reply.
func lhloReply(t *testing.T, addr string) string {
	t.Helper()
	var c net.Conn
	deadline := time.Now().Add(3 * time.Second)
	for {
		var err error
		if c, err = net.Dial("tcp", addr); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(c)
	if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "220") {
		t.Fatalf("greeting: %q %v", line, err)
	}
	if _, err := c.Write([]byte("LHLO client.example.org\r\n")); err != nil {
		t.Fatal(err)
	}
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
	_, _ = c.Write([]byte("QUIT\r\n"))
	_, _ = r.ReadString('\n')
	return reply.String()
}
