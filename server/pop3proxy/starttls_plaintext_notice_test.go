package pop3proxy

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
)

// A client that has not sent STLS reads in plaintext: the shutdown notice must
// reach it. It used to be withheld from every session of a STARTTLS listener
// that was not yet TLS, upgrade in progress or not (#236).
func TestShutdownNoticeBeforeSTLSReachesPlaintextClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()

	srv, err := New(ctx, "localhost", addr, &resilient.ResilientDatabase{}, POP3ProxyServerOptions{
		Name:           "test",
		RemoteAddrs:    []string{"127.0.0.1:110"},
		RemotePort:     110,
		TLS:            true,
		TLSUseStartTLS: true,
		TLSCertFile:    "../../testdata/sora.crt",
		TLSKeyFile:     "../../testdata/sora.key",
		CommandTimeout: time.Minute,
		ConnectTimeout: 5 * time.Second,
		AuthRateLimit:  server.AuthRateLimiterConfig{},
		MaxConnections: 10,
		RemoteLookup:   &config.RemoteLookupConfig{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go srv.Start()

	var conn net.Conn
	for deadline := time.Now().Add(3 * time.Second); ; {
		if conn, err = net.Dial("tcp", addr); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("greeting = %q, %v", line, err)
	}

	go srv.sendGracefulShutdownMessage()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the shutdown notice in plaintext: %v", err)
	}
	if want := "-ERR Server shutting down, please reconnect\r\n"; line != want {
		t.Fatalf("shutdown notice = %q, want %q", line, want)
	}
}
