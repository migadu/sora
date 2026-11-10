package managesieve

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
)

// A client that has not sent STARTTLS reads in plaintext: the shutdown BYE must
// reach it. It used to be withheld from every session of a STARTTLS listener
// that was not yet TLS, upgrade in progress or not (#236).
func TestShutdownNoticeBeforeStartTLSReachesPlaintextClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	srv, err := New(ctx, "test", "localhost", addr, &resilient.ResilientDatabase{}, ManageSieveServerOptions{
		TLS:            true,
		TLSUseStartTLS: true,
		TLSCertFile:    "../../testdata/sora.crt",
		TLSKeyFile:     "../../testdata/sora.key",
		CommandTimeout: time.Minute,
		MaxConnections: 10,
		Config:         &config.Config{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	errChan := make(chan error, 1)
	go srv.Start(errChan)

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
	readUntilOK(t, reader, "greeting")

	go srv.Close()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the shutdown notice in plaintext: %v", err)
	}
	if want := "BYE (TRYLATER) \"Server shutting down, please reconnect\"\r\n"; line != want {
		t.Fatalf("shutdown notice = %q, want %q", line, want)
	}
}
