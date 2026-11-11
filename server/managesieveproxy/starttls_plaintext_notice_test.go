package managesieveproxy

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

func dialTransitionNoticeProxy(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "OK") {
			return conn, reader
		}
	}
}

// A client that has not sent STARTTLS reads in plaintext: the shutdown BYE must
// reach it. It used to be withheld from every session of a STARTTLS listener
// that was not yet TLS, upgrade in progress or not (#236).
func TestManageSieveProxyShutdownBeforeSTARTTLSReachesPlaintextClient(t *testing.T) {
	s, addr := startTransitionNoticeProxy(t, false)
	_, reader := dialTransitionNoticeProxy(t, addr)

	go s.sendGracefulShutdownBye()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the shutdown notice in plaintext: %v", err)
	}
	if want := "BYE (TRYLATER) \"Server shutting down, please reconnect\"\r\n"; line != want {
		t.Fatalf("shutdown notice = %q, want %q", line, want)
	}
}

// The slow-throughput notice of a session that stays plaintext goes to it in
// plaintext.
func TestManageSieveProxyThroughputOnPlaintextSessionSendsNotice(t *testing.T) {
	_, addr := startTransitionNoticeProxy(t, true)
	conn, reader := dialTransitionNoticeProxy(t, addr)
	quit, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-quit:
				return
			case <-ticker.C:
				if _, err := conn.Write([]byte("N")); err != nil {
					return
				}
			}
		}
	}()
	defer func() { close(quit); <-done }()

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the timeout notice in plaintext: %v", err)
	}
	if !strings.HasPrefix(line, "BYE ") {
		t.Fatalf("timeout notice = %q, want a BYE", line)
	}
}
