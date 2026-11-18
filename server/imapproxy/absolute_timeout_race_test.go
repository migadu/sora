package imapproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/resilient"
)

// TestAbsoluteTimeoutDuringLoginDoesNotRaceSessionState covers #2085: the absolute
// session timeout fires while a LOGIN is in progress. A cached login writes
// s.accountID and s.username, then the session dials a backend that never sends its
// greeting and blocks reading it, so nothing orders those writes before the timer
// goroutine runs. The timer callback used to log through s.InfoLog, reading the fields
// on the timer goroutine (run with -race). The session must still end at the timeout.
func TestAbsoluteTimeoutDuringLoginDoesNotRaceSessionState(t *testing.T) {
	const absoluteTimeout = 500 * time.Millisecond

	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(io.Discard, c); c.Close() }() // never greets
		}
	}()
	// Never asked: the login is answered from the lookup cache.
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer lookup.Close()

	srv, err := New(context.Background(), &resilient.ResilientDatabase{}, "localhost", ServerOptions{
		Name: "abs-timeout", RemoteAddrs: []string{backend.Addr().String()}, ConnectTimeout: 3 * time.Second,
		InsecureAuth:           true,
		AbsoluteSessionTimeout: absoluteTimeout,
		RemoteLookup:           &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", Timeout: "2s"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Stop()
	srv.authLimiter = &failureCountingLimiter{}
	now := time.Now()
	srv.lookupCache.Set(srv.name, "anna@example.com", &lookupcache.CacheEntry{
		AccountID:        7,
		PasswordDigest:   lookupcache.NewPasswordDigest("secret"),
		ActualEmail:      "anna@example.com",
		Result:           lookupcache.AuthSuccess,
		FromRemoteLookup: true,
		CreatedAt:        now,
		ExpiresAt:        now.Add(time.Minute),
	})

	// Driven over a pipe, not the listener: the listener's connection timeout checker
	// reads the connection's state under its own locks, which can order the session's
	// writes before the timer callback and hide the race.
	serverEnd, conn := net.Pipe()
	sess := newSession(srv, serverEnd)
	done := make(chan struct{})
	go func() { defer close(done); sess.handleConnection() }()
	defer func() { conn.Close(); <-done }()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	start := time.Now()
	if _, err := conn.Write([]byte("a1 LOGIN anna@example.com secret\r\n")); err != nil {
		t.Fatal(err)
	}

	// The client connection is closed at the absolute timeout, although the backend
	// never answers.
	for {
		if _, err := r.ReadString('\n'); err != nil {
			break
		}
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("client connection closed %v after LOGIN; the absolute timeout is %v", elapsed, absoluteTimeout)
	}
}
