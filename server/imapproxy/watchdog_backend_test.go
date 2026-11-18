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

// TestAbsoluteTimeoutEndsSessionBlockedOnBackend covers #2096: a login whose backend
// accepts the connection and never sends its greeting. The greeting read is bounded
// only by the connect timeout (30s here); the absolute session timeout (2s) must end
// the session first. The context watchdog has to close the backend connection for
// that, as closing the client does not unblock a read on the backend.
func TestAbsoluteTimeoutEndsSessionBlockedOnBackend(t *testing.T) {
	const (
		absoluteTimeout = 2 * time.Second
		connectTimeout  = 30 * time.Second
		bound           = 6 * time.Second
	)

	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	accepted := make(chan struct{})
	backendClosed := make(chan struct{})
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		close(accepted)
		io.Copy(io.Discard, c) // never greets; returns when the proxy closes
		close(backendClosed)
	}()
	// Never asked: the login is answered from the lookup cache.
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer lookup.Close()

	srv, err := New(context.Background(), &resilient.ResilientDatabase{}, "localhost", ServerOptions{
		Name: "watchdog", RemoteAddrs: []string{backend.Addr().String()}, ConnectTimeout: connectTimeout,
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

	serverEnd, conn := net.Pipe()
	sess := newSession(srv, serverEnd)
	done := make(chan struct{})
	start := time.Now()
	go func() { defer close(done); sess.handleConnection() }()
	defer func() { conn.Close(); <-done }()
	go io.Copy(io.Discard, bufio.NewReader(conn)) // drain greeting and replies

	conn.SetWriteDeadline(time.Now().Add(bound))
	if _, err := conn.Write([]byte("a1 LOGIN anna@example.com secret\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-accepted:
	case <-time.After(bound):
		t.Fatal("the proxy never connected to the backend")
	}
	select {
	case <-done:
		t.Fatalf("precondition: the session ended %v after it started, before blocking on the backend", time.Since(start))
	default:
	}

	select {
	case <-done:
	case <-time.After(bound):
		t.Fatalf("session still blocked on the backend %v after start (absolute timeout %v, connect timeout %v)",
			time.Since(start), absoluteTimeout, connectTimeout)
	}
	if elapsed := time.Since(start); elapsed < absoluteTimeout {
		t.Errorf("session ended after %v, before the absolute timeout %v", elapsed, absoluteTimeout)
	}
	select {
	case <-backendClosed:
	case <-time.After(bound):
		t.Fatal("the session ended but left the backend connection open")
	}
}
