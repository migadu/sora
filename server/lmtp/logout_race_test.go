package lmtp

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/server"
)

// go-smtp logs a session out from Server.Close (Conn.Close) on the closing goroutine, while
// the connection's own goroutine may still be inside a command. These tests run Logout
// against such a command and fail under -race when Logout reads what the command writes.

// newLogoutTestSession builds a session the way NewSession does, without a connection.
func newLogoutTestSession(t *testing.T) *LMTPSession {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &LMTPSession{
		backend:   &LMTPServerBackend{name: "test", hostname: "test"},
		ctx:       ctx,
		cancel:    cancel,
		startTime: time.Now(),
	}
	s.Id = "logout-race-test"
	s.Protocol = "LMTP"
	s.ServerName = "test"
	s.RemoteIP = "127.0.0.1"
	s.mutexHelper = server.NewMutexTimeoutHelper(&s.mutex, ctx, "LMTP", nil)
	return s
}

func testUser(t *testing.T) *server.User {
	t.Helper()
	addr, err := server.NewAddress("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	return server.NewUser(addr, 42)
}

// loopbackConn returns go-smtp's Conn of a real loopback connection, for the session code
// that checks the peer's address.
func loopbackConn(t *testing.T) *smtp.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conns := make(chan *smtp.Conn, 1)
	srv := smtp.NewServer(smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
		conns <- c
		return nil, errors.New("the test drives its own session")
	}))
	srv.LMTP = true
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	if _, err := bufio.NewReader(client).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("LHLO test\r\n")); err != nil {
		t.Fatal(err)
	}
	return <-conns
}

// A command holds the session lock and writes (Rcpt the user, Data the trace id) when
// Server.Close logs the session out: Logout must read those only once it has the lock.
func TestLogoutReadsTheSessionOnlyUnderTheLock(t *testing.T) {
	s := newLogoutTestSession(t)
	user := testUser(t)

	held := make(chan struct{})
	go func() { // the connection's goroutine, inside a command
		s.mutex.Lock()
		defer s.mutex.Unlock()
		close(held)
		s.User = user
		s.traceID = "9f86d081884c7d65"
	}()

	<-held
	if err := s.Logout(); err == nil {
		t.Error("Logout returned nil, want the 221 reply")
	}
}

// At Server.Close go-smtp cancels the connection's context, so Logout cannot take the session
// lock and goes on without it, while a command that took the lock earlier (a DATA under way)
// keeps writing. Logout must then read nothing that command writes, and not wait for it.
func TestLogoutWithoutTheLockReadsNothingACommandWrites(t *testing.T) {
	s := newLogoutTestSession(t)
	user := testUser(t)

	held := make(chan struct{})
	loggedOut := make(chan struct{})
	commandDone := make(chan struct{})
	go func() { // the connection's goroutine, inside DATA
		defer close(commandDone)
		s.mutex.Lock()
		defer s.mutex.Unlock()
		close(held)
		s.User = user
		s.traceID = "9f86d081884c7d65" // DATA has parsed the header
		<-loggedOut
	}()

	<-held
	s.cancel()
	start := time.Now()
	if err := s.Logout(); err == nil {
		t.Error("Logout returned nil, want the 221 reply")
	}
	if waited := time.Since(start); waited >= server.MutexTimeout {
		t.Errorf("Logout waited %v for the lock of a cancelled session", waited)
	}
	close(loggedOut)
	<-commandDone
}

// The reproduction from the issue, with the real RSET. It catches a Logout that reads
// before taking the lock only when RSET happens to win the lock; the tests above always do.
func TestLogoutRacesReset(t *testing.T) {
	user := testUser(t)
	for range 50 {
		s := newLogoutTestSession(t)
		s.User = user
		s.traceID = "9f86d081884c7d65"
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); s.Reset() }()
		go func() { defer wg.Done(); s.Logout() }()
		wg.Wait()
	}
}

// The XCLIENT hook rewrites the remote address of the session that go-smtp logs out next,
// and Server.Close may log that session out while the hook runs.
func TestLogoutRacesXCLIENT(t *testing.T) {
	for range 10 {
		s := newLogoutTestSession(t)
		// A trusted peer: the hook judges the forwarded address by the connection's.
		s.conn = loopbackConn(t)
		s.backend.xclientTrustedNets = mustParseNets(t, []string{"127.0.0.0/8"})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = s.XCLIENT(nil, map[string]string{"ADDR": "203.0.113.7"})
		}()
		go func() { defer wg.Done(); s.Logout() }()
		wg.Wait()
	}
}

// XRCPTFORWARD from a trusted peer sets the proxy address that Logout logs. It is applied
// under the session lock, for an accepted recipient only.
func TestLogoutRacesXRCPTFORWARD(t *testing.T) {
	forward := &smtp.RcptOptions{Extensions: map[string]string{
		"XRCPTFORWARD": base64.StdEncoding.EncodeToString([]byte("proxy=127.0.0.1\toriginating-ip=192.0.2.1")),
	}}
	for range 10 {
		s := newLogoutTestSession(t)
		s.conn = loopbackConn(t)
		s.backend.xclientTrustedNets = mustParseNets(t, []string{"127.0.0.0/8"})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = s.Rcpt(context.Background(), "not an address", forward)
		}()
		go func() { defer wg.Done(); s.Logout() }()
		wg.Wait()
		if s.ProxyIP != "" || s.ForwardingParams != nil {
			t.Fatalf("a rejected recipient's XRCPTFORWARD was applied: proxy %q, params %+v", s.ProxyIP, s.ForwardingParams)
		}
	}
}
