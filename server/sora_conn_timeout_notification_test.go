package server

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type timeoutNoticeCloseObservedConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *timeoutNoticeCloseObservedConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestSoraConnTimeoutTLSCloseIsBounded(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("../testdata/sora.crt", "../testdata/sora.key")
	if err != nil {
		t.Fatal(err)
	}
	transport, peer := net.Pipe()
	defer transport.Close()
	defer peer.Close()
	observed := &timeoutNoticeCloseObservedConn{Conn: transport, closed: make(chan struct{})}
	serverTLS := tls.Server(observed, &tls.Config{Certificates: []tls.Certificate{cert}})
	clientTLS := tls.Client(peer, &tls.Config{InsecureSkipVerify: true})
	clientHandshake := make(chan error, 1)
	go func() { clientHandshake <- clientTLS.Handshake() }()
	if err := serverTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-clientHandshake; err != nil {
		t.Fatal(err)
	}
	// The callback returns immediately, but TLS Close itself sends close_notify
	// and can block for five seconds when the peer stops reading after handshake.
	sc := NewSoraConn(serverTLS, SoraConnConfig{AbsoluteTimeout: time.Millisecond})
	checked := make(chan struct{})
	go func() { sc.checkTimeouts(time.Now().Add(time.Second)); close(checked) }()
	select {
	case <-observed.closed:
	case <-time.After(time.Second):
		t.Error("timeout did not close the underlying TLS transport within one second")
	}
	peer.Close()
	<-checked
}

// A protocol writer can replace a connection's write deadline while a timeout
// notice is being sent. Simulate a transport whose deadline cannot bound the
// callback, to check that hard closure still releases its write and goroutine.
type timeoutNoticeNoDeadlineConn struct{ net.Conn }

func (c timeoutNoticeNoDeadlineConn) SetWriteDeadline(time.Time) error { return nil }

func TestSoraConnTimeoutNoticeCannotHoldConnectionOpen(t *testing.T) {
	for _, reason := range []string{"idle", "session_max", "slow_throughput"} {
		t.Run(reason, func(t *testing.T) {
			transport, peer := net.Pipe()
			defer peer.Close()
			defer transport.Close()
			finished := make(chan struct{})
			sc := NewSoraConn(timeoutNoticeNoDeadlineConn{transport}, SoraConnConfig{
				NoAbsoluteTimeout: true,
				OnTimeout: func(conn net.Conn, got string) {
					defer close(finished)
					if got != reason {
						t.Errorf("timeout reason = %q, want %q", got, reason)
					}
					fmt.Fprint(conn, "goodbye\r\n")
				},
			})
			now := time.Now()
			switch reason {
			case "idle":
				sc.idleTimeout = time.Second
				sc.lastActivity = now.Add(-time.Minute)
			case "session_max":
				sc.absoluteTimeout = time.Second
				sc.sessionStart = now.Add(-time.Minute)
			case "slow_throughput":
				sc.minBytesPerMinute = 512
				sc.sessionStart = now.Add(-5 * time.Minute)
				sc.lastThroughputCheck = now.Add(-time.Minute)
				sc.bytesRead = 1
				sc.consecutiveStalledWindows = 1
			}
			checked := make(chan struct{})
			go func() { sc.checkTimeouts(now); close(checked) }()
			select {
			case <-checked:
			case <-time.After(time.Second):
				t.Error("timeout check blocked on the protocol notice")
			}
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Error("stalled notice was not released by closing the transport")
			}
			// Cleanup also waits for the check and callback on the unfixed code.
			peer.Close()
			<-checked
			<-finished
		})
	}
}

func TestSoraConnTimeoutNoticeRunsOnce(t *testing.T) {
	transport, peer := net.Pipe()
	defer transport.Close()
	entered := make(chan struct{})
	var first sync.Once
	var calls atomic.Int32
	sc := NewSoraConn(transport, SoraConnConfig{
		AbsoluteTimeout: time.Millisecond,
		OnTimeout: func(conn net.Conn, _ string) {
			calls.Add(1)
			first.Do(func() { close(entered) })
			fmt.Fprint(conn, "goodbye\r\n")
		},
	})
	now := time.Now().Add(time.Second)
	var checks sync.WaitGroup
	check := func() { defer checks.Done(); sc.checkTimeouts(now) }
	checks.Add(1)
	go check()
	<-entered
	for range 20 {
		checks.Add(1)
		go check()
	}
	// Leave the first notice blocked while subsequent checks run.
	time.Sleep(30 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Errorf("timeout notice invoked %d times for one connection, want 1", got)
	}
	peer.Close()
	checks.Wait()
}

// noticeRecordingConn stands for the TLS connection a protocol library layers
// above a SoraConn on STARTTLS: what is written to it reaches the SoraConn.
type noticeRecordingConn struct {
	net.Conn
	mu    sync.Mutex
	wrote []byte
}

func (c *noticeRecordingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.wrote = append(c.wrote, b...)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

// A protocol library swaps in its STARTTLS connection on the goroutine that
// reads, without synchronisation (go-pop3 and go-managesieve assign a plain
// field), so the provider registered with SetTimeoutNoticeConn may only be
// called on that goroutine. Calling it from the timeout goroutine raced with
// the swap; run with -race. The notice still goes to the swapped-in connection.
func TestSoraConnTimeoutNoticeConnIsAskedForOnTheReadingGoroutine(t *testing.T) {
	transport, peer := net.Pipe()
	defer peer.Close()
	notified := make(chan struct{})
	sc := NewSoraConn(transport, SoraConnConfig{
		IdleTimeout:       time.Minute,
		NoAbsoluteTimeout: true,
		OnTimeout: func(conn net.Conn, _ string) {
			defer close(notified)
			fmt.Fprint(conn, "goodbye\r\n")
		},
	})
	upgraded := &noticeRecordingConn{Conn: sc}
	var libraryConn net.Conn = sc
	SetTimeoutNoticeConn(sc, func() net.Conn { return libraryConn })

	// The library: read STLS, swap in the TLS connection, read on through it.
	served := make(chan struct{})
	go func() {
		defer close(served)
		buf := make([]byte, 16)
		if _, err := sc.Read(buf); err != nil {
			return
		}
		libraryConn = upgraded
		sc.Read(buf) // until the timeout closes the connection
	}()
	if _, err := peer.Write([]byte("STLS\r\n")); err != nil {
		t.Fatal(err)
	}
	// Nothing synchronises with the library after its swap, as with a client
	// that goes quiet after STARTTLS; give it time to start reading again.
	time.Sleep(50 * time.Millisecond)
	go io.Copy(io.Discard, peer)
	sc.checkTimeouts(time.Now().Add(time.Hour))
	<-notified
	<-served

	upgraded.mu.Lock()
	defer upgraded.mu.Unlock()
	if got := string(upgraded.wrote); got != "goodbye\r\n" {
		t.Errorf("notice written to the swapped-in connection = %q, want %q", got, "goodbye\r\n")
	}
}

// A shutdown broadcast writes from another goroutine, so NoticeConn must hand it
// the connection the library is using without calling the provider: the record
// the reading goroutine made. Before any record, and with no SoraConn at all, it
// is the connection it was given. Run with -race.
func TestNoticeConnFollowsTheRecordedConnection(t *testing.T) {
	transport, peer := net.Pipe()
	defer peer.Close()
	sc := NewSoraConn(transport, SoraConnConfig{NoAbsoluteTimeout: true})
	defer sc.Close()

	if got := NoticeConn(sc); got != sc {
		t.Fatalf("NoticeConn with nothing registered = %T, want the SoraConn itself", got)
	}
	plain, other := net.Pipe()
	defer plain.Close()
	defer other.Close()
	if got := NoticeConn(plain); got != plain {
		t.Fatalf("NoticeConn without a SoraConn = %T, want the connection given", got)
	}

	upgraded := &noticeRecordingConn{Conn: sc}
	var libraryConn net.Conn = sc
	SetTimeoutNoticeConn(sc, func() net.Conn { return libraryConn })

	// The library: read STLS, swap in the TLS connection, read on through it.
	read := make(chan struct{})
	go func() {
		buf := make([]byte, 16)
		if _, err := sc.Read(buf); err != nil {
			return
		}
		libraryConn = upgraded
		read <- struct{}{}
		sc.Read(buf)
		read <- struct{}{}
	}()
	peer.Write([]byte("STLS\r\n"))
	<-read
	peer.Write([]byte("CAPA\r\n"))
	<-read

	for name, conn := range map[string]net.Conn{"SoraConn": sc, "wrapper": unwrapConn{sc}} {
		if got := NoticeConn(conn); got != upgraded {
			t.Errorf("NoticeConn(%s) after the upgrade = %T, want the swapped-in connection", name, got)
		}
	}
}

func TestNoticeConnSuppressesUnsafeRegisteredWriter(t *testing.T) {
	transport, peer := net.Pipe()
	defer peer.Close()
	sc := NewSoraConn(transport, SoraConnConfig{NoAbsoluteTimeout: true})
	defer sc.Close()
	SetTimeoutNoticeConn(sc, func() net.Conn { return nil })
	for _, conn := range []net.Conn{sc, unwrapConn{sc}} {
		if got := NoticeConn(conn); got != nil {
			t.Fatalf("unsafe registered writer returned %T", got)
		}
	}
}
