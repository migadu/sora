package server

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func newTestProxyListener(t *testing.T, timeout string) (*ProxyProtocolListener, string) {
	t.Helper()
	reader, err := NewProxyProtocolReader("TEST", ProxyProtocolConfig{
		Enabled:        true,
		Mode:           "required",
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		Timeout:        timeout,
	})
	if err != nil {
		t.Fatalf("failed to create PROXY reader: %v", err)
	}
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	pl := NewProxyProtocolListener(tcpListener, reader, "TEST")
	t.Cleanup(func() { pl.Close() })
	return pl, tcpListener.Addr().String()
}

// TestProxyProtocolListenerNoHeadOfLineBlocking pins the concurrency property
// that motivated the async design: a peer that connects and never sends its
// PROXY header must NOT delay other clients. Before this design the header
// was read serially in the accept path, so with a 5s required-mode timeout a
// single misconfigured peer (a proxy without remote_use_proxy_protocol, a TCP
// health probe) dribbling connections starved the whole listener — observed
// in production as fleet-wide backend-greeting timeouts.
func TestProxyProtocolListenerNoHeadOfLineBlocking(t *testing.T) {
	pl, addr := newTestProxyListener(t, "3s")

	// Silent peer first: connects, never sends a header.
	silent, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("silent dial failed: %v", err)
	}
	defer silent.Close()

	// Give the listener time to accept the silent conn and park its parser.
	time.Sleep(100 * time.Millisecond)

	// Well-behaved peer second: header plus payload in one write.
	good, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("good dial failed: %v", err)
	}
	defer good.Close()
	if _, err := good.Write([]byte("PROXY TCP4 192.0.2.7 127.0.0.1 51000 143\r\nHELLO")); err != nil {
		t.Fatalf("good write failed: %v", err)
	}

	// The good conn must be delivered well within the 3s header timeout the
	// silent conn is still burning.
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	resCh := make(chan acceptResult, 1)
	go func() {
		c, err := pl.Accept()
		resCh <- acceptResult{c, err}
	}()

	start := time.Now()
	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatalf("Accept failed: %v", res.err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("Accept took %v; the silent peer head-of-line blocked the good one", elapsed)
		}
		info := GetProxyProtocolInfo(res.conn)
		if info == nil || info.SrcIP != "192.0.2.7" {
			t.Errorf("expected PROXY info SrcIP=192.0.2.7, got %+v", info)
		}
		// The payload written alongside the header must read through intact.
		buf := make([]byte, 5)
		res.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(res.conn, buf); err != nil || string(buf) != "HELLO" {
			t.Errorf("payload read through PROXY conn: %q, %v", buf, err)
		}
		res.conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return within 2s: silent peer blocked the accept path")
	}

	// The silent peer must be rejected once its header timeout expires
	// (required mode): its connection gets closed, never delivered.
	silent.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if _, err := silent.Read(buf); err == nil {
		t.Error("silent conn read succeeded; expected close after header timeout")
	}
}

// TestProxyProtocolListenerCloseUnblocksAccept verifies shutdown: Close must
// release a blocked Accept with a closed-listener error, and repeated Accept
// calls must keep failing rather than block (several accept loops treat
// errors as transient and immediately re-call Accept).
func TestProxyProtocolListenerCloseUnblocksAccept(t *testing.T) {
	pl, _ := newTestProxyListener(t, "1s")

	errCh := make(chan error, 1)
	go func() {
		_, err := pl.Accept()
		errCh <- err
	}()

	time.Sleep(50 * time.Millisecond)
	pl.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Accept returned a conn after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not unblock after Close")
	}

	// Sticky: subsequent Accept calls fail immediately.
	for i := 0; i < 3; i++ {
		done := make(chan error, 1)
		go func() {
			_, err := pl.Accept()
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("post-Close Accept returned a conn")
			}
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("post-Close Accept error should wrap net.ErrClosed, got %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("post-Close Accept blocked instead of failing")
		}
	}
}

// TestProxyProtocolListenerConcurrentClients verifies many clients with valid
// headers all get through concurrently and carry their own PROXY info.
func TestProxyProtocolListenerConcurrentClients(t *testing.T) {
	pl, addr := newTestProxyListener(t, "3s")

	const n = 20
	for i := 0; i < n; i++ {
		go func(i int) {
			c, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				return
			}
			// Distinct source IP per client so delivery can be verified.
			fmt.Fprintf(c, "PROXY TCP4 192.0.2.%d 127.0.0.1 51000 143\r\n", i+1)
			// Hold the conn open until the test ends.
			buf := make([]byte, 1)
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			c.Read(buf)
			c.Close()
		}(i)
	}

	seen := make(map[string]bool)
	deadline := time.After(5 * time.Second)
	for len(seen) < n {
		type res struct {
			conn net.Conn
			err  error
		}
		rc := make(chan res, 1)
		go func() {
			c, err := pl.Accept()
			rc <- res{c, err}
		}()
		select {
		case r := <-rc:
			if r.err != nil {
				t.Fatalf("Accept failed after %d conns: %v", len(seen), r.err)
			}
			info := GetProxyProtocolInfo(r.conn)
			if info == nil {
				t.Fatal("accepted conn without PROXY info")
			}
			if seen[info.SrcIP] {
				t.Fatalf("duplicate PROXY info for %s", info.SrcIP)
			}
			seen[info.SrcIP] = true
			defer r.conn.Close()
		case <-deadline:
			t.Fatalf("only %d/%d connections delivered within 5s", len(seen), n)
		}
	}
}

// TestSoraListenerSkipsTLSProbeForProxyConns pins the accept-path latency fix
// from the 2026-07-05 production incident: SoraListener's TLS-on-plaintext
// probe peeks with a 100ms deadline, and sora's protocols are
// server-speaks-first — after the PROXY header the peer sends NOTHING until
// the greeting, so probing PROXY-validated connections burned the full 100ms
// per connection SERIALLY in the accept loop (~10 accepts/s, listener
// collapse under login load). PROXY-validated conns must skip the probe:
// accepting a batch must take far less than batch×100ms.
func TestSoraListenerSkipsTLSProbeForProxyConns(t *testing.T) {
	pl, addr := newTestProxyListener(t, "3s")
	sl := NewSoraListener(pl, SoraConnConfig{Protocol: "test"})

	const n = 10
	for i := 0; i < n; i++ {
		go func(i int) {
			c, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				return
			}
			// Header only — then wait for a greeting like a real proxy does.
			fmt.Fprintf(c, "PROXY TCP4 192.0.2.%d 127.0.0.1 51000 143\r\n", i+1)
			buf := make([]byte, 1)
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			c.Read(buf)
			c.Close()
		}(i)
	}

	start := time.Now()
	var conns []net.Conn
	for len(conns) < n {
		c, err := sl.Accept()
		if err != nil {
			t.Fatalf("Accept failed after %d conns: %v", len(conns), err)
		}
		conns = append(conns, c)
	}
	elapsed := time.Since(start)
	for _, c := range conns {
		if GetProxyProtocolInfo(c) == nil {
			t.Error("accepted conn lost its PROXY info through SoraListener")
		}
		c.Close()
	}

	// With the probe skipped, accepting 10 conns is effectively instant.
	// With the probe (the bug), it takes >= 10 × 100ms = 1s serially.
	if elapsed > 500*time.Millisecond {
		t.Errorf("accepting %d PROXY conns took %v; the TLS probe is stalling the accept path", n, elapsed)
	}
}

// TestSoraListenerAcceptInstantForDirectPlaintext pins the direct-client half
// of the accept-path fix: the TLS-on-plaintext probe no longer runs in the
// accept loop at all (it moved to the connection's first Read), so accepting
// silent direct connections is instant. Before the fix each accept burned the
// probe's 100ms peek deadline serially — same stall class as the 2026-07-05
// incident, but for direct plaintext clients.
func TestSoraListenerAcceptInstantForDirectPlaintext(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer tcpListener.Close()
	sl := NewSoraListener(tcpListener, SoraConnConfig{Protocol: "test"})

	const n = 10
	for i := 0; i < n; i++ {
		go func() {
			c, err := net.DialTimeout("tcp", tcpListener.Addr().String(), 5*time.Second)
			if err != nil {
				return
			}
			// Silent: a real client of a server-speaks-first protocol sends
			// nothing until it receives the greeting.
			buf := make([]byte, 1)
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			c.Read(buf)
			c.Close()
		}()
	}

	start := time.Now()
	var conns []net.Conn
	for len(conns) < n {
		c, err := sl.Accept()
		if err != nil {
			t.Fatalf("Accept failed after %d conns: %v", len(conns), err)
		}
		conns = append(conns, c)
	}
	elapsed := time.Since(start)
	for _, c := range conns {
		c.Close()
	}
	// Pre-fix: n × 100ms serial probe = 1s minimum. Post-fix: instant.
	if elapsed > 500*time.Millisecond {
		t.Errorf("accepting %d silent plaintext conns took %v; the TLS probe is back in the accept path", n, elapsed)
	}
}

// TestSoraConnFirstReadRejectsTLSOnPlaintext verifies the probe still works
// from its new home in the first Read: a TLS ClientHello on a plaintext port
// is rejected with the helpful error message, and a normal plaintext client
// reads through transparently.
func TestSoraConnFirstReadRejectsTLSOnPlaintext(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer tcpListener.Close()
	sl := NewSoraListener(tcpListener, SoraConnConfig{Protocol: "test"})

	t.Run("TLS ClientHello rejected", func(t *testing.T) {
		client, err := net.DialTimeout("tcp", tcpListener.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		defer client.Close()
		// TLS record header: handshake(0x16), TLS 1.x (0x03 0x01)
		client.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x02, 0x03})

		srvConn, err := sl.Accept()
		if err != nil {
			t.Fatalf("Accept failed: %v", err)
		}
		defer srvConn.Close()
		srvConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		if _, err := srvConn.Read(buf); !errors.Is(err, ErrTLSOnPlainPort) {
			t.Fatalf("first Read: want ErrTLSOnPlainPort, got %v", err)
		}
		// The client must receive the diagnostic message before the close.
		client.SetReadDeadline(time.Now().Add(2 * time.Second))
		reply := make([]byte, 256)
		rn, _ := client.Read(reply)
		if !strings.Contains(string(reply[:rn]), "TLS connection attempted on plain-text port") {
			t.Errorf("client did not receive rejection message, got %q", reply[:rn])
		}
	})

	t.Run("plaintext passes through", func(t *testing.T) {
		client, err := net.DialTimeout("tcp", tcpListener.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		defer client.Close()
		client.Write([]byte("HELLO\r\n"))

		srvConn, err := sl.Accept()
		if err != nil {
			t.Fatalf("Accept failed: %v", err)
		}
		defer srvConn.Close()
		srvConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 7)
		if _, err := io.ReadFull(srvConn, buf); err != nil || string(buf) != "HELLO\r\n" {
			t.Fatalf("plaintext read through probe: %q, %v", buf, err)
		}
	})
}

// TestWrapProxyProtocolHTTPClientAddr pins the net/http variant: delivered
// conns must report the PROXY-forwarded client address from RemoteAddr()
// (net/http derives r.RemoteAddr from it — allowed_hosts and rate limiting
// depend on seeing the real client, not the LB).
func TestWrapProxyProtocolHTTPClientAddr(t *testing.T) {
	reader, err := NewProxyProtocolReader("TEST-HTTP", ProxyProtocolConfig{
		Enabled:        true,
		Mode:           "required",
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		Timeout:        "3s",
	})
	if err != nil {
		t.Fatalf("failed to create PROXY reader: %v", err)
	}
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	hl := WrapProxyProtocolHTTP(tcpListener, reader, "TEST-HTTP")
	defer hl.Close()

	go func() {
		c, err := net.DialTimeout("tcp", tcpListener.Addr().String(), 5*time.Second)
		if err != nil {
			return
		}
		fmt.Fprintf(c, "PROXY TCP4 192.0.2.42 127.0.0.1 4242 8080\r\n")
		buf := make([]byte, 1)
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		c.Read(buf)
		c.Close()
	}()

	conn, err := hl.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	defer conn.Close()

	addr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || addr.IP.String() != "192.0.2.42" || addr.Port != 4242 {
		t.Errorf("RemoteAddr must report the forwarded client, got %v", conn.RemoteAddr())
	}
	if info := GetProxyProtocolInfo(conn); info == nil || info.SrcIP != "192.0.2.42" {
		t.Errorf("PROXY info must remain reachable through the HTTP conn, got %+v", info)
	}
}

// TestProxyProtocolListenerSurvivesBadHeader pins the error-containment fix
// for the net/http stacks: a connection with a malformed PROXY header (or
// from an untrusted source) must be closed and NEVER surface as an Accept
// error. The old per-package HTTP listeners returned it, and net/http treats
// non-temporary Accept errors as fatal — a single bad connection killed the
// whole API listener.
func TestProxyProtocolListenerSurvivesBadHeader(t *testing.T) {
	pl, addr := newTestProxyListener(t, "2s")

	// Malformed header from a trusted source.
	bad, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("bad dial failed: %v", err)
	}
	defer bad.Close()
	bad.Write([]byte("NOT A PROXY HEADER AT ALL\r\n"))

	time.Sleep(200 * time.Millisecond)

	// A good connection afterwards must still be delivered.
	good, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("good dial failed: %v", err)
	}
	defer good.Close()
	good.Write([]byte("PROXY TCP4 192.0.2.8 127.0.0.1 51001 143\r\n"))

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := pl.Accept()
		if err != nil {
			t.Errorf("Accept returned an error after a bad-header conn (would kill http.Server.Serve): %v", err)
			return
		}
		defer conn.Close()
		if info := GetProxyProtocolInfo(conn); info == nil || info.SrcIP != "192.0.2.8" {
			t.Errorf("expected the good conn (192.0.2.8), got %+v", info)
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Accept blocked after a bad-header conn")
	}
}
