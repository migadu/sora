package pop3proxy

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"
)

// TestTimeoutNoticesCarryNoResponseCode: the notice written before a connection is
// closed for a timeout answers no command and carries no response code. [IN-USE]
// (RFC 2449 section 8.1.2) says a login succeeded with the maildrop locked, and no
// RFC 2449 or RFC 3206 code describes a timeout.
func TestTimeoutNoticesCarryNoResponseCode(t *testing.T) {
	srv := &POP3ProxyServer{name: "test", hostname: "test-host"}
	for _, tc := range []struct{ reason, want string }{
		{"idle", "-ERR Idle timeout, please reconnect\r\n"},
		{"slow_throughput", "-ERR Connection too slow, please reconnect\r\n"},
		{"session_max", "-ERR Maximum session duration exceeded, please reconnect\r\n"},
		{"other", "-ERR Connection timeout, please reconnect\r\n"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer c1.Close()
			defer c2.Close()
			go srv.connConfig().OnTimeout(c1, tc.reason)
			_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
			line, err := bufio.NewReader(c2).ReadString('\n')
			if err != nil {
				t.Fatalf("reading the %s notice: %v", tc.reason, err)
			}
			if line != tc.want {
				t.Errorf("%s notice = %q, want %q", tc.reason, line, tc.want)
			}
		})
	}
}

// TestRelayIdleTimeoutNoticeCarriesNoResponseCode: without command_timeout the
// relay enforces auth_idle_timeout itself, and its notice carries no response code
// either.
func TestRelayIdleTimeoutNoticeCarriesNoResponseCode(t *testing.T) {
	clientA, clientB := net.Pipe()
	backendA, backendB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()
	defer backendA.Close()
	defer backendB.Close()

	sess := &POP3ProxySession{
		server:       &POP3ProxyServer{name: "test", hostname: "test-host"},
		settings:     &reloadableSettings{authIdleTimeout: 50 * time.Millisecond},
		clientConn:   clientA,
		listenerConn: clientA,
		clientReader: bufio.NewReader(clientA),
		backendConn:  backendA,
		ctx:          context.Background(),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.filteredCopyClientToBackend()
	}()

	_ = clientB.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(clientB).ReadString('\n')
	if err != nil {
		t.Fatalf("reading the idle notice: %v", err)
	}
	if want := "-ERR Idle timeout, please reconnect\r\n"; line != want {
		t.Errorf("idle notice = %q, want %q", line, want)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("relay still running after the idle timeout")
	}
}
