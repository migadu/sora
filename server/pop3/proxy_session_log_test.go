package pop3

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/server"
)

// proxySessionLogs is a log sink the server's goroutines can write to.
type proxySessionLogs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *proxySessionLogs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// waitForLine waits up to 3s for a log line that contains every one of parts.
func (l *proxySessionLogs) waitForLine(parts ...string) bool {
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		l.mu.Lock()
		text := l.buf.String()
		l.mu.Unlock()
	lines:
		for _, line := range strings.Split(text, "\n") {
			for _, part := range parts {
				if !strings.Contains(line, part) {
					continue lines
				}
			}
			return true
		}
	}
	return false
}

// A connection from a pop3_proxy is logged with the proxy's session ID as proxy_session,
// whether the PROXY v2 header carries it (TLV 0xE1) or XCLIENT names it (SESSION=), so a
// POP3 session can be followed from the proxy's log line (session=<id>) to the backend's.
// Only the IMAP backend logged it; the POP3 backend kept the XCLIENT one in a debug line
// as session_id and never read the header's (#1369).
func TestBackendLogsProxySession(t *testing.T) {
	const proxySession = "proxysession1369"
	for _, tc := range []struct {
		name      string
		proxy     bool   // the listener takes PROXY headers
		header    []byte // sent before the greeting
		xclient   string // sent after it
		wantParts []string
	}{
		{name: "PROXY v2 header", proxy: true, wantParts: []string{"level=INFO", "msg=connected", "proxy_session=" + proxySession}},
		{name: "XCLIENT", xclient: "XCLIENT ADDR=203.0.113.5 PORT=51000 SESSION=" + proxySession + " TTL=5", wantParts: []string{"level=INFO", "proxy_session=" + proxySession}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := &proxySessionLogs{}
			prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
			t.Cleanup(func() { logger.Swap(prev) })

			s, addr := newReloadTestServer(t, POP3ServerOptions{
				TrustedNetworks: []string{"127.0.0.0/8"},
				ProxyProtocol:   tc.proxy,
				CommandTimeout:  time.Minute,
			})
			startListenerTestServer(t, s, addr)
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			if tc.proxy {
				header, err := server.GenerateProxyV2HeaderWithTLVs("192.0.2.10", 51000, "127.0.0.1", 110, "TCP4",
					map[byte][]byte{server.TLVTypeProxySessionID: []byte(proxySession)})
				if err != nil {
					t.Fatal(err)
				}
				conn.Write(header)
			}
			r := bufio.NewReader(conn)
			if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
				t.Fatalf("greeting = %q, %v", line, err)
			}
			if tc.xclient != "" {
				fmt.Fprintf(conn, "%s\r\n", tc.xclient)
				if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
					t.Fatalf("XCLIENT = %q, %v", line, err)
				}
			}

			if !logs.waitForLine(tc.wantParts...) {
				t.Errorf("no log line with %q", tc.wantParts)
			}
		})
	}
}
