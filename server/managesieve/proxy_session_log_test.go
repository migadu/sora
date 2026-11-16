package managesieve

import (
	"bufio"
	"bytes"
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

// A connection from a managesieve_proxy is logged with the proxy's session ID, which the
// proxy's PROXY v2 header carries (TLV 0xE1), as proxy_session on its INFO "connected"
// line, so a ManageSieve session can be followed from the proxy's log line
// (session=<id>) to the backend's. The ManageSieve backend never read it and announced a
// connection only at DEBUG (#1369).
func TestBackendLogsProxySession(t *testing.T) {
	const proxySession = "proxysession1369"
	logs := &proxySessionLogs{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { logger.Swap(prev) })

	_, addr := startListenerTestServer(t, ManageSieveServerOptions{
		CommandTimeout:  time.Minute,
		MaxConnections:  10,
		ProxyProtocol:   true,
		TrustedNetworks: []string{"127.0.0.0/8"},
	})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	header, err := server.GenerateProxyV2HeaderWithTLVs("192.0.2.10", 51000, "127.0.0.1", 4190, "TCP4",
		map[byte][]byte{server.TLVTypeProxySessionID: []byte(proxySession)})
	if err != nil {
		t.Fatal(err)
	}
	conn.Write(header)
	for r := bufio.NewReader(conn); ; {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("greeting: %v", err)
		}
		if strings.HasPrefix(line, "OK") {
			break
		}
	}

	if want := []string{"level=INFO", "msg=connected", "proxy_session=" + proxySession}; !logs.waitForLine(want...) {
		t.Errorf("no log line with %q", want)
	}
}
