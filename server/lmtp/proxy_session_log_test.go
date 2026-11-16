package lmtp

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
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

// A delivery from an lmtp_proxy is logged with the proxy's session ID, which the proxy's
// PROXY v2 header carries (TLV 0xE1), as proxy_session on the backend's "new session"
// line, so it can be followed from the proxy's log line (session=<id>) to the backend's.
// The LMTP backend never read it (#1369).
func TestBackendLogsProxySession(t *testing.T) {
	const proxySession = "proxysession1369"
	logs := &proxySessionLogs{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { logger.Swap(prev) })

	addr, _ := startProxiedXCLIENTBackend(t)
	conn := dialUntilListening(t, addr)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	header, err := server.GenerateProxyV2HeaderWithTLVs("192.0.2.10", 51000, "127.0.0.1", 24, "TCP4",
		map[byte][]byte{server.TLVTypeProxySessionID: []byte(proxySession)})
	if err != nil {
		t.Fatal(err)
	}
	conn.Write(header)
	r := bufio.NewReader(conn)
	if line := lmtpReply(t, r); !strings.HasPrefix(line, "220 ") {
		t.Fatalf("greeting = %q", line)
	}
	// go-smtp creates the session at LHLO.
	fmt.Fprint(conn, "LHLO proxy.example.org\r\n")
	if line := lmtpReply(t, r); !strings.HasPrefix(line, "250 ") {
		t.Fatalf("LHLO = %q", line)
	}

	if want := []string{"level=INFO", "msg=\"new session\"", "proxy_session=" + proxySession}; !logs.waitForLine(want...) {
		t.Errorf("no log line with %q", want)
	}
}
