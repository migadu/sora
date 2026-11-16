package imap

import (
	"bufio"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/logger"
)

// An imap_proxy that forwards with the ID command names its session in x-session-id. The
// backend logs it as proxy_session, as it does the one a PROXY v2 header carries, so the
// session can be followed from the proxy's log line (session=<id>) to the backend's. It
// was kept only in a debug line, as session_id (#1369).
func TestIDForwardingLogsProxySession(t *testing.T) {
	logs := &syncLogBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { logger.Swap(prev) })

	_, addr, _ := newTTLTestServer(t, "id-proxy-session")
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(c)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	c.Write([]byte(`a ID ("name" "proxy" "x-session-id" "proxysession1369" "x-proxy-ttl" "5" "x-originating-ip" "198.51.100.7")` + "\r\n"))
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("ID: %v", err)
		}
		if strings.HasPrefix(line, "a ") {
			if !strings.HasPrefix(line, "a OK") {
				t.Fatalf("ID = %q", line)
			}
			break
		}
	}

	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "level=INFO") && strings.Contains(line, "proxy_session=proxysession1369") {
			return
		}
	}
	t.Errorf("no INFO line with proxy_session=proxysession1369:\n%s", logs.String())
}
