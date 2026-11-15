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

// A connection is announced with one "connected" line. newSession logged it twice at
// INFO, once unconditionally and once more with or without proxy_session (#299).
func TestNewSessionLogsConnectedOnce(t *testing.T) {
	logs := &syncLogBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { logger.Swap(prev) })

	_, addr, _ := newTTLTestServer(t, "connected-once")
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	// The session logs before go-imap writes the greeting.
	if greeting, err := bufio.NewReader(c).ReadString('\n'); err != nil {
		t.Fatalf("no greeting: %v", err)
	} else if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("greeting = %q", greeting)
	}

	var connected []string
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "msg=connected") && strings.Contains(line, "protocol=IMAP-connected-once") {
			connected = append(connected, line)
		}
	}
	if len(connected) != 1 {
		t.Errorf("%d \"connected\" lines for one connection, want 1:\n%s", len(connected), strings.Join(connected, "\n"))
	}
}
