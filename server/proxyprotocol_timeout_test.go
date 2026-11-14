package server

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/logger"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// proxy_protocol_timeout takes the syntax of every other duration key, whole
// days included, and a value it cannot use falls back to the 5s default with a
// WARN: it was parsed with time.ParseDuration and the fallback logged at DEBUG
// (#417). Zero or a negative value would set the read deadline in the past and
// fail every PROXY header, so it falls back too.
func TestProxyProtocolTimeoutParsing(t *testing.T) {
	logs := &lockedBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { logger.Swap(prev) })

	for _, tt := range []struct {
		in   string
		want time.Duration
		warn bool
	}{
		{"", 5 * time.Second, false},
		{"3s", 3 * time.Second, false},
		{"1d", 24 * time.Hour, false},
		{"5 seconds", 5 * time.Second, true},
		{"0", 5 * time.Second, true},
		{"-1s", 5 * time.Second, true},
	} {
		before := len(logs.String())
		reader, err := NewProxyProtocolReader("TEST", ProxyProtocolConfig{Enabled: true, Timeout: tt.in})
		if err != nil {
			t.Fatalf("timeout %q: %v", tt.in, err)
		}
		if reader.timeout != tt.want {
			t.Errorf("timeout %q = %v, want %v", tt.in, reader.timeout, tt.want)
		}
		logged := logs.String()[before:]
		if warned := strings.Contains(logged, "level=WARN") && strings.Contains(logged, tt.in); warned != tt.warn {
			t.Errorf("timeout %q: WARN logged = %v, want %v; log: %q", tt.in, warned, tt.warn, logged)
		}
	}
}
