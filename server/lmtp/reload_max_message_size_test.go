package lmtp

import (
	"bytes"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
)

// reloadLogs is a bytes.Buffer safe to log into from several goroutines.
type reloadLogs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *reloadLogs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *reloadLogs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// A SIGHUP whose max_message_size does not parse keeps the running limit and says so
// at WARN, naming the server, the key, the error and the kept value; it does not report
// max_message_size as reloaded (#669). Before, the reload replaced the running limit
// with the 50 MB default, so a node running "100mb" that reloaded "100 MiB" refused
// every message between 50 and 100 MB with a permanent 552. A value that parses still
// applies, capped at the largest message sora can store, as at start-up.
func TestReloadConfigMaxMessageSize(t *testing.T) {
	logs := &reloadLogs{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { logger.Swap(prev) })

	const running = 100 << 20
	for _, tt := range []struct {
		name         string
		reload       string
		want         int64
		wantReloaded bool
		wantWarn     bool
	}{
		{name: "unparsable keeps the running limit", reload: "100 MiB", want: running, wantWarn: true},
		{name: "unchanged", reload: "100mb", want: running},
		{name: "changed", reload: "60mb", want: 60 << 20, wantReloaded: true},
		{name: "omitted is the default", reload: "", want: DefaultMaxMessageSize, wantReloaded: true},
		{name: "above storable is clamped", reload: "3gb", want: math.MaxInt32, wantReloaded: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			name := "lmtp-" + strings.ReplaceAll(tt.name, " ", "-")
			b := &LMTPServerBackend{name: name}
			b.settings.Store(&reloadableSettings{maxMessageSize: running})

			logsBefore := len(logs.String())
			if err := b.ReloadConfig(config.ServerConfig{Name: name, Type: "lmtp", MaxMessageSize: tt.reload}); err != nil {
				t.Fatal(err)
			}
			logged := logs.String()[logsBefore:]

			if got := b.settings.Load().maxMessageSize; got != tt.want {
				t.Errorf("max_message_size after reloading %q = %d, want %d", tt.reload, got, tt.want)
			}
			reported, warned := false, false
			for _, line := range strings.Split(logged, "\n") {
				if !strings.Contains(line, "max_message_size") || !strings.Contains(line, "name="+name) {
					continue
				}
				if strings.Contains(line, "config reloaded") {
					reported = true
				}
				if strings.Contains(line, "level=WARN") && strings.Contains(line, "error=") &&
					strings.Contains(line, "running="+strconv.Itoa(running)) {
					warned = true
				}
			}
			if reported != tt.wantReloaded {
				t.Errorf("reloading %q reported max_message_size as reloaded: %v, want %v; logged:\n%s", tt.reload, reported, tt.wantReloaded, logged)
			}
			if warned != tt.wantWarn {
				t.Errorf("WARN naming max_message_size, the error and the kept limit: %v, want %v; logged:\n%s", warned, tt.wantWarn, logged)
			}
		})
	}
}
