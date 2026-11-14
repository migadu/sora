package imap

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// [local_cache] warmup_interval reaches the IMAP backend since #291, so a value
// it cannot parse is the one way left for the setting to be ignored. It falls
// back to the default with a WARN, like the other [local_cache] durations: the
// fallback was logged at DEBUG, so at the default level nothing said the value
// was not used. warmup_timeout is parsed the same way, and zero or a negative
// timeout would cancel every warmup before its first query, so it falls back
// too. A zero interval is kept: it means a warmup at every login.
func TestWarmupSettingsFallBackWithAWarning(t *testing.T) {
	for _, tt := range []struct {
		interval, timeout         string
		wantInterval, wantTimeout time.Duration
		warn                      string // the key a WARN must name, "" for none
	}{
		{"", "", 24 * time.Hour, 5 * time.Minute, ""},
		{"1h", "30s", time.Hour, 30 * time.Second, ""},
		{"2d", "1m", 48 * time.Hour, time.Minute, ""},
		{"0", "1m", 0, time.Minute, ""},
		{"1 day", "", 24 * time.Hour, 5 * time.Minute, "warmup_interval"},
		{"", "five minutes", 24 * time.Hour, 5 * time.Minute, "warmup_timeout"},
		{"", "0", 24 * time.Hour, 5 * time.Minute, "warmup_timeout"},
		{"", "-1m", 24 * time.Hour, 5 * time.Minute, "warmup_timeout"},
	} {
		t.Run("interval="+tt.interval+",timeout="+tt.timeout, func(t *testing.T) {
			logs := &syncLogBuffer{}
			prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer logger.Swap(prev)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			srv, err := New(ctx, "warmup-settings", "localhost", "127.0.0.1:0", &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{},
				IMAPServerOptions{
					AppendLimit:    DefaultAppendLimit,
					MaxConnections: 10,
					Config:         &config.Config{},
					WarmupInterval: tt.interval,
					WarmupTimeout:  tt.timeout,
				})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer srv.Close()

			if srv.warmupInterval != tt.wantInterval {
				t.Errorf("warmup_interval = %q: interval %v, want %v", tt.interval, srv.warmupInterval, tt.wantInterval)
			}
			if srv.warmupTimeout != tt.wantTimeout {
				t.Errorf("warmup_timeout = %q: timeout %v, want %v", tt.timeout, srv.warmupTimeout, tt.wantTimeout)
			}
			out := logs.String()
			for _, key := range []string{"warmup_interval", "warmup_timeout"} {
				warned := strings.Contains(out, "invalid "+key)
				if want := key == tt.warn; warned != want {
					t.Errorf("warmup_interval = %q, warmup_timeout = %q: WARN about %s = %v, want %v; WARN output:\n%s", tt.interval, tt.timeout, key, warned, want, out)
				}
			}
		})
	}
}
