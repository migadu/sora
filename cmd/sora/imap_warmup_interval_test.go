package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// [local_cache] warmup_interval reaches the IMAP backend (#291). The backend
// remembers a user's last warmup across a restart only while it is within the
// interval: it reads the warmups from the state file in the cache directory when
// it starts and writes back the ones still within the interval when it stops.
// Each case is decided the other way by the built-in 24 hours.
func TestDynamicIMAPServerUsesWarmupInterval(t *testing.T) {
	tests := []struct {
		interval string
		age      time.Duration // how long ago the user was warmed
		kept     bool
	}{
		{"1h", 2 * time.Hour, false},
		{"48h", 30 * time.Hour, true},
	}
	for _, tt := range tests {
		t.Run(tt.interval, func(t *testing.T) {
			dir := t.TempDir()
			c, err := cache.New(dir, 1<<20, 1<<20, time.Hour, time.Hour, nil)
			if err != nil {
				t.Fatalf("cache.New: %v", err)
			}
			t.Cleanup(func() { c.Close() })

			const accountID = 42
			statePath := filepath.Join(dir, ".sora_warmup_state")
			state := fmt.Sprintf("%d %d\n", accountID, time.Now().Add(-tt.age).Unix())
			if err := os.WriteFile(statePath, []byte(state), 0o600); err != nil {
				t.Fatal(err)
			}

			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := l.Addr().String()
			l.Close()

			cfg := config.NewDefaultConfig()
			cfg.LocalCache.EnableWarmup = true
			cfg.LocalCache.WarmupInterval = tt.interval
			deps := &serverDependencies{
				storage:       &storage.S3Storage{},
				resilientDB:   &resilient.ResilientDatabase{},
				uploadWorker:  &uploader.UploadWorker{},
				cacheInstance: c,
				hostname:      "localhost",
				config:        cfg,
				serverManager: &serverManager{},
			}
			serverConfig := config.ServerConfig{Type: "imap", Name: "imap-warmup-interval", Addr: addr}

			ctx, cancel := context.WithCancel(context.Background())
			errChan := make(chan error, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				startDynamicIMAPServer(ctx, deps, serverConfig, errChan)
			}()
			stop := func() { cancel(); <-done }
			t.Cleanup(stop)

			for deadline := time.Now().Add(5 * time.Second); ; {
				select {
				case err := <-errChan:
					t.Fatalf("server failed to start: %v", err)
				default:
				}
				if conn, err := net.Dial("tcp", addr); err == nil {
					conn.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("server did not start")
				}
				time.Sleep(10 * time.Millisecond)
			}

			// The server writes the state file back before it stops listening.
			stop()
			data, err := os.ReadFile(statePath)
			if err != nil {
				t.Fatalf("warmup state after shutdown: %v", err)
			}
			kept := strings.HasPrefix(string(data), fmt.Sprintf("%d ", accountID))
			if kept != tt.kept {
				t.Errorf("warmup_interval = %q: a warmup %v old kept across the restart = %v, want %v", tt.interval, tt.age, kept, tt.kept)
			}
		})
	}
}
