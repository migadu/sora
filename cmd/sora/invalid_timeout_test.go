package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// An unparsable command_timeout gives a backend the value an absent key gets,
// not the start function's own literal (#295): 30m for IMAP (RFC 9051 §5.4
// autologout floor), 10m for POP3 (RFC 1939 §3). It used to be 5m and 2m.
func TestDynamicBackendInvalidCommandTimeoutUsesTheDefault(t *testing.T) {
	tests := []struct {
		serverType string
		start      func(context.Context, *serverDependencies, config.ServerConfig, chan error)
		want       time.Duration
	}{
		{"imap", startDynamicIMAPServer, 30 * time.Minute},
		{"pop3", startDynamicPOP3Server, 10 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.serverType, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := l.Addr().String()
			l.Close()

			deps := &serverDependencies{
				storage:       &storage.S3Storage{},
				resilientDB:   &resilient.ResilientDatabase{},
				uploadWorker:  &uploader.UploadWorker{},
				cacheInstance: &cache.Cache{},
				hostname:      "localhost",
				config:        config.NewDefaultConfig(),
				serverManager: &serverManager{},
			}
			serverConfig := config.ServerConfig{
				Type:     tt.serverType,
				Name:     tt.serverType + "-invalid-timeout",
				Addr:     addr,
				Timeouts: &config.ServerTimeoutsConfig{CommandTimeout: "30 min"},
			}

			gauge := metrics.CommandTimeoutThresholdSeconds.WithLabelValues(tt.serverType)
			gauge.Set(-1)

			ctx, cancel := context.WithCancel(context.Background())
			errChan := make(chan error, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				tt.start(ctx, deps, serverConfig, errChan)
			}()
			t.Cleanup(func() { cancel(); <-done })

			// The server reports its idle timeout when it is built, before it listens.
			for deadline := time.Now().Add(5 * time.Second); ; {
				select {
				case err := <-errChan:
					t.Fatalf("server failed to start: %v", err)
				default:
				}
				if c, err := net.Dial("tcp", addr); err == nil {
					c.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("server did not start")
				}
				time.Sleep(10 * time.Millisecond)
			}

			if got := time.Duration(testutil.ToFloat64(gauge) * float64(time.Second)); got != tt.want {
				t.Errorf("command_timeout = \"30 min\" gives an idle timeout of %v, want the default %v", got, tt.want)
			}
		})
	}
}
