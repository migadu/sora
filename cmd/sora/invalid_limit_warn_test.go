package main

import (
	"context"
	"log/slog"
	"net"
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

// A [[server]] limits value that does not parse is replaced by a default when the
// server is built, and that is a WARN record naming the key and the parse error, as
// for the other invalid-value fallbacks (#648). Logged at INFO, it was dropped with
// [logging] level = "warn", so a typo silently changed a limit.
func TestInvalidServerLimitsFallbackLogsAtWarn(t *testing.T) {
	tests := []struct {
		serverType string
		limits     config.ServerLimitsConfig
		build      func(*testing.T, *serverDependencies, config.ServerConfig)
		want       [][2]string // key, and the invalid value the parse error quotes
	}{
		{
			serverType: "imap",
			limits: config.ServerLimitsConfig{
				SearchRateLimitWindow: "1 min",
				SessionMemoryLimit:    "100 megabytes",
				PreviewS3MaxSize:      "5 megabytes",
			},
			build: startBackendUntilListening(startDynamicIMAPServer),
			want: [][2]string{
				{"limits.search_rate_limit_window", "1 min"},
				{"limits.session_memory_limit", "100 megabytes"},
				{"limits.preview_s3_max_size", "5 megabytes"},
			},
		},
		{
			// A zero or negative window parses, but the rate limiter replaces it
			// with the same 1 minute default.
			serverType: "imap",
			limits:     config.ServerLimitsConfig{SearchRateLimitWindow: "-1m"},
			build:      startBackendUntilListening(startDynamicIMAPServer),
			want:       [][2]string{{"limits.search_rate_limit_window", "-1m"}},
		},
		{
			serverType: "pop3",
			limits:     config.ServerLimitsConfig{SessionMemoryLimit: "100 megabytes"},
			build:      startBackendUntilListening(startDynamicPOP3Server),
			want:       [][2]string{{"limits.session_memory_limit", "100 megabytes"}},
		},
		{
			serverType: "lmtp",
			limits:     config.ServerLimitsConfig{RedirectRateWindow: "1 h"},
			build: func(t *testing.T, deps *serverDependencies, serverConfig config.ServerConfig) {
				if got := buildLMTPServerOptions(deps, serverConfig).RedirectRateWindow; got != time.Hour {
					t.Errorf("redirect_rate_window = %q gives %v, want the default 1h", serverConfig.Limits.RedirectRateWindow, got)
				}
			},
			want: [][2]string{{"limits.redirect_rate_window", "1 h"}},
		},
		{
			serverType: "http_admin_api",
			limits:     config.ServerLimitsConfig{RedirectRateWindow: "1 h"},
			build: func(t *testing.T, deps *serverDependencies, serverConfig config.ServerConfig) {
				if got := buildAdminAPIServerOptions(deps, serverConfig).RedirectRateWindow; got != time.Hour {
					t.Errorf("redirect_rate_window = %q gives %v, want the default 1h", serverConfig.Limits.RedirectRateWindow, got)
				}
			},
			want: [][2]string{{"limits.redirect_rate_window", "1 h"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.serverType, func(t *testing.T) {
			// The server's logger with [logging] level = "warn".
			logs := &syncLogBuffer{}
			prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
			t.Cleanup(func() { logger.Swap(prev) })

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
			limits := tt.limits
			serverConfig := config.ServerConfig{
				Type:   tt.serverType,
				Name:   tt.serverType + "-648",
				Addr:   addr,
				Limits: &limits,
			}
			tt.build(t, deps, serverConfig)

			lines := strings.Split(logs.String(), "\n")
			for _, kv := range tt.want {
				key, value := kv[0], kv[1]
				found := false
				for _, line := range lines {
					if strings.Contains(line, "level=WARN") && strings.Contains(line, key) &&
						strings.Contains(line, serverConfig.Name) && strings.Contains(line, value) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("%s = %q: no WARN record naming the key, the server and the error; WARN log:\n%s", key, value, logs.String())
				}
			}
		})
	}
}

// startBackendUntilListening runs a backend's start function until it accepts a
// connection, so everything it logs while building the server has been logged.
func startBackendUntilListening(start func(context.Context, *serverDependencies, config.ServerConfig, chan error)) func(*testing.T, *serverDependencies, config.ServerConfig) {
	return func(t *testing.T, deps *serverDependencies, serverConfig config.ServerConfig) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		errChan := make(chan error, 1)
		done := make(chan struct{})
		go func() {
			defer close(done)
			start(ctx, deps, serverConfig, errChan)
		}()
		t.Cleanup(func() { cancel(); <-done })

		for deadline := time.Now().Add(5 * time.Second); ; {
			select {
			case err := <-errChan:
				t.Fatalf("server failed to start: %v", err)
			default:
			}
			if c, err := net.Dial("tcp", serverConfig.Addr); err == nil {
				c.Close()
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("server did not start")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}
