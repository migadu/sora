package imap

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// A client_filters entry with a pattern that does not compile is left out, so the
// capability it was meant to hide stays advertised. Config validation refuses such
// a pattern (#959); a server built without it still says so at WARN, naming the
// key and the pattern. The skip was logged at DEBUG, which the default level drops.
func TestClientFilterInvalidPatternSkippedWithAWarning(t *testing.T) {
	for _, tt := range []struct {
		key, pattern string
		filter       config.ClientCapabilityFilter
	}{
		{"client_name", "Mail(", config.ClientCapabilityFilter{ClientName: "Mail("}},
		{"client_version", "[1-", config.ClientCapabilityFilter{ClientName: "^Mail$", ClientVersion: "[1-"}},
		{"ja4_fingerprints", "t13d**", config.ClientCapabilityFilter{JA4Fingerprints: []string{"^t13d1516h2_", "t13d**"}}},
	} {
		t.Run(tt.key, func(t *testing.T) {
			logs := &syncLogBuffer{}
			prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer logger.Swap(prev)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tt.filter.DisableCaps = []string{"IDLE"}
			srv, err := New(ctx, "client-filters", "localhost", "127.0.0.1:0", &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{},
				IMAPServerOptions{
					AppendLimit:    DefaultAppendLimit,
					MaxConnections: 10,
					Config:         &config.Config{},
					CapabilityFilters: []config.ClientCapabilityFilter{
						{ClientName: "^ExampleMail$", DisableCaps: []string{"CONDSTORE"}},
						tt.filter,
					},
				})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer srv.Close()

			if len(srv.capFilters) != 1 || srv.capFilters[0].ClientName != "^ExampleMail$" {
				t.Errorf("%s = %q: filters %+v, want only the valid one", tt.key, tt.pattern, srv.capFilters)
			}
			out := logs.String()
			for _, want := range []string{"client_filters", tt.key, tt.pattern, "client-filters"} {
				if !strings.Contains(out, want) {
					t.Errorf("%s = %q: no WARN naming %q; WARN output:\n%s", tt.key, tt.pattern, want, out)
				}
			}
		})
	}
}
