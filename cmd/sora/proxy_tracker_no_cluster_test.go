package main

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/migadu/sora/logger"
)

// The IMAP, POP3 and ManageSieve proxies count a user's connections only through
// the cluster connection tracker. Without [cluster] there is none, so their
// max_connections_per_user and max_connections_per_user_per_ip are not applied,
// and startup must say so at WARN for the keys the block sets (#619).
func TestProxyPerUserLimitsWithoutClusterAreReported(t *testing.T) {
	for _, protocol := range []string{"IMAP", "POP3", "ManageSieve"} {
		for _, tc := range []struct {
			name             string
			perUser, perUIP  int
			wantKeys, noKeys []string
		}{
			{"per user", 1, 0, []string{"max_connections_per_user="}, []string{"max_connections_per_user_per_ip="}},
			{"per user per ip", 0, 2, []string{"max_connections_per_user_per_ip="}, []string{"max_connections_per_user="}},
			{"both", 3, 2, []string{"max_connections_per_user=", "max_connections_per_user_per_ip="}, nil},
			{"neither", 0, 0, nil, nil},
		} {
			t.Run(protocol+"/"+tc.name, func(t *testing.T) {
				logs := &syncLogBuffer{}
				prev := logger.Swap(slog.New(slog.NewTextHandler(logs, nil)))
				t.Cleanup(func() { logger.Swap(prev) })

				sink := &trackerSink{}
				tracker, _ := startConnectionTrackerForProxy(protocol, "proxy-619", "mail", tc.perUser, tc.perUIP, nil, nil, sink)
				if tracker != nil {
					tracker.Stop()
					t.Fatalf("%s proxy without a cluster got a connection tracker", protocol)
				}

				var warns []string
				for _, line := range strings.Split(logs.String(), "\n") {
					if strings.Contains(line, "level=WARN") && strings.Contains(line, "proxy-619") {
						warns = append(warns, line)
					}
				}
				if len(tc.wantKeys) == 0 {
					if len(warns) > 0 {
						t.Errorf("no per-user limit is set, but startup warned: %q", warns)
					}
					return
				}
				if len(warns) != 1 {
					t.Fatalf("want one WARN line naming proxy-619, got %q; log:\n%s", warns, logs.String())
				}
				for _, key := range tc.wantKeys {
					if !strings.Contains(warns[0], " "+key) {
						t.Errorf("warning does not name %s: %s", strings.TrimSuffix(key, "="), warns[0])
					}
				}
				for _, key := range tc.noKeys {
					if strings.Contains(warns[0], " "+key) {
						t.Errorf("warning names %s, which the block does not set: %s", strings.TrimSuffix(key, "="), warns[0])
					}
				}
			})
		}
	}
}
