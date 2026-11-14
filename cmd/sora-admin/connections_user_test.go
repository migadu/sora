package main

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/adminapi"
)

// startTrackerAdminAPI serves the Admin API with the given connection trackers on a free
// local port and returns the sora-admin configuration that reaches it.
func startTrackerAdminAPI(t *testing.T, trackers map[string]*server.ConnectionTracker) AdminConfig {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	const apiKey = "test-admin-api-key-0123456789"

	srv, err := adminapi.New(nil, adminapi.ServerOptions{
		Name:               "admin-api",
		Addr:               addr,
		APIKey:             apiKey,
		ConnectionTrackers: func() map[string]*server.ConnectionTracker { return trackers },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv.Serve(ctx, make(chan error, 1))

	cfg := AdminConfig{HTTPAPIAddr: "http://" + addr, HTTPAPIKey: apiKey}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get(cfg.HTTPAPIAddr + "/")
		if err == nil {
			resp.Body.Close()
			return cfg
		}
		if time.Now().After(deadline) {
			t.Fatalf("Admin API did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// rowFields returns the fields of the first output line that starts with prefix.
func rowFields(out, prefix string) []string {
	for line := range strings.SplitSeq(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			return strings.Fields(line)
		}
	}
	return nil
}

// "connections list --user" reads GET /admin/connections/user/{email}. Its --protocol and
// --instance filters match the entry's tracker key and its Protocol column prints the
// entry's protocol, as without --user. The per-user endpoint sent the tracker key as
// protocol and no instance, so both filters dropped every row and the Protocol column
// showed the key; "stats connection --user" grouped its By Protocol lines by the key.
func TestUserConnectionsListFiltersByProtocolAndInstance(t *testing.T) {
	// An IMAP proxy in cluster mode: tracker key <PROTOCOL>-<node_id>-<server name>.
	tracker := server.NewConnectionTracker("IMAP", "imap-proxy", "host", "node-1-imap-proxy", nil, 0, 0, 0, true)
	t.Cleanup(tracker.Stop)
	if err := tracker.RegisterConnection(context.Background(), 123, "anna@example.com", "IMAP", "192.0.2.1:50000"); err != nil {
		t.Fatal(err)
	}
	cfg := startTrackerAdminAPI(t, map[string]*server.ConnectionTracker{"IMAP-node-1-imap-proxy": tracker})
	ctx := context.Background()

	for _, tc := range []struct {
		name, protocol, instance string
		listed                   bool
	}{
		{"no filter", "", "", true},
		{"--protocol IMAP", "IMAP", "", true},
		{"--protocol imap", "imap", "", true},
		{"--protocol POP3", "POP3", "", false},
		{"--instance node-1", "", "node-1", true},
		{"--instance node-2", "", "node-2", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStdout(t, func() error {
				return listConnections(ctx, cfg, "anna@example.com", "", tc.protocol, tc.instance)
			})
			row := rowFields(out, "anna@example.com")
			if !tc.listed {
				if row != nil || !strings.Contains(out, "No connections matching the specified filters.") {
					t.Errorf("session listed although the filter does not match it:\n%s", out)
				}
				return
			}
			if row == nil {
				t.Fatalf("session not listed:\n%s", out)
			}
			if len(row) < 3 || row[1] != "IMAP" || row[2] != "node-1-imap-proxy" {
				t.Errorf("row %q, want Protocol IMAP and Instance node-1-imap-proxy:\n%s", row, out)
			}
		})
	}

	t.Run("stats connection --user", func(t *testing.T) {
		out := captureStdout(t, func() error { return showConnectionStats(ctx, cfg, "anna@example.com", true) })
		if row := rowFields(out, "IMAP:"); len(row) != 2 || row[1] != "1" {
			t.Errorf("By Protocol has no line \"IMAP: 1\":\n%s", out)
		}
		if row := rowFields(out, "IMAP "); len(row) < 2 || row[1] != "node-1-imap-proxy" {
			t.Errorf("Details row %q, want Protocol IMAP and Instance node-1-imap-proxy:\n%s", row, out)
		}
	})
}
