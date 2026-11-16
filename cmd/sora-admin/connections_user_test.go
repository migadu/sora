package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
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

// gossipRegister hands each tracker the register event another node gossips for a session.
func gossipRegister(t *testing.T, accountID int64, username, clientAddr string, trackers ...*server.ConnectionTracker) {
	t.Helper()
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(server.ConnectionEvent{
		Type:       server.ConnectionEventRegister,
		EventID:    fmt.Sprintf("node-2-%d-%s", accountID, clientAddr),
		AccountID:  accountID,
		Username:   username,
		Protocol:   "IMAP",
		ClientAddr: clientAddr,
		Timestamp:  time.Now(),
		NodeID:     "node-2",
		InstanceID: "node-2-imap-proxy",
	}); err != nil {
		t.Fatal(err)
	}
	for _, tracker := range trackers {
		tracker.HandleClusterEvent(buf.Bytes())
	}
}

// Every gossip tracker of a protocol on a node hears the other nodes' sessions, so an
// account's entries on two IMAP proxy listeners (143 and 993) both carry its sessions on
// other nodes in total_count. "connections list" summed Remote over the entries and
// printed those sessions once per listener; "stats connection --user" counts them once.
func TestConnectionsListCountsRemoteSessionsOnce(t *testing.T) {
	imap := server.NewConnectionTracker("IMAP", "imap-proxy", "host", "node-1-imap-proxy", nil, 0, 0, 0, true)
	imaps := server.NewConnectionTracker("IMAP", "imaps-proxy", "host", "node-1-imaps-proxy", nil, 0, 0, 0, true)
	t.Cleanup(imap.Stop)
	t.Cleanup(imaps.Stop)
	ctx := context.Background()
	// anna: one session here on 993 and two on node-2. bob: one session here on each
	// listener and one on node-2.
	for _, s := range []struct {
		tracker   *server.ConnectionTracker
		accountID int64
		username  string
		addr      string
	}{
		{imaps, 1, "anna@example.com", "192.0.2.1:50000"},
		{imap, 2, "bob@example.com", "192.0.2.2:50000"},
		{imaps, 2, "bob@example.com", "192.0.2.2:50001"},
	} {
		if err := s.tracker.RegisterConnection(ctx, s.accountID, s.username, "IMAP", s.addr); err != nil {
			t.Fatal(err)
		}
	}
	gossipRegister(t, 1, "anna@example.com", "198.51.100.1:40000", imap, imaps)
	gossipRegister(t, 1, "anna@example.com", "198.51.100.2:40000", imap, imaps)
	gossipRegister(t, 2, "bob@example.com", "198.51.100.3:40000", imap, imaps)
	cfg := startTrackerAdminAPI(t, map[string]*server.ConnectionTracker{
		"IMAP-node-1-imap-proxy":  imap,
		"IMAP-node-1-imaps-proxy": imaps,
	})

	for _, tc := range []struct {
		name, user, protocol, want string
	}{
		{"connections list", "", "", "Total connections: 3 local, 3 remote\n"},
		{"connections list --user", "anna@example.com", "", "Total connections: 1 local, 2 remote\n"},
		{"connections list --user --protocol IMAP", "anna@example.com", "IMAP", "Total connections: 1 local, 2 remote\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStdout(t, func() error { return listConnections(ctx, cfg, tc.user, "", tc.protocol, "") })
			if !strings.Contains(out, tc.want) {
				t.Errorf("output does not contain %q:\n%s", tc.want, out)
			}
		})
	}

	t.Run("stats connection --user", func(t *testing.T) {
		out := captureStdout(t, func() error { return showConnectionStats(ctx, cfg, "anna@example.com", false) })
		if want := "Total connections: 3\n"; !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	})
}
