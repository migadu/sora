package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// serveAdminAPIJSON answers every request with body, as the Admin API would.
func serveAdminAPIJSON(t *testing.T, body string) AdminConfig {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return AdminConfig{HTTPAPIAddr: srv.URL, HTTPAPIKey: "test-key"}
}

// captureStdout returns what f prints to stdout.
func captureStdout(t *testing.T, f func() error) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	out := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		out <- string(b)
	}()
	ferr := f()
	w.Close()
	os.Stdout = stdout
	printed := <-out
	if ferr != nil {
		t.Fatalf("%v; printed:\n%s", ferr, printed)
	}
	return printed
}

// The Admin API lists one entry per account and connection tracker, with the account's
// connection counts inside. The totals sora-admin prints are connections, not entries.
func TestConnectionTotalsCountConnectionsNotEntries(t *testing.T) {
	ctx := context.Background()

	t.Run("connections list", func(t *testing.T) {
		// Two accounts with sessions on this node: five (and two more on another
		// node) and one.
		cfg := serveAdminAPIJSON(t, `{"connections":[
			{"protocol":"IMAP","instance":"IMAP-host-imap-proxy","account_id":1,"email":"a@example.com","local_count":5,"total_count":7,"last_update":"2026-11-14T10:00:00Z"},
			{"protocol":"IMAP","instance":"IMAP-host-imap-proxy","account_id":2,"email":"b@example.com","local_count":1,"total_count":1,"last_update":"2026-11-14T10:00:00Z"}
		],"count":2,"source":"in-memory connection tracker"}`)
		out := captureStdout(t, func() error { return listConnections(ctx, cfg, "", "", "", "") })
		if want := "Total connections: 6 local, 2 remote"; !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	})

	t.Run("stats connection --user", func(t *testing.T) {
		// One account: five IMAP sessions here and two on another node, one POP3
		// session known only through another node's gossip.
		cfg := serveAdminAPIJSON(t, `{"email":"a@example.com","connections":[
			{"protocol":"IMAP","instance":"IMAP-host-imap-proxy","account_id":1,"email":"a@example.com","local_count":5,"total_count":7,"last_update":"2026-11-14T10:00:00Z"},
			{"protocol":"POP3","instance":"POP3-host-pop3-proxy","account_id":1,"email":"a@example.com","local_count":0,"total_count":1,"last_update":"2026-11-14T10:00:00Z"}
		],"count":2,"source":"in-memory connection tracker"}`)
		out := captureStdout(t, func() error { return showConnectionStats(ctx, cfg, "a@example.com", false) })
		if want := "Total connections: 8\n"; !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	})

	t.Run("stats connection --user, two trackers of one protocol", func(t *testing.T) {
		// Two IMAP proxy listeners on this node with three and one of the account's
		// sessions, and two sessions on another node. Each tracker's total_count is its
		// own sessions plus what other nodes report, so both include those two.
		cfg := serveAdminAPIJSON(t, `{"email":"a@example.com","connections":[
			{"protocol":"IMAP","instance":"IMAP-node-1-imap-proxy","account_id":1,"email":"a@example.com","local_count":3,"total_count":5,"last_update":"2026-11-14T10:00:00Z"},
			{"protocol":"IMAP","instance":"IMAP-node-1-imaps-proxy","account_id":1,"email":"a@example.com","local_count":1,"total_count":3,"last_update":"2026-11-14T10:00:00Z"}
		],"count":2,"source":"in-memory connection tracker"}`)
		out := captureStdout(t, func() error { return showConnectionStats(ctx, cfg, "a@example.com", false) })
		if want := "Total connections: 6\n"; !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
		if row := rowFields(out, "IMAP:"); len(row) != 2 || row[1] != "6" {
			t.Errorf("By Protocol has no line \"IMAP: 6\":\n%s", out)
		}
	})

	t.Run("stats connection --user, reused address on different accounts", func(t *testing.T) {
		// The endpoint matches the session's login address. Reassigning that address
		// leaves existing sessions alone, so both account IDs can still be listed.
		cfg := serveAdminAPIJSON(t, `{"email":"a@example.com","connections":[
			{"protocol":"IMAP","instance":"IMAP-node-1-imap-proxy","account_id":1,"email":"a@example.com","local_count":1,"total_count":4},
			{"protocol":"IMAP","instance":"IMAP-node-1-imap-proxy","account_id":2,"email":"a@example.com","local_count":2,"total_count":6}
		],"count":2}`)
		out := captureStdout(t, func() error { return showConnectionStats(ctx, cfg, "a@example.com", false) })
		if want := "Total connections: 10\n"; !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
		if row := rowFields(out, "IMAP:"); len(row) != 2 || row[1] != "10" {
			t.Errorf("By Protocol has no line \"IMAP: 10\":\n%s", out)
		}
	})
}
