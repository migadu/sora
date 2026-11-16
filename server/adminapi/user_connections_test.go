package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/migadu/sora/server"
)

// GET /admin/connections/user/{email} lists a session as GET /admin/connections does:
// protocol is the protocol and instance the tracker key. It sent the whole tracker key as
// protocol and no instance, so sora-admin's --protocol and --instance filters, which
// match instance, never matched a per-user entry, and its Protocol column showed the key.
func TestUserConnectionsEntryMatchesConnectionList(t *testing.T) {
	// A proxy tracker in cluster mode is keyed <PROTOCOL>-<node_id>-<server name>.
	const key = "IMAP-node-1-imap-proxy"
	tracker := server.NewConnectionTracker("IMAP", "imap-proxy", "host", "node-1-imap-proxy", nil, 0, 0, 0, true)
	t.Cleanup(tracker.Stop)
	if err := tracker.RegisterConnection(context.Background(), 123, "anna@example.com", "IMAP", "192.0.2.1:50000"); err != nil {
		t.Fatal(err)
	}
	s := &Server{connectionTrackers: func() map[string]*server.ConnectionTracker {
		return map[string]*server.ConnectionTracker{key: tracker}
	}}

	entries := func(h http.HandlerFunc, target string) []map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.SetPathValue("email", "anna@example.com")
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s answered %d: %s", target, rec.Code, rec.Body)
		}
		var body struct {
			Connections []map[string]any `json:"connections"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Connections
	}
	list := entries(s.handleListConnections, "/admin/connections")
	user := entries(s.handleGetUserConnections, "/admin/connections/user/anna@example.com")

	if len(user) != 1 {
		t.Fatalf("per-user endpoint listed %d entries, want 1: %v", len(user), user)
	}
	if got := user[0]["protocol"]; got != "IMAP" {
		t.Errorf("per-user entry protocol = %v, want IMAP", got)
	}
	if got := user[0]["instance"]; got != key {
		t.Errorf("per-user entry instance = %v, want %s", got, key)
	}
	if !reflect.DeepEqual(user, list) {
		t.Errorf("per-user entries differ from the connection list\n  user: %v\n  list: %v", user, list)
	}
}
