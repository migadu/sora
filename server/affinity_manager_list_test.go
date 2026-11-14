package server

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/affinitycache"
)

// List reports every unexpired affinity with the user it belongs to, also a user whose
// address contains ":" (a quoted local part), and leaves expired entries out.
func TestAffinityManagerList(t *testing.T) {
	now := time.Now()
	live := now.Add(time.Hour)
	am := &AffinityManager{enabled: true, affinityMap: map[string]*AffinityInfo{
		"anna@example.com:imap":    {Backend: "192.0.2.21:143", Protocol: "imap", AssignedAt: now, ExpiresAt: live, NodeID: "node-1"},
		"anna@example.com:pop3":    {Backend: "192.0.2.21:110", Protocol: "pop3", AssignedAt: now, ExpiresAt: live, NodeID: "node-2"},
		`"a:b"@example.com:imap`:   {Backend: "192.0.2.22:143", Protocol: "imap", AssignedAt: now, ExpiresAt: live, NodeID: "node-1"},
		"expired@example.com:imap": {Backend: "192.0.2.22:143", Protocol: "imap", AssignedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour), NodeID: "node-1"},
	}}

	got := am.List()
	slices.SortFunc(got, func(a, b affinitycache.AffinityEntry) int {
		return strings.Compare(a.Username+" "+a.Protocol, b.Username+" "+b.Protocol)
	})
	want := []affinitycache.AffinityEntry{
		{Username: `"a:b"@example.com`, Protocol: "imap", Backend: "192.0.2.22:143", AssignedAt: now, ExpiresAt: live, NodeID: "node-1"},
		{Username: "anna@example.com", Protocol: "imap", Backend: "192.0.2.21:143", AssignedAt: now, ExpiresAt: live, NodeID: "node-1"},
		{Username: "anna@example.com", Protocol: "pop3", Backend: "192.0.2.21:110", AssignedAt: now, ExpiresAt: live, NodeID: "node-2"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("List() = %+v\nwant %+v", got, want)
	}

	var disabled *AffinityManager
	if l := disabled.List(); l != nil {
		t.Errorf("List() on a nil manager = %v, want nil", l)
	}
}
