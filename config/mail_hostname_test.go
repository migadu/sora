package config

import (
	"errors"
	"testing"
)

// TestMailHostnameIgnoresNodeID pins the boundary between this node's two names.
//
// cluster.node_id is a lease key: it must be unique per node and stable across restarts,
// and operators legitimately set it to an internal label like "node-1" or "mail-eu-3".
// The mail hostname is the opposite kind of string - it is published to the world in the
// "by" clause of the Received header of every delivery and as the domain of the Message-ID
// on vacation auto-replies, so it has to be a name that resolves (RFC 5321 4.4). Feeding
// the lease key into those headers stamps an internal label onto outbound mail and mints
// Message-IDs in a domain that does not exist, which is a spam signal on a message the
// user did not choose to send.
//
// The two derivations therefore may not share a source: node_id must never reach the mail
// hostname, no matter how it is configured.
func TestMailHostnameIgnoresNodeID(t *testing.T) {
	hostnameOK := func() (string, error) { return "mail1.example.com", nil }
	hostnameErr := func() (string, error) { return "", errors.New("no hostname") }
	hostnameEmpty := func() (string, error) { return "", nil }

	tests := []struct {
		name       string
		nodeID     string
		hostnameFn func() (string, error)
		want       string
	}{
		{
			name:       "node_id does not override the host's own name",
			nodeID:     "node-1",
			hostnameFn: hostnameOK,
			want:       "mail1.example.com",
		},
		{
			name:       "no node_id, same answer",
			nodeID:     "",
			hostnameFn: hostnameOK,
			want:       "mail1.example.com",
		},
		{
			name:       "node_id is not a substitute when the host has no name",
			nodeID:     "node-1",
			hostnameFn: hostnameErr,
			want:       FallbackMailHostname,
		},
		{
			name:       "empty hostname falls back rather than borrowing node_id",
			nodeID:     "node-1",
			hostnameFn: hostnameEmpty,
			want:       FallbackMailHostname,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mailHostnameFrom(tt.hostnameFn)
			if got != tt.want {
				t.Errorf("mailHostnameFrom() = %q, want %q", got, tt.want)
			}
			if got == tt.nodeID {
				t.Errorf("mail hostname resolved to the cluster node id %q - node_id is an internal "+
					"lease key and must never appear in Received or a vacation Message-ID", tt.nodeID)
			}
		})
	}
}

// TestNodeIdentitySeparatesLeaseKeyFromMailHostname is the wiring guard. The two names are
// resolved together by one function so the split cannot be quietly re-collapsed: a caller
// that reaches for "the hostname" gets a struct with both fields and has to choose.
// The lease key comes from uploader.instance_id; cluster.node_id names the gossip node
// and must leak into neither field.
func TestNodeIdentitySeparatesLeaseKeyFromMailHostname(t *testing.T) {
	cfg := Config{}
	cfg.Cluster.NodeID = "gossip-node-1"
	cfg.Uploader.InstanceID = "spool-1"

	identity := cfg.NodeIdentity()

	if identity.InstanceID != "spool-1" {
		t.Errorf("InstanceID = %q, want the configured uploader.instance_id %q - the upload lease is keyed on it",
			identity.InstanceID, "spool-1")
	}
	if identity.InstanceID == "gossip-node-1" || identity.MailHostname == "gossip-node-1" {
		t.Error("cluster.node_id leaked into node identity; it names the gossip node and nothing else")
	}
	if identity.MailHostname == "spool-1" {
		t.Error("MailHostname is the upload lease key; it is published in Received and vacation Message-IDs")
	}
	if identity.MailHostname == "" {
		t.Error("MailHostname is empty, which would produce a malformed Received header")
	}
}
