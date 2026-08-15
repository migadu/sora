package config

import (
	"errors"
	"testing"
)

// TestInstanceID pins how this node names itself in pending_uploads.instance_id and
// instance_heartbeats.instance_id. Those two must always be the same string: a pending
// upload can only be performed by the instance that created it (the body is a file on
// that node's local disk), and db.CleanupFailedUploads reaps an upload whose owner has
// stopped heartbeating. A disagreement between the two writers is silent mail loss, so
// the derivation lives in one pure function instead of an inline os.Hostname() call.
func TestInstanceID(t *testing.T) {
	hostnameOK := func() (string, error) { return "mail1.example.com", nil }
	hostnameErr := func() (string, error) { return "", errors.New("no hostname") }
	hostnameEmpty := func() (string, error) { return "", nil }

	tests := []struct {
		name       string
		configured string
		hostnameFn func() (string, error)
		want       string
	}{
		{
			name:       "configured uploader.instance_id wins over hostname",
			configured: "spool-1",
			hostnameFn: hostnameOK,
			want:       "spool-1",
		},
		{
			name:       "instance_id unset falls back to hostname",
			configured: "",
			hostnameFn: hostnameOK,
			want:       "mail1.example.com",
		},
		{
			name:       "whitespace-only instance_id is not an identity",
			configured: "   ",
			hostnameFn: hostnameOK,
			want:       "mail1.example.com",
		},
		{
			name:       "hostname error falls back to a deterministic id, never empty",
			configured: "",
			hostnameFn: hostnameErr,
			want:       FallbackInstanceID,
		},
		{
			name:       "empty hostname falls back to a deterministic id, never empty",
			configured: "",
			hostnameFn: hostnameEmpty,
			want:       FallbackInstanceID,
		},
		{
			name:       "configured id still wins when hostname is unavailable",
			configured: "spool-1",
			hostnameFn: hostnameErr,
			want:       "spool-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := instanceIDFrom(tt.configured, tt.hostnameFn)
			if got != tt.want {
				t.Errorf("instanceIDFrom() = %q, want %q", got, tt.want)
			}
			if got == "" {
				t.Error("instanceIDFrom() returned an empty instance id, which collides across nodes")
			}
		})
	}
}

// TestInstanceIDIsStable guards the property the lease depends on: the same config must
// resolve to the same id on every call, so a restart re-claims its own queued uploads
// instead of stranding them under the previous run's id.
func TestInstanceIDIsStable(t *testing.T) {
	cfg := Config{}
	first := cfg.InstanceID()
	second := cfg.InstanceID()
	if first != second {
		t.Fatalf("InstanceID() is not stable: %q then %q", first, second)
	}
	if first == "" {
		t.Fatal("InstanceID() returned an empty instance id")
	}
}

// TestInstanceIDDecoupledFromClusterNodeID pins the decoupling of storage identity from
// gossip identity. cluster.node_id names this node on the memberlist bus; the upload
// lease key names whoever owns the staged bodies on this node's disk. Coupling them
// means renaming the gossip node silently strands every queued upload (the rows keep
// the old id, no instance claims them, and the cleaner eventually reaps them as
// owner-gone). The lease key must therefore come from its own setting,
// uploader.instance_id, and default to the hostname — the exact value pre-split
// binaries stamped, so an upgrade is lease-continuous with no re-stamping.
func TestInstanceIDDecoupledFromClusterNodeID(t *testing.T) {
	cfg := Config{}
	cfg.Cluster.NodeID = "gossip-node-1"

	got := cfg.InstanceID()
	if got == "gossip-node-1" {
		t.Fatalf("InstanceID() = %q: cluster.node_id leaked into the upload lease key; "+
			"renaming the gossip node would strand every queued upload", got)
	}
	// With no explicit uploader.instance_id the lease key must be what a pre-split
	// binary stamped: the hostname chain.
	if want := ResolveInstanceID(""); got != want {
		t.Fatalf("InstanceID() = %q, want the hostname-chain default %q", got, want)
	}

	// And an explicit uploader.instance_id wins — including over a node_id that is
	// also set, because the two identities are independent.
	cfg.Uploader.InstanceID = "spool-1"
	if got := cfg.InstanceID(); got != "spool-1" {
		t.Fatalf("InstanceID() = %q, want the configured uploader.instance_id %q", got, "spool-1")
	}
}
