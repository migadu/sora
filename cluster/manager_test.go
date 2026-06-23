package cluster

import (
	"strings"
	"testing"

	"github.com/migadu/sora/config"
)

// TestNew_RequiresSecretKey verifies that cluster mode refuses to start without a
// secret_key. Gossip carries auth-failure state, IP blocks, and connection-kick
// commands, so running it unencrypted would let any host able to reach the gossip
// port forge those messages. Regression test for the "encryption optional" gap.
//
// The check returns before memberlist.Create, so no gossip port is bound.
func TestNew_RequiresSecretKey(t *testing.T) {
	cfg := config.ClusterConfig{
		Enabled: true,
		Addr:    "127.0.0.1:17946", // valid bind addr so we reach the secret_key check
		NodeID:  "test-node",
		// SecretKey intentionally left empty
	}

	mgr, err := New(cfg)
	if err == nil {
		t.Fatal("expected error when cluster enabled without secret_key, got nil")
	}
	if mgr != nil {
		t.Errorf("expected nil manager on error, got non-nil")
	}
	if !strings.Contains(err.Error(), "secret_key") {
		t.Errorf("expected error to mention secret_key, got: %v", err)
	}
}

// TestNew_RejectsShortSecretKey verifies that a non-empty but wrong-length key is
// also rejected (the key must be exactly 32 bytes for AES-256).
func TestNew_RejectsShortSecretKey(t *testing.T) {
	cfg := config.ClusterConfig{
		Enabled:   true,
		Addr:      "127.0.0.1:17946",
		NodeID:    "test-node",
		SecretKey: "c2hvcnQ=", // base64("short") -> 5 bytes, not 32
	}

	mgr, err := New(cfg)
	if err == nil {
		t.Fatal("expected error for short secret_key, got nil")
	}
	if mgr != nil {
		t.Errorf("expected nil manager on error, got non-nil")
	}
	if !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("expected error to mention the 32-byte requirement, got: %v", err)
	}
}
