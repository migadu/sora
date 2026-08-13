package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/migadu/sora/config"
)

// sora and sora-admin decode the same config.toml into different structs, and both write
// pending_uploads rows on the same host. instance_id is a lease key: db.CleanupFailedUploads
// deletes an unuploaded message once no live instance answers to the id on its row, so if
// the two binaries resolved identity differently, an import would leave rows owned by a
// name that never heartbeats - and the cleaner would eventually delete the mail.

const instanceIDFixture = `
[uploader]
instance_id = "mail-node-7"

[cluster]
enabled = true
node_id = "gossip-name-distinct"

[database]
[s3]
`

// loadAdminConfigFromString exercises the REAL production loader. Decoding straight into
// AdminConfig would not: loadAdminConfig copies named fields across from config.Config
// rather than decoding into AdminConfig itself, so a field it forgets to copy is
// populated by a direct toml.Decode and empty in production.
func loadAdminConfigFromString(t *testing.T, body string) AdminConfig {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var cfg AdminConfig
	if err := loadAdminConfig(path, &cfg); err != nil {
		t.Fatalf("loadAdminConfig: %v", err)
	}
	return cfg
}

func TestAdminAndServerResolveTheSameInstanceID(t *testing.T) {
	admin := loadAdminConfigFromString(t, instanceIDFixture)

	var server config.Config
	if _, err := toml.Decode(instanceIDFixture, &server); err != nil {
		t.Fatalf("decode into config.Config: %v", err)
	}

	if admin.InstanceID() != server.InstanceID() {
		t.Errorf("sora-admin resolves instance id %q but sora resolves %q: an import would write "+
			"pending_uploads rows owned by an instance that never heartbeats",
			admin.InstanceID(), server.InstanceID())
	}
	if admin.InstanceID() != "mail-node-7" {
		t.Errorf("instance id = %q, want the configured uploader.instance_id %q", admin.InstanceID(), "mail-node-7")
	}
}

// TestAdminInstanceIDIgnoresClusterNodeID pins the decoupling of storage identity from
// gossip identity: cluster.node_id names this node on the memberlist bus and nothing
// else. The upload lease key comes from uploader.instance_id (default: hostname), so
// renaming the gossip node cannot strand queued uploads — and a config that sets only
// cluster.node_id keeps stamping exactly what pre-split binaries stamped.
func TestAdminInstanceIDIgnoresClusterNodeID(t *testing.T) {
	admin := loadAdminConfigFromString(t, "[cluster]\nenabled = true\nnode_id = \"gossip-node-7\"\n")

	if got := admin.InstanceID(); got == "gossip-node-7" {
		t.Errorf("instance id = %q: cluster.node_id leaked into the upload lease key; "+
			"renaming the gossip node would strand every queued upload", got)
	}
	if got, want := admin.InstanceID(), config.ResolveInstanceID(""); got != want {
		t.Errorf("instance id = %q, want the hostname-chain default %q", got, want)
	}
}

// TestAdminInstanceIDIsNeverEmpty guards the collision case: an empty instance_id is
// shared by every node, so one node could lease uploads whose bodies are on another's disk.
func TestAdminInstanceIDIsNeverEmpty(t *testing.T) {
	admin := loadAdminConfigFromString(t, "[database]\n")

	if admin.InstanceID() == "" {
		t.Error("instance id is empty with no cluster section configured; it would collide across nodes")
	}
}
