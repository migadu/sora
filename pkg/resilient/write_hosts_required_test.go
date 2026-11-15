package resilient

import (
	"context"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
)

// A database without [database.write] hosts cannot be opened: the migrations and every
// write go there. sora refuses such a file in Config.Validate, but sora-admin opens its
// database without that check, and it stopped with "no healthy database pools
// available", which does not name the missing section, after trying the replicas (#1266).
func TestNewResilientDatabaseNamesMissingWriteHosts(t *testing.T) {
	// Port 1 on loopback refuses at once: a replica the manager tries fails fast.
	replica := &config.DatabaseEndpointConfig{Hosts: []string{"127.0.0.1"}, Port: 1, User: "postgres", Name: "sora_unreachable"}

	tests := []struct {
		name string
		cfg  *config.DatabaseConfig
	}{
		{name: "read hosts only", cfg: &config.DatabaseConfig{Read: replica}},
		{name: "write endpoint without hosts", cfg: &config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{}, Read: replica}},
		{name: "no endpoints", cfg: &config.DatabaseConfig{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, skipReadReplicas := range []bool{false, true} { // sora, sora-admin
				rdb, err := NewResilientDatabaseWithOptions(context.Background(), tt.cfg, false, false, skipReadReplicas)
				if err == nil {
					rdb.Close()
					t.Fatalf("skipReadReplicas=%v: opened a database without [database.write] hosts", skipReadReplicas)
				}
				if !strings.Contains(err.Error(), "[database.write] has no hosts") {
					t.Errorf("skipReadReplicas=%v: error %q does not name [database.write]", skipReadReplicas, err)
				}
			}
		})
	}
}
