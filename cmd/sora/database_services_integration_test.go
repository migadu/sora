//go:build integration

package main

import (
	"context"
	"os"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/errors"
)

// A node connects to its configured database whenever one of its servers queries it. The
// ManageSieve backend authenticates and keeps its scripts there, and a mail proxy
// authenticates there unless a remote lookup answers for every user: without
// remote_lookup, with it disabled, or with lookup_local_users = true. Left unconnected,
// each login dereferenced a nil database and the session dropped the client.
func TestInitializeServices_ConnectsDatabaseForServersThatQueryIt(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	dbName := os.Getenv("SORA_TEST_DB_NAME")
	if dbName == "" {
		dbName = "sora_test_db"
	}
	remoteLookup := func(enabled, localUsers bool) *config.RemoteLookupConfig {
		return &config.RemoteLookupConfig{Enabled: enabled, URL: "http://127.0.0.1:9/lookup", LookupLocalUsers: localUsers}
	}
	proxy := func(typ string, rl *config.RemoteLookupConfig) config.ServerConfig {
		return config.ServerConfig{
			Type: typ, Name: typ, Addr: "127.0.0.1:0",
			RemoteAddrs: []string{"192.0.2.10:143"}, RemoteLookup: rl,
		}
	}

	tests := []struct {
		name   string
		server config.ServerConfig
		wantDB bool
	}{
		{"managesieve backend", config.ServerConfig{Type: "managesieve", Name: "sieve", Addr: "127.0.0.1:0"}, true},
		{"imap_proxy without remote_lookup", proxy("imap_proxy", nil), true},
		{"pop3_proxy without remote_lookup", proxy("pop3_proxy", nil), true},
		{"managesieve_proxy without remote_lookup", proxy("managesieve_proxy", nil), true},
		{"lmtp_proxy without remote_lookup", proxy("lmtp_proxy", nil), true},
		{"imap_proxy with remote_lookup disabled", proxy("imap_proxy", remoteLookup(false, false)), true},
		{"imap_proxy with lookup_local_users", proxy("imap_proxy", remoteLookup(true, true)), true},
		// The remote lookup authenticates every user; the database stays unused.
		{"imap_proxy with remote_lookup only", proxy("imap_proxy", remoteLookup(true, false)), false},
		// The backend authenticates User API logins and checks the JWT.
		{"user_api_proxy without remote_lookup", proxy("user_api_proxy", nil), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.NewDefaultConfig()
			cfg.Database = config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
				Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: dbName,
			}}
			cfg.DynamicServers = []config.ServerConfig{tt.server}

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			deps, err := initializeServices(ctx, cfg, errors.NewErrorHandler())
			if err != nil {
				t.Fatalf("initializeServices: %v", err)
			}
			t.Cleanup(func() {
				if deps.resilientDB != nil {
					deps.resilientDB.Close()
				}
			})

			if got := deps.resilientDB != nil; got != tt.wantDB {
				t.Errorf("database connected = %v, want %v", got, tt.wantDB)
			}
		})
	}
}
