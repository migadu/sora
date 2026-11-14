package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/errors"
)

// loadStartupDatabaseConfig loads content the way main does at start-up.
func loadStartupDatabaseConfig(t *testing.T, content string) config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.NewDefaultConfig()
	loadAndValidateConfig(path, &cfg, errors.NewErrorHandler())
	return cfg
}

const imapServerTOML = `
[[server]]
type = "imap"
name = "imap"
addr = ":143"
`

// TestStartupKeepsDatabaseTablesTheFileDefines pins that a [database.write] or
// [database.read] table the file defines is used even when its values are the built-in
// defaults (localhost, postgres, sora_mail_db): only a table the file leaves out is
// dropped, so a node without one runs without that endpoint (proxy-only).
func TestStartupKeepsDatabaseTablesTheFileDefines(t *testing.T) {
	tests := []struct {
		name      string
		toml      string
		wantWrite []string // nil: no write endpoint
		wantRead  []string // nil: no read endpoint
	}{
		{
			name: "write table with the default values",
			toml: `
[database.write]
hosts = ["localhost"]
port = 5432
user = "postgres"
name = "sora_mail_db"
` + imapServerTOML,
			wantWrite: []string{"localhost"},
		},
		{
			name: "write and read tables with the default values",
			toml: `
[database.write]
hosts = ["localhost"]
user = "postgres"
name = "sora_mail_db"

[database.read]
hosts = ["localhost"]
user = "postgres"
name = "sora_mail_db"
` + imapServerTOML,
			wantWrite: []string{"localhost"},
			wantRead:  []string{"localhost"},
		},
		{
			name: "write as an inline table with the default values",
			toml: `
[database]
write = { hosts = ["localhost"], user = "postgres", name = "sora_mail_db" }
` + imapServerTOML,
			wantWrite: []string{"localhost"},
		},
		{
			// A table without keys is in the file too: it takes every default.
			name: "empty write table",
			toml: `
[database.write]
` + imapServerTOML,
			wantWrite: []string{"localhost"},
		},
		{
			// toml.Decode matches keys to struct fields case-insensitively, so this
			// table fills cfg.Database.Write without an unknown-key warning.
			name: "write table spelled [Database.Write]",
			toml: `
[Database.Write]
hosts = ["db1.example.com"]
` + imapServerTOML,
			wantWrite: []string{"db1.example.com"},
		},
		{
			name: "read as an inline table spelled Read",
			toml: `
[database.write]
hosts = ["db1.example.com"]

[database]
Read = { hosts = ["db2.example.com"] }
` + imapServerTOML,
			wantWrite: []string{"db1.example.com"},
			wantRead:  []string{"db2.example.com"},
		},
		{
			name: "write elsewhere, no read table",
			toml: `
[database.write]
hosts = ["db1.example.com"]
` + imapServerTOML,
			wantWrite: []string{"db1.example.com"},
		},
		{
			name: "database table without endpoints",
			toml: `
[database]
query_timeout = "30s"

[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = ":1143"
remote_addrs = ["backend1.example.com:143"]
`,
		},
		{
			name: "no database table",
			toml: `
[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = ":1143"
remote_addrs = ["backend1.example.com:143"]
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := loadStartupDatabaseConfig(t, tt.toml)
			checkEndpoint(t, "write", cfg.Database.Write, tt.wantWrite)
			checkEndpoint(t, "read", cfg.Database.Read, tt.wantRead)
		})
	}
}

func checkEndpoint(t *testing.T, which string, got *config.DatabaseEndpointConfig, wantHosts []string) {
	t.Helper()
	if wantHosts == nil {
		if got != nil {
			t.Errorf("[database.%s] = %+v, want none (the file defines no such table)", which, *got)
		}
		return
	}
	if got == nil {
		t.Errorf("[database.%s] dropped, want hosts %v (the file defines the table)", which, wantHosts)
		return
	}
	if !slices.Equal(got.Hosts, wantHosts) {
		t.Errorf("[database.%s] hosts = %v, want %v", which, got.Hosts, wantHosts)
	}
}
