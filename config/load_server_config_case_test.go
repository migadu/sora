package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLoadServerConfigPreservesCaseInsensitiveDatabaseSections(t *testing.T) {
	t.Run("mixed_case_write_and_read_headers", func(t *testing.T) {
		warns := captureWarnings(t)
		path := filepath.Join(t.TempDir(), "config.toml")
		content := `[Database.Write]
hosts = ["db-primary.internal"]
name = "mail_prod"

[database.Read]
hosts = ["db-replica1.internal", "db-replica2.internal"]
name = "mail_prod"
`
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("writing config: %v", err)
		}

		var cfg Config
		if err := LoadServerConfig(path, &cfg); err != nil {
			t.Fatalf("LoadServerConfig: %v", err)
		}
		if strings.Contains(warns.String(), "unknown key") {
			t.Errorf("unexpected unknown-key warning: %s", warns.String())
		}
		if cfg.Database.Write == nil {
			t.Fatal("cfg.Database.Write = nil, want non-nil for [Database.Write]")
		}
		if !slices.Equal(cfg.Database.Write.Hosts, []string{"db-primary.internal"}) || cfg.Database.Write.Name != "mail_prod" || cfg.Database.Write.User != "postgres" {
			t.Errorf("cfg.Database.Write = %+v, want hosts=[db-primary.internal] name=mail_prod user=postgres", *cfg.Database.Write)
		}
		if cfg.Database.Read == nil {
			t.Fatal("cfg.Database.Read = nil, want non-nil for [database.Read]")
		}
		if !slices.Equal(cfg.Database.Read.Hosts, []string{"db-replica1.internal", "db-replica2.internal"}) || cfg.Database.Read.Name != "mail_prod" {
			t.Errorf("cfg.Database.Read = %+v, want hosts=[db-replica1.internal db-replica2.internal] name=mail_prod", *cfg.Database.Read)
		}
	})

	t.Run("uppercase_write_only_leaves_read_nil", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		content := `[DATABASE.WRITE]
hosts = ["10.0.0.10"]
`
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("writing config: %v", err)
		}

		var cfg Config
		if err := LoadServerConfig(path, &cfg); err != nil {
			t.Fatalf("LoadServerConfig: %v", err)
		}
		if cfg.Database.Write == nil {
			t.Fatal("cfg.Database.Write = nil, want non-nil for [DATABASE.WRITE]")
		}
		if !slices.Equal(cfg.Database.Write.Hosts, []string{"10.0.0.10"}) {
			t.Errorf("cfg.Database.Write.Hosts = %q, want [10.0.0.10]", cfg.Database.Write.Hosts)
		}
		if cfg.Database.Read != nil {
			t.Errorf("cfg.Database.Read = %+v, want nil when read section is absent", cfg.Database.Read)
		}
	})

	t.Run("empty_mixed_case_table_keeps_seeded_defaults", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(path, []byte("[Database.Write]\n"), 0o600); err != nil {
			t.Fatalf("writing config: %v", err)
		}

		var cfg Config
		if err := LoadServerConfig(path, &cfg); err != nil {
			t.Fatalf("LoadServerConfig: %v", err)
		}
		if cfg.Database.Write == nil {
			t.Fatal("cfg.Database.Write = nil, want default endpoint for empty [Database.Write]")
		}
		if !slices.Equal(cfg.Database.Write.Hosts, []string{"localhost"}) || cfg.Database.Write.Name != "sora_mail_db" {
			t.Errorf("cfg.Database.Write = %+v, want seeded localhost/sora_mail_db defaults", *cfg.Database.Write)
		}
		if cfg.Database.Read != nil {
			t.Errorf("cfg.Database.Read = %+v, want nil", cfg.Database.Read)
		}
	})

	t.Run("inline_subtable_mixed_case", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		content := `[database]
Write = { hosts = ["db-inline.internal"] }
`
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("writing config: %v", err)
		}

		var cfg Config
		if err := LoadServerConfig(path, &cfg); err != nil {
			t.Fatalf("LoadServerConfig: %v", err)
		}
		if cfg.Database.Write == nil {
			t.Fatal("cfg.Database.Write = nil, want non-nil for inline Write table")
		}
		if !slices.Equal(cfg.Database.Write.Hosts, []string{"db-inline.internal"}) {
			t.Errorf("cfg.Database.Write.Hosts = %q, want [db-inline.internal]", cfg.Database.Write.Hosts)
		}
		if cfg.Database.Read != nil {
			t.Errorf("cfg.Database.Read = %+v, want nil", cfg.Database.Read)
		}
	})

	t.Run("neither_write_nor_read_leaves_both_nil", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		content := `[Database]
debug = true
`
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("writing config: %v", err)
		}

		var cfg Config
		if err := LoadServerConfig(path, &cfg); err != nil {
			t.Fatalf("LoadServerConfig: %v", err)
		}
		if !cfg.Database.Debug {
			t.Error("cfg.Database.Debug = false, want true")
		}
		if cfg.Database.Write != nil || cfg.Database.Read != nil {
			t.Errorf("Database.Write = %+v, Database.Read = %+v; want both nil", cfg.Database.Write, cfg.Database.Read)
		}
	})
}
