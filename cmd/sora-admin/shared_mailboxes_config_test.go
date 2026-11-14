package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadAdminConfig_SharedNamespacePrefix (#338): `mailbox create` and `mailbox rename`
// classify names with the [shared_mailboxes] namespace_prefix, so sora-admin must read
// the same prefix the server does. Its loader started from an empty config: with
// enabled = true and no namespace_prefix the server used "Shared/" and sora-admin "",
// which put every mailbox it created in the shared namespace. A prefix the server
// refuses at start-up is refused here too.
func TestLoadAdminConfig_SharedNamespacePrefix(t *testing.T) {
	for _, tc := range []struct {
		name, toml string
		wantPrefix string
		wantErr    string // substring of the error, "" when the config loads
	}{
		{name: "enabled without namespace_prefix", toml: "[shared_mailboxes]\nenabled = true\n", wantPrefix: "Shared/"},
		{name: "explicit prefix", toml: "[shared_mailboxes]\nenabled = true\nnamespace_prefix = \"#shared/\"\n", wantPrefix: "#shared/"},
		{name: "empty prefix", toml: "[shared_mailboxes]\nenabled = true\nnamespace_prefix = \"\"\n",
			wantErr: `[shared_mailboxes]: namespace_prefix ""`},
		{name: "no trailing delimiter", toml: "[shared_mailboxes]\nenabled = true\nnamespace_prefix = \"Shared\"\n",
			wantErr: `[shared_mailboxes]: namespace_prefix "Shared"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.toml), 0o600); err != nil {
				t.Fatal(err)
			}
			var cfg AdminConfig
			err := loadAdminConfig(path, &cfg)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("loadAdminConfig error = %v, want one saying %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadAdminConfig: %v", err)
			}
			if got := cfg.SharedMailboxes.NamespacePrefix; got != tc.wantPrefix {
				t.Errorf("namespace_prefix = %q, want %q", got, tc.wantPrefix)
			}
			for _, name := range []string{"Projects", "SharedDocs"} {
				if cfg.SharedMailboxes.InNamespace(name) {
					t.Errorf("personal mailbox %q is in the shared namespace", name)
				}
			}
		})
	}
}
