package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A negative [cleanup] fts_retention stops every import from creating search rows, the
// way it stops delivery on the server (#284). sora-admin refuses it like the server does,
// both when loading its configuration and in `config validate`.
func TestNegativeFTSRetentionRejected(t *testing.T) {
	keepBcryptCost(t)
	for _, tc := range []struct {
		name, value string
		wantErr     string // substring of the failure, "" when the config is accepted
	}{
		{name: "unset"},
		{name: "positive", value: "180d"},
		{name: "negative", value: "-30d", wantErr: `fts_retention must not be negative, got "-30d"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := "[[server]]\ntype = \"lmtp\"\nname = \"lmtp\"\naddr = \"127.0.0.1:0\"\n"
			if tc.value != "" {
				content += "\n[cleanup]\nfts_retention = \"" + tc.value + "\"\n"
			}
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}

			var cfg AdminConfig
			err := loadAdminConfig(path, &cfg)
			if tc.wantErr == "" && err != nil {
				t.Errorf("loadAdminConfig: %v", err)
			} else if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("loadAdminConfig error = %v, want one saying %q", err, tc.wantErr)
			}

			cmd := exec.Command(os.Args[0], "-test.run=^TestConfigValidateCommandHelper$")
			cmd.Env = append(os.Environ(), configValidateHelperEnv+"="+path)
			out, err := cmd.CombinedOutput()
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("config validate failed a valid file: %v\n%s", err, out)
				}
				return
			}
			if err == nil {
				t.Errorf("config validate passed the file; want it failed with %q", tc.wantErr)
			} else if !strings.Contains(string(out), tc.wantErr) {
				t.Errorf("config validate failed, but the output does not say %q:\n%s", tc.wantErr, out)
			}
		})
	}
}
