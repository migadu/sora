package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `accounts create` stamps [quota] default_storage_quota on new accounts, so the
// loader must carry it into AdminConfig (it copies sections one by one) and refuse a
// value the server refuses.
func TestQuotaConfigLoaded(t *testing.T) {
	keepBcryptCost(t)
	for _, tc := range []struct {
		name, value string
		want        int64 // 0: unlimited
		wantErr     string
	}{
		{name: "unset"},
		{name: "set", value: "2gb", want: 2 << 30},
		{name: "zero", value: "0", wantErr: "must be more than 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := storageTOML
			if tc.value != "" {
				content += "\n[quota]\ndefault_storage_quota = \"" + tc.value + "\"\n"
			}
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
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
			got, err := cfg.Quota.DefaultStorage()
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case tc.want == 0 && got != nil:
				t.Errorf("default = %d, want unlimited", *got)
			case tc.want != 0 && (got == nil || *got != tc.want):
				t.Errorf("default = %v, want %d", got, tc.want)
			}
		})
	}
}
