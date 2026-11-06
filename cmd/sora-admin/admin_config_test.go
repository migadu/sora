package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/migadu/sora/config"
)

// A config without [uploader] max_attempts gets the server's default, as cmd/sora does.
// With zero, every pending upload would count as parked (attempts >= 0): `backends status`
// and `uploader status` report them all as given up, and `uploader resolve` treats live
// uploads as written off.
func TestLoadAdminConfig_DefaultsUploaderMaxAttempts(t *testing.T) {
	want := config.NewDefaultConfig().Uploader.MaxAttempts
	if want <= 0 {
		t.Fatalf("test setup: server default max_attempts is %d", want)
	}

	for _, tc := range []struct {
		name, toml string
		want       int
	}{
		{"no uploader section", "[database]\n", want},
		{"uploader without max_attempts", "[uploader]\npath = \"/var/spool/sora\"\n", want},
		{"explicit max_attempts", "[uploader]\nmax_attempts = 7\n", 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.toml), 0o600); err != nil {
				t.Fatal(err)
			}
			var cfg AdminConfig
			if err := loadAdminConfig(path, &cfg); err != nil {
				t.Fatalf("loadAdminConfig: %v", err)
			}
			if cfg.Uploader.MaxAttempts != tc.want {
				t.Fatalf("Uploader.MaxAttempts = %d, want %d", cfg.Uploader.MaxAttempts, tc.want)
			}
		})
	}
}
