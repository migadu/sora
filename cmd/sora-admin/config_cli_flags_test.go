package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigDumpConfigFlagPositions verifies that `sora-admin config dump`
// accepts `--config PATH` and `--config=PATH` anywhere on the command line
// (matching `sora-admin config validate` and all other `sora-admin` commands),
// and that `--help` / `-h` prints usage and exits 0 regardless of `--config`
// position.
func TestConfigDumpConfigFlagPositions(t *testing.T) {
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "first.toml")
	secondPath := filepath.Join(dir, "second.toml")
	const firstBody = "[admin_cli]\naddr = \"https://first.example.invalid:8443\"\napi_key = \"first-secret-key\"\n"
	const secondBody = "[admin_cli]\naddr = \"https://second.example.invalid:8443\"\napi_key = \"second-secret-key\"\n"
	if err := os.WriteFile(firstPath, []byte(firstBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, []byte(secondBody), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		args       []string
		wantSubstr string
		forbid     string
	}{
		{
			name:       "global --config before config dump",
			args:       []string{"--config", firstPath, "config", "dump", "--format", "json"},
			wantSubstr: "https://first.example.invalid:8443",
			forbid:     "first-secret-key",
		},
		{
			name:       "global --config= before config dump",
			args:       []string{"--config=" + firstPath, "config", "dump", "--format", "json"},
			wantSubstr: "https://first.example.invalid:8443",
			forbid:     "first-secret-key",
		},
		{
			name:       "--config between config and dump",
			args:       []string{"config", "--config", firstPath, "dump", "--format", "json"},
			wantSubstr: "https://first.example.invalid:8443",
			forbid:     "first-secret-key",
		},
		{
			name:       "--config= between config and dump",
			args:       []string{"config", "--config=" + firstPath, "dump", "--format", "json"},
			wantSubstr: "https://first.example.invalid:8443",
			forbid:     "first-secret-key",
		},
		{
			name:       "trailing --config after config dump",
			args:       []string{"config", "dump", "--config", firstPath},
			wantSubstr: "https://first.example.invalid:8443",
			forbid:     "first-secret-key",
		},
		{
			name:       "trailing --config= after config dump",
			args:       []string{"config", "dump", "--config=" + firstPath},
			wantSubstr: "https://first.example.invalid:8443",
			forbid:     "first-secret-key",
		},
		{
			name:       "--config interleaved with dump flags",
			args:       []string{"config", "dump", "--format", "json", "--config", firstPath, "--mask-secrets=false"},
			wantSubstr: "first-secret-key",
		},
		{
			name:       "first --config wins when repeated",
			args:       []string{"--config", firstPath, "config", "dump", "--config", secondPath, "--format", "json"},
			wantSubstr: "https://first.example.invalid:8443",
			forbid:     "https://second.example.invalid:8443",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, code := runAdminMain(t, tc.args...)
			if code != 0 {
				t.Fatalf("exit code %d, want 0:\n%s", code, out)
			}
			if !strings.Contains(out, tc.wantSubstr) {
				t.Errorf("output lacks %q:\n%s", tc.wantSubstr, out)
			}
			if tc.forbid != "" && strings.Contains(out, tc.forbid) {
				t.Errorf("output unexpectedly contains %q:\n%s", tc.forbid, out)
			}
		})
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no config --help", []string{"config", "dump", "--help"}},
		{"no config -h", []string{"config", "dump", "-h"}},
		{"trailing --config then --help", []string{"config", "dump", "--config", firstPath, "--help"}},
		{"trailing --config= then -h", []string{"config", "dump", "--config=" + firstPath, "-h"}},
		{"--help before trailing --config", []string{"config", "dump", "--help", "--config", firstPath}},
	} {
		t.Run("help/"+tc.name, func(t *testing.T) {
			out, code := runAdminMain(t, tc.args...)
			if code != 0 {
				t.Fatalf("exit code %d, want 0:\n%s", code, out)
			}
			if !strings.Contains(out, "Usage:") {
				t.Errorf("no usage printed:\n%s", out)
			}
			if strings.Contains(out, "first.example.invalid") || strings.Contains(out, "Error:") || strings.Contains(out, "flag provided but not defined") {
				t.Errorf("--help did not cleanly print usage:\n%s", out)
			}
		})
	}
}

// TestRootHelpWithConfigFlagExitsZero verifies that `sora-admin --config PATH --help`
// (and `-h` / `--config=PATH`) prints root usage and exits 0 without requiring
// the config file to exist, while `sora-admin --config PATH` with no command
// and no help flag still exits 1.
func TestRootHelpWithConfigFlagExitsZero(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "nonexistent.toml")

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"--config PATH --help", []string{"--config", missingPath, "--help"}},
		{"--config PATH -h", []string{"--config", missingPath, "-h"}},
		{"--config=PATH --help", []string{"--config=" + missingPath, "--help"}},
		{"--config=PATH -h", []string{"--config=" + missingPath, "-h"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, code := runAdminMain(t, tc.args...)
			if code != 0 {
				t.Errorf("exit code %d, want 0:\n%s", code, out)
			}
			if !strings.Contains(out, "SORA Admin Tool") || !strings.Contains(out, "Usage:") {
				t.Errorf("expected root usage output, got:\n%s", out)
			}
		})
	}

	t.Run("--config PATH without command still exits 1", func(t *testing.T) {
		out, code := runAdminMain(t, "--config", missingPath)
		if code != 1 {
			t.Errorf("exit code %d, want 1:\n%s", code, out)
		}
		if !strings.Contains(out, "Usage:") {
			t.Errorf("expected usage output, got:\n%s", out)
		}
	})
}
