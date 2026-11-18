package main

import (
	"strings"
	"testing"
)

// TestFlagBeforeCommandRefused (#1982): only --config (and the help and version flags) may
// come before the command. Any other flag there stayed in the arguments the command handlers
// read by position, so `--foo accounts list` made the accounts handler see "accounts" as its
// subcommand and every later argument shifted by one.
func TestFlagBeforeCommandRefused(t *testing.T) {
	configPath := unreachableAdminConfig(t, true)
	for _, tc := range []struct {
		flag string
		args []string
	}{
		{"--foo", []string{"--foo", "accounts", "list", "--config", configPath}},
		{"--foo", []string{"--foo", "accounts", "create", "--help", "--config", configPath}},
		{"--email", []string{"--config", configPath, "--email", "user@example.com", "accounts", "show"}},
		{"-x", []string{"--config=" + configPath, "-x", "mailbox", "list", "--email", "user@example.com"}},
		{"-config", []string{"-config", configPath, "accounts", "list"}},
		{"--dry-run", []string{"--dry-run", "config", "validate", "--config", configPath}},
	} {
		name := strings.ReplaceAll(strings.Join(tc.args, " "), configPath, "config.toml")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out, code := runAdminMain(t, tc.args...)
			if code != 1 {
				t.Errorf("exit code %d, want 1:\n%s", code, out)
			}
			if !strings.Contains(out, tc.flag+" before the command") {
				t.Errorf("output does not refuse %s before the command:\n%s", tc.flag, out)
			}
			if strings.Contains(out, "Unknown") || strings.Contains(out, "Failed to") {
				t.Errorf("the line was read as a command:\n%s", out)
			}
		})
	}

	// The flags the top level answers stay accepted before the command.
	for _, tc := range []struct {
		want string
		args []string
	}{
		{"Usage", []string{"--config", configPath, "--help"}},
		{"Usage", []string{"--config=" + configPath, "-h", "accounts"}},
		{"sora-admin version", []string{"--config", configPath, "--version"}},
		{"sora-admin version", []string{"--config", configPath, "-v", "accounts", "list"}},
		{"Usage", []string{"--config", configPath, "accounts", "--help"}},
	} {
		name := strings.ReplaceAll(strings.Join(tc.args, " "), configPath, "config.toml")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out, code := runAdminMain(t, tc.args...)
			if code != 0 || !strings.Contains(out, tc.want) {
				t.Errorf("exit code %d, want 0 and %q:\n%s", code, tc.want, out)
			}
		})
	}
}
