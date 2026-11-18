package main

import (
	"strings"
	"testing"
)

// TestSubcommandHelpContent (#2006): the help of acl, relay and import s3 subcommands has the
// shape of every other subcommand's: a one-line description first, a Usage line, and examples
// that pass --config. It was only the flag package's "Usage of <name>:" listing.
func TestSubcommandHelpContent(t *testing.T) {
	configPath := unreachableAdminConfig(t, true)
	for _, run := range [][]string{
		{"acl", "grant"}, {"acl", "revoke"}, {"acl", "list"},
		{"relay", "stats"}, {"relay", "list"}, {"relay", "show"}, {"relay", "delete"}, {"relay", "requeue"},
		{"import", "s3"},
	} {
		t.Run(strings.Join(run, " "), func(t *testing.T) {
			t.Parallel()
			out, code := runAdminMain(t, append(append([]string{"--config", configPath}, run...), "--help")...)
			if code != 0 {
				t.Errorf("exit code %d, want 0:\n%s", code, out)
			}
			first, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
			if strings.HasPrefix(first, "Usage") {
				t.Errorf("no description before the usage:\n%s", out)
			}
			name := "sora-admin --config PATH " + strings.Join(run, " ")
			if !strings.Contains(out, "Usage:\n  "+name) {
				t.Errorf("no %q Usage line:\n%s", name, out)
			}
			_, examples, ok := strings.Cut(out, "Examples:\n")
			if !ok || !strings.Contains(examples, "sora-admin --config config.toml "+strings.Join(run, " ")) {
				t.Errorf("no Examples section with --config:\n%s", out)
			}
		})
	}
}
