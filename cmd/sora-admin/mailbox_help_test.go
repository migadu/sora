package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMailboxSubcommandHelpExamples (#1902): the help of each `mailbox` subcommand shows
// examples of that subcommand only. `mailbox fix-utf7 --help` listed two
// `mailbox repair-unseen` examples among its own.
func TestMailboxSubcommandHelpExamples(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(configPath, []byte("[database]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{
		"create", "list", "delete", "rename", "subscribe", "unsubscribe",
		"fix-utf7", "repair-hierarchy", "repair-unseen",
	} {
		t.Run(sub, func(t *testing.T) {
			out, code := runAdminMain(t, "--config", configPath, "mailbox", sub, "--help")
			if code != 0 {
				t.Fatalf("exit code %d, want 0:\n%s", code, out)
			}
			_, examples, ok := strings.Cut(out, "\nExamples:\n")
			if !ok {
				t.Fatalf("no Examples section:\n%s", out)
			}
			own := 0
			for _, line := range strings.Split(examples, "\n") {
				_, rest, ok := strings.Cut(line, "sora-admin mailbox ")
				if !ok {
					continue
				}
				if name, _, _ := strings.Cut(rest, " "); name != sub {
					t.Errorf("example names %q, not %q: %s", name, sub, strings.TrimSpace(line))
					continue
				}
				own++
			}
			if own == 0 {
				t.Errorf("no %q example:\n%s", sub, out)
			}
		})
	}

	// The repair-unseen examples belong in its own help.
	out, _ := runAdminMain(t, "--config", configPath, "mailbox", "repair-unseen", "--help")
	for _, want := range []string{
		"sora-admin mailbox repair-unseen --config config.toml\n",
		"sora-admin mailbox repair-unseen --config config.toml --apply\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("repair-unseen help lacks %q:\n%s", strings.TrimSpace(want), out)
		}
	}
}
