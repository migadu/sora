package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCommandOverviewExamples (#1936): a command group's overview (`sora-admin <group>
// help`) shows an example for every subcommand it lists. The mailbox overview had none
// for repair-unseen or unsubscribe, the verify overview none for body-deletions.
func TestCommandOverviewExamples(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(configPath, []byte("[database]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Every group whose overview has a Subcommands and an Examples section.
	for _, group := range []string{
		"accounts", "acl", "credentials", "mailbox", "cache", "auth-cache", "affinity-cache",
		"stats", "connections", "affinity", "migrate", "import", "export", "uploader",
		"messages", "relay", "verify", "tls", "sieve",
	} {
		t.Run(group, func(t *testing.T) {
			out, _ := runAdminMain(t, "--config", configPath, group, "help")
			_, rest, ok := strings.Cut(out, "\nSubcommands:\n")
			if !ok {
				t.Fatalf("no Subcommands section:\n%s", out)
			}
			list, examples, ok := strings.Cut(rest, "\nExamples:\n")
			if !ok {
				t.Fatalf("no Examples section:\n%s", out)
			}
			var subs []string
			for _, line := range strings.Split(list, "\n") {
				if strings.TrimSpace(line) == "" {
					break
				}
				if sub := strings.Fields(line)[0]; sub != "help" {
					subs = append(subs, sub)
				}
			}
			if len(subs) == 0 {
				t.Fatalf("no subcommands listed:\n%s", out)
			}
			shown := map[string]bool{}
			for _, line := range strings.Split(examples, "\n") {
				_, cmd, ok := strings.Cut(line, "sora-admin ")
				if !ok {
					continue
				}
				fields := strings.Fields(cmd)
				// The global --config may come before the group.
				for len(fields) > 1 && fields[0] == "--config" {
					fields = fields[2:]
				}
				if len(fields) > 1 && fields[0] == group {
					shown[fields[1]] = true
				}
			}
			for _, sub := range subs {
				if !shown[sub] {
					t.Errorf("%s overview lists %q but shows no example of it", group, sub)
				}
			}
		})
	}
}
