package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestCommandHelpWithoutConfig (#1946): `--help` (or -h, -help) after a command or a
// subcommand prints its usage and exits 0 without a config file, or with one that does not
// load. The file was loaded before any command was dispatched, so without --config the tool
// stopped with "--config flag is required". It walks the command table: each command
// `sora-admin help` lists and each subcommand that command's usage lists.
func TestCommandHelpWithoutConfig(t *testing.T) {
	configPath := unreachableAdminConfig(t, true)
	missing := filepath.Join(t.TempDir(), "missing.toml")

	var runs [][]string
	top, _ := runAdminMain(t, "help")
	commands := listedNames(top, "Commands:")
	if len(commands) < minListedCommand {
		t.Fatalf("`sora-admin help` lists %d commands:\n%s", len(commands), top)
	}
	subcommands := 0
	for _, cmd := range commands {
		if cmd == "help" || cmd == "version" {
			continue
		}
		runs = append(runs, []string{cmd, "--help"}, []string{cmd, "-h"})
		// The subcommands are read from the usage printed with a config that loads.
		usage, _ := runAdminMain(t, "--config", configPath, cmd, "--help")
		for _, sub := range listedNames(usage, "Subcommands:") {
			runs = append(runs, []string{cmd, sub, "--help"}, []string{cmd, sub, "-h"})
			subcommands++
		}
	}
	if subcommands < 3*minListedCommand {
		t.Fatalf("the command usages list %d subcommands", subcommands)
	}
	runs = append(runs,
		// Not listed under "Subcommands:".
		[]string{"backends", "maintenance", "on", "--help"},
		[]string{"backends", "maintenance", "off", "-h"},
		[]string{"backends", "maintenance", "--help"},
		[]string{"backends", "status", "--help"},
		// -help is help to the flag package too.
		[]string{"accounts", "create", "-help"},
		// Flags before the help flag, in both spellings.
		[]string{"accounts", "create", "--email", "user@example.com", "--help"},
		[]string{"mailbox", "create", "--email=user@example.com", "--mailbox=Work", "-h"},
		// An argument before the help flag ends the flags, so the command would run.
		[]string{"migrate", "up", "extra", "--help"},
		// A config file that does not load.
		[]string{"--config", missing, "accounts", "create", "--help"},
		[]string{"mailbox", "list", "--config=" + missing, "--help"},
	)

	for _, args := range runs {
		name := strings.ReplaceAll(strings.Join(args, " "), missing, "missing.toml")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out, code := runAdminMain(t, args...)
			if code != 0 {
				t.Errorf("exit code %d, want 0:\n%s", code, out)
			}
			if !strings.Contains(out, "Usage") {
				t.Errorf("no usage printed:\n%s", out)
			}
			for _, bad := range []string{"--config flag is required", "Failed to "} {
				if strings.Contains(out, bad) {
					t.Errorf("output has %q:\n%s", bad, out)
				}
			}
		})
	}
}

// TestHelpAsFlagValueWithConfig (#1946): with a config that loads, "--help" given as a flag's
// value is that value, as before: the command runs (and here fails on the unreachable
// database) instead of printing its usage.
func TestHelpAsFlagValueWithConfig(t *testing.T) {
	configPath := unreachableAdminConfig(t, true)
	out, code := runAdminMain(t, "--config", configPath, "accounts", "show", "--email", "--help")
	if code == 0 {
		t.Errorf("exit code 0, want the command to run and fail:\n%s", out)
	}
	if strings.Contains(out, "Usage") {
		t.Errorf("--help as the value of --email printed the usage:\n%s", out)
	}
}
