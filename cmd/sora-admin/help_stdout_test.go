package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// runAdminMainSplit runs sora-admin with args, like runAdminMain, and returns its stdout and
// stderr apart, and its exit code.
func runAdminMainSplit(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestAdminMainHelper$")
	cmd.Env = append(os.Environ(), adminMainHelperEnv+"="+strings.Join(args, "\x1f"))
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok {
		return out.String(), errOut.String(), exitErr.ExitCode()
	}
	if err != nil {
		t.Fatalf("running sora-admin %v: %v", args, err)
	}
	return out.String(), errOut.String(), 0
}

// TestSubcommandHelpOnStdout (#1980): `--help` after any subcommand prints its usage on
// stdout and nothing on stderr, so `sora-admin <command> <subcommand> --help | less` shows
// it. acl, relay and import s3 left the usage to the flag package's default, which writes
// to stderr. It walks each command `sora-admin help` lists and each subcommand its usage
// lists.
func TestSubcommandHelpOnStdout(t *testing.T) {
	configPath := unreachableAdminConfig(t, true)

	top, _ := runAdminMain(t, "help")
	commands := listedNames(top, "Commands:")
	if len(commands) < minListedCommand {
		t.Fatalf("`sora-admin help` lists %d commands:\n%s", len(commands), top)
	}
	var runs [][]string
	for _, cmd := range commands {
		if cmd == "help" || cmd == "version" || cmd == "config" {
			continue // config parses its own --config; its help is tested elsewhere
		}
		usage, _ := runAdminMain(t, "--config", configPath, cmd, "--help")
		for _, sub := range listedNames(usage, "Subcommands:") {
			runs = append(runs, []string{cmd, sub})
		}
	}
	if len(runs) < 3*minListedCommand {
		t.Fatalf("the command usages list %d subcommands", len(runs))
	}

	for _, run := range runs {
		for _, help := range []string{"--help", "-h"} {
			args := append(append([]string{"--config", configPath}, run...), help)
			t.Run(strings.Join(append(run, help), " "), func(t *testing.T) {
				t.Parallel()
				stdout, stderr, code := runAdminMainSplit(t, args...)
				if code != 0 {
					t.Errorf("exit code %d, want 0:\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
				}
				if !strings.Contains(stdout, "Usage") {
					t.Errorf("no usage on stdout:\n%s", stdout)
				}
				if stderr != "" {
					t.Errorf("stderr is not empty:\n%s", stderr)
				}
			})
		}
	}
}

// TestUsageErrorStreams (#2025): a subcommand run without a required flag prints the error
// line on stderr and the usage after it on stdout, the stream --help prints it on. acl wrote
// the error on stdout and its flag listing on stderr, so either redirect showed half of it.
func TestUsageErrorStreams(t *testing.T) {
	configPath := unreachableAdminConfig(t, true)
	for _, tc := range []struct {
		missing string
		args    []string
	}{
		{"--email", []string{"acl", "grant"}},
		{"--mailbox", []string{"acl", "grant", "--email", "owner@example.com"}},
		{"--identifier", []string{"acl", "grant", "--email", "owner@example.com", "--mailbox", "Shared/Sales"}},
		{"--rights", []string{"acl", "grant", "--email", "owner@example.com", "--mailbox", "Shared/Sales", "--user", "bob@example.com"}},
		{"--email", []string{"acl", "revoke"}},
		{"--identifier", []string{"acl", "revoke", "--email", "owner@example.com", "--mailbox", "Shared/Sales"}},
		{"--mailbox", []string{"acl", "list", "--email", "owner@example.com"}},
		{"--id", []string{"relay", "show"}},
		{"--id", []string{"relay", "delete"}},
		{"--id", []string{"relay", "requeue"}},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			t.Parallel()
			stdout, stderr, code := runAdminMainSplit(t, append([]string{"--config", configPath}, tc.args...)...)
			if code != 1 {
				t.Errorf("exit code %d, want 1", code)
			}
			if !strings.Contains(stderr, "Error: "+tc.missing) || strings.Contains(stderr, "Usage") {
				t.Errorf("stderr does not hold just the %s error:\n%s", tc.missing, stderr)
			}
			if !strings.Contains(stdout, "Usage:\n  sora-admin --config PATH "+strings.Join(tc.args[:2], " ")) || strings.Contains(stdout, "Error") {
				t.Errorf("stdout does not hold just the usage:\n%s", stdout)
			}
		})
	}
}
