package main

import (
	"strings"
	"testing"
)

// TestErrorsOnStderr (#2029): an error message goes to stderr, so stdout carries only the
// command's output (and, after a usage error, the usage). Most commands printed their
// "Error: ..." line on stdout. One representative error path per command group.
func TestErrorsOnStderr(t *testing.T) {
	configPath := unreachableAdminConfig(t, true)
	for _, tc := range []struct {
		want string
		args []string
	}{
		{"Unknown command: bogus", []string{"bogus"}},
		{"Error: either --email or --credentials is required", []string{"accounts", "create"}},
		{"Unknown acl subcommand: bogus", []string{"acl", "bogus"}},
		{"Error: --primary is required", []string{"credentials", "add"}},
		{"Error: --email is required", []string{"mailbox", "create"}},
		{"Error: --email is required", []string{"sieve", "list"}},
		{"ERROR: --email is required", []string{"messages", "list-deleted"}},
		{"Error: --email is required", []string{"import", "maildir"}},
		{"Error: --email is required", []string{"export", "maildir"}},
		{"Error: --user is required", []string{"connections", "kick"}},
		{"Relay is not configured", []string{"relay", "stats"}},
		{"Unknown cache subcommand: bogus", []string{"cache", "bogus"}},
		{"Unknown auth-cache subcommand: bogus", []string{"auth-cache", "bogus"}},
		{"Unknown affinity-cache subcommand: bogus", []string{"affinity-cache", "bogus"}},
		{"Unknown affinity subcommand: bogus", []string{"affinity", "bogus"}},
		{"Unknown stats subcommand: bogus", []string{"stats", "bogus"}},
		{"Unknown health subcommand: bogus", []string{"health", "bogus"}},
		{"Unknown migrate subcommand: bogus", []string{"migrate", "bogus"}},
		{"Unknown backends subcommand: bogus", []string{"backends", "bogus"}},
		{"Unknown tls subcommand: bogus", []string{"tls", "bogus"}},
		{"Unknown verify subcommand: bogus", []string{"verify", "bogus"}},
		{"Unknown uploader subcommand: bogus", []string{"uploader", "bogus"}},
		{"Unknown config subcommand: bogus", []string{"config", "bogus"}},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			t.Parallel()
			stdout, stderr, code := runAdminMainSplit(t, append([]string{"--config", configPath}, tc.args...)...)
			if code == 0 {
				t.Errorf("exit code 0, want an error")
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr lacks %q:\n%s", tc.want, stderr)
			}
			if strings.Contains(stdout, tc.want) {
				t.Errorf("stdout has %q:\n%s", tc.want, stdout)
			}
		})
	}
}
