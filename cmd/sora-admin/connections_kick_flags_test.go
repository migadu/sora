package main

import (
	"strings"
	"testing"
)

// TestConnectionsKickOffersOnlyImplementedFlags (#1901): "connections kick" defined
// --server, --client and --all, then refused every one of them in kickConnections, so
// the flags were advertised by the parser but could never be used. The command offers
// only what it implements: the parser rejects the three, and the flags it keeps work.
func TestConnectionsKickOffersOnlyImplementedFlags(t *testing.T) {
	for _, extra := range [][]string{
		{"--server", "192.0.2.10:143"},
		{"--client", "198.51.100.7:50000"},
		{"--all"},
	} {
		flagName := strings.TrimLeft(extra[0], "-")
		t.Run(flagName, func(t *testing.T) {
			configPath, requests := adminAPIStub(t, `{"message":"kicked"}`)
			args := append([]string{"--config", configPath, "connections", "kick", "--user", "user@example.com", "-y"}, extra...)
			out, code := runAdminMain(t, args...)
			if want := "flag provided but not defined: -" + flagName; !strings.Contains(out, want) {
				t.Errorf("output does not contain %q (exit %d):\n%s", want, code, out)
			}
			if code == 0 {
				t.Errorf("exit code 0, want non-zero:\n%s", out)
			}
			if n := requests.Load(); n != 0 {
				t.Errorf("sent %d kick requests, want 0", n)
			}
		})
	}

	t.Run("user protocol confirm", func(t *testing.T) {
		configPath, requests := adminAPIStub(t, `{"message":"kicked"}`)
		out, code := runAdminMain(t, "--config", configPath, "connections", "kick", "--user", "user@example.com", "--protocol", "imap", "--confirm")
		if code != 0 {
			t.Errorf("exit code %d, want 0:\n%s", code, out)
		}
		if n := requests.Load(); n != 1 {
			t.Errorf("sent %d kick requests, want 1:\n%s", n, out)
		}
	})
}
