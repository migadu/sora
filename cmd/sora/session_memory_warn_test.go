package main

import (
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/errors"
)

// sessionMemoryWarning is what the WARN about a session_memory_limit below an LMTP
// max_message_size says.
const sessionMemoryWarning = "session_memory_limit is below the max_message_size of an lmtp server"

// sessionMemoryTOML is a backend with an IMAP, a POP3 and an LMTP server; limits
// are the [[server]] lines the test sets.
func sessionMemoryTOML(imapLimit, pop3Limit, lmtp string) string {
	limit := func(v string) string {
		if v == "" {
			return ""
		}
		return `limits.session_memory_limit = "` + v + `"` + "\n"
	}
	return `
[database.write]
hosts = ["localhost"]

[s3]
endpoint = "s3.example.com"
bucket = "mail"

[[server]]
type = "imap"
name = "imap"
addr = ":143"
` + limit(imapLimit) + `
[[server]]
type = "pop3"
name = "pop3"
addr = ":110"
` + limit(pop3Limit) + lmtp
}

func lmtpTOML(name, addr, maxMessageSize string) string {
	s := "\n[[server]]\ntype = \"lmtp\"\nname = \"" + name + "\"\naddr = \"" + addr + "\"\n"
	if maxMessageSize != "" {
		s += `max_message_size = "` + maxMessageSize + `"` + "\n"
	}
	return s
}

// TestSessionMemoryBelowLMTPMaxMessageSizeWarns: an IMAP or POP3 session loads a
// whole message body into its session_memory_limit, so with a limit below an LMTP
// server's max_message_size a message can be delivered that the server never
// fetches: FETCH answers NO [LIMIT] and RETR -ERR [SYS/PERM]. Start-up and a reload
// say so once per such server, naming both values. Production runs 200mb against
// 55mb, which must not warn.
func TestSessionMemoryBelowLMTPMaxMessageSizeWarns(t *testing.T) {
	tests := []struct {
		name string
		toml string
		want map[string][]string // server -> what its WARN line names
	}{
		{
			name: "production: 200mb sessions, 55mb LMTP",
			toml: sessionMemoryTOML("200mb", "200mb", lmtpTOML("lmtp", ":24", "55mb")),
		},
		{
			name: "defaults: 100mb sessions, 50mb LMTP",
			toml: sessionMemoryTOML("", "", lmtpTOML("lmtp", ":24", "")),
		},
		{
			name: "no session limit",
			toml: sessionMemoryTOML("0", "0", lmtpTOML("lmtp", ":24", "55mb")),
		},
		{
			name: "no LMTP server",
			toml: sessionMemoryTOML("10mb", "10mb", ""),
		},
		{
			name: "IMAP below LMTP",
			toml: sessionMemoryTOML("50mb", "200mb", lmtpTOML("lmtp", ":24", "55mb")),
			want: map[string][]string{"imap": {"type=imap", "session_memory_limit=52428800", "lmtp_server=lmtp", "max_message_size=57671680"}},
		},
		{
			name: "POP3 below LMTP",
			toml: sessionMemoryTOML("200mb", "50mb", lmtpTOML("lmtp", ":24", "55mb")),
			want: map[string][]string{"pop3": {"type=pop3", "session_memory_limit=52428800", "lmtp_server=lmtp", "max_message_size=57671680"}},
		},
		{
			name: "the largest of two LMTP servers",
			toml: sessionMemoryTOML("50mb", "50mb", lmtpTOML("lmtp-small", ":24", "40mb")+lmtpTOML("lmtp-large", ":2424", "60mb")),
			want: map[string][]string{
				"imap": {"type=imap", "session_memory_limit=52428800", "lmtp_server=lmtp-large", "max_message_size=62914560"},
				"pop3": {"type=pop3", "session_memory_limit=52428800", "lmtp_server=lmtp-large", "max_message_size=62914560"},
			},
		},
	}

	check := func(t *testing.T, out string, want map[string][]string) {
		t.Helper()
		var lines []string
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, sessionMemoryWarning) {
				lines = append(lines, line)
			}
		}
		if len(lines) != len(want) {
			t.Fatalf("got %d session_memory_limit warnings, want %d:\n%s", len(lines), len(want), out)
		}
		for server, parts := range want {
			found := false
			for _, line := range lines {
				if !strings.Contains(line, "server="+server+" ") {
					continue
				}
				found = true
				if !strings.Contains(line, "level=WARN") {
					t.Errorf("server %s: warning not at WARN: %s", server, line)
				}
				for _, part := range append(parts, "import_message_limit") {
					if !strings.Contains(line, part) {
						t.Errorf("server %s: warning does not name %q: %s", server, part, line)
					}
				}
			}
			if !found {
				t.Errorf("no warning for server %s:\n%s", server, strings.Join(lines, "\n"))
			}
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run("start-up", func(t *testing.T) {
				logs := captureReloadLogs(t)
				cfg := config.NewDefaultConfig()
				loadAndValidateConfig(writeReloadConfig(t, tt.toml), &cfg, errors.NewErrorHandler())
				check(t, logs.String(), tt.want)
			})
			t.Run("reload", func(t *testing.T) {
				logs := captureReloadLogs(t)
				cfg := startupConfig()
				handleConfigReload(&cfg, reloadedFrom(t, tt.toml))
				check(t, logs.String(), tt.want)
			})
		})
	}
}
