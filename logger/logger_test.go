package logger

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestSanitizeSyslogLine verifies CR/LF are collapsed so attacker-controlled fields
// cannot inject forged syslog lines (audit M6).
func TestSanitizeSyslogLine(t *testing.T) {
	cases := []struct{ in, want string }{
		{"normal message", "normal message"},
		{"line1\nline2", "line1\\nline2"},
		{"a\r\nb", "a\\r\\nb"},
		{"user=admin\nlevel=INFO msg=\"forged audit line\"", "user=admin\\nlevel=INFO msg=\"forged audit line\""},
		{"trailing\r", "trailing\\r"},
	}
	for _, c := range cases {
		if got := sanitizeSyslogLine(c.in); got != c.want {
			t.Errorf("sanitizeSyslogLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestFormatSyslogMessage verifies attribute values are rendered as valid
// logfmt: bare when they are a single token, quoted otherwise.
func TestFormatSyslogMessage(t *testing.T) {
	r := slog.NewRecord(time.Time{}, slog.LevelInfo, "message delivered", 0)
	r.AddAttrs(
		slog.String("mailbox", "INBOX"),
		slog.String("error", "connection refused"),
		slog.String("empty", ""),
		slog.String("quote", `say "hi"`),
		slog.String("kv", "a=b"),
		slog.Int("size", 1234),
		slog.Duration("took", 1500*time.Millisecond),
		slog.String("multi", "line1\nline2"),
	)
	handlerAttrs := []slog.Attr{slog.String("protocol", "LMTP")}

	got := formatSyslogMessage(r, handlerAttrs)
	want := `message delivered protocol=LMTP mailbox=INBOX error="connection refused" empty="" ` +
		`quote="say \"hi\"" kv="a=b" size=1234 took=1.5s multi="line1\nline2"`
	if got != want {
		t.Errorf("formatSyslogMessage =\n  %s\nwant\n  %s", got, want)
	}
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("formatted message contains a raw CR/LF: %q", got)
	}
}
