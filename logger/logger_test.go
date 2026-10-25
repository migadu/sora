package logger

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
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

// After newsyslog has renamed the log file, Reopen must send later lines to a
// fresh file at the configured path, not on into the rotated one.
func TestReopenFollowsRotation(t *testing.T) {
	// Initialize points the process's stdout and stderr at the log file.
	stdout, stderr := os.Stdout, os.Stderr
	t.Cleanup(func() { os.Stdout, os.Stderr = stdout, stderr })

	path := filepath.Join(t.TempDir(), "sora.log")
	lf, err := Initialize(config.LoggingConfig{Output: path, Format: "console", Level: "info"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lf.Close() })

	// What holds the descriptor before the rotation must follow the reopen:
	// the error handler keeps a log.Logger on os.Stderr, the servers' debug
	// output os.Stdout.
	held := log.New(os.Stderr, "", 0)

	Info("before rotation")
	rotated := path + ".0"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := Reopen(); err != nil {
		t.Fatal(err)
	}
	Info("after reopen")
	held.Print("held after reopen")
	fmt.Fprintln(os.Stdout, "stdout after reopen")

	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no new log file after Reopen: %v", err)
	}
	for _, want := range []string{"after reopen", "held after reopen", "stdout after reopen"} {
		if !strings.Contains(string(current), want) {
			t.Fatalf("new file lacks %q: %q", want, current)
		}
	}
	if strings.Contains(string(current), "before rotation") {
		t.Fatalf("new file has %q", current)
	}
	old, err := os.ReadFile(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(old), "before rotation") || strings.Contains(string(old), "after reopen") {
		t.Fatalf("rotated file has %q", old)
	}
}

// Reopen on a non-file output has nothing to do and must not fail.
func TestReopenWithoutFile(t *testing.T) {
	if _, err := Initialize(config.LoggingConfig{Output: "stderr"}); err != nil {
		t.Fatal(err)
	}
	if err := Reopen(); err != nil {
		t.Fatal(err)
	}
}
