package logger

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

// preserveLoggerState isolates tests that Initialize the process-wide logger.
func preserveLoggerState(t *testing.T) {
	t.Helper()
	previousLogger, previousFile := globalLogger.Load(), fileOutput.Load()
	previousDefault := slog.Default()
	previousWriter, previousFlags, previousPrefix := log.Writer(), log.Flags(), log.Prefix()
	stdout, stderr := os.Stdout, os.Stderr
	t.Cleanup(func() {
		globalLogger.Store(previousLogger)
		fileOutput.Store(previousFile)
		slog.SetDefault(previousDefault)
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
		log.SetPrefix(previousPrefix)
		os.Stdout, os.Stderr = stdout, stderr
	})
}

// After newsyslog has renamed the log file, every retained writer must send
// later lines to the configured path, including writers captured before startup.
func TestReopenFollowsRotation(t *testing.T) {
	preserveLoggerState(t)
	stdout, stderr := Stdout(), Stderr()
	held := log.New(stderr, "", 0)
	originalStdout, originalStderr := os.Stdout, os.Stderr

	path := filepath.Join(t.TempDir(), "sora.log")
	lf, err := Initialize(config.LoggingConfig{Output: path, Format: "console", Level: "info"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lf.Close() })
	if os.Stdout != originalStdout || os.Stderr != originalStderr {
		t.Fatal("Initialize replaced the process stdout or stderr")
	}

	Info("before rotation")
	rotated := path + ".0"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := Reopen(); err != nil {
		t.Fatal(err)
	}
	Info("after reopen")
	if err := held.Output(1, "held after reopen"); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(stdout, "stdout after reopen"); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(stderr, "stderr after reopen"); err != nil {
		t.Fatal(err)
	}

	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no new log file after Reopen: %v", err)
	}
	for _, want := range []string{"after reopen", "held after reopen", "stdout after reopen", "stderr after reopen"} {
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

// Direct protocol and error writers must not race rotation and lose records.
func TestReopenConcurrentWriters(t *testing.T) {
	preserveLoggerState(t)
	stdout, stderr := Stdout(), Stderr()
	held := log.New(stderr, "", 0)
	dir := t.TempDir()
	path := filepath.Join(dir, "sora.log")
	lf, err := Initialize(config.LoggingConfig{Output: path, Level: "info"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lf.Close() })

	const workers, records, rotations = 8, 5000, 100
	start := make(chan struct{})
	writeErrors := make(chan error, workers)
	var writers sync.WaitGroup
	for worker := range workers {
		writers.Add(1)
		go func() {
			defer writers.Done()
			<-start
			for record := range records {
				id := worker*records + record
				var err error
				switch worker % 4 {
				case 0:
					Info("concurrent write", "record", id)
				case 1:
					_, err = fmt.Fprintf(stdout, "record=%d\n", id)
				case 2:
					_, err = fmt.Fprintf(stderr, "record=%d\n", id)
				case 3:
					err = held.Output(1, fmt.Sprintf("record=%d", id))
				}
				if err != nil {
					writeErrors <- fmt.Errorf("record %d: %w", id, err)
					return
				}
			}
		}()
	}
	close(start)
	var rotationErr error
	for rotation := range rotations {
		if err := os.Rename(path, fmt.Sprintf("%s.%d", path, rotation)); err != nil {
			rotationErr = err
			break
		}
		if err := Reopen(); err != nil {
			rotationErr = err
			break
		}
	}
	writers.Wait()
	close(writeErrors)
	for err := range writeErrors {
		t.Error(err)
	}
	if rotationErr != nil {
		t.Fatal(rotationErr)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := make([]bool, workers*records)
	for _, entry := range entries {
		f, err := os.Open(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			found := false
			for _, field := range strings.Fields(line) {
				value, ok := strings.CutPrefix(field, "record=")
				if !ok {
					continue
				}
				id, err := strconv.Atoi(value)
				if err != nil || id < 0 || id >= len(seen) {
					t.Errorf("invalid record in %s: %q", entry.Name(), line)
					break
				}
				if seen[id] {
					t.Errorf("duplicate record %d in %s", id, entry.Name())
				}
				seen[id] = true
				found = true
				break
			}
			if !found {
				t.Errorf("unrecognized record in %s: %q", entry.Name(), line)
			}
		}
		scanErr := scanner.Err()
		f.Close()
		if scanErr != nil {
			t.Fatal(scanErr)
		}
	}
	missing := 0
	for _, present := range seen {
		if !present {
			missing++
		}
	}
	if missing != 0 {
		t.Fatalf("lost %d of %d records during rotation", missing, len(seen))
	}
}

func TestReopenFailureKeepsCurrentFile(t *testing.T) {
	preserveLoggerState(t)
	stdout := Stdout()
	path := filepath.Join(t.TempDir(), "sora.log")
	lf, err := Initialize(config.LoggingConfig{Output: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lf.Close() })
	rotated := path + ".0"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	// A directory at the path makes opening it for writing fail even as root.
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := Reopen(); err == nil {
		t.Fatal("Reopen succeeded with a directory at the log path")
	}
	Info("slog after failed reopen")
	if _, err := fmt.Fprintln(stdout, "stdout after failed reopen"); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(rotated)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"slog after failed reopen", "stdout after failed reopen"} {
		if !strings.Contains(string(old), want) {
			t.Errorf("current descriptor lost %q after failed reopen: %q", want, old)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := Reopen(); err != nil {
		t.Fatal(err)
	}
	Info("recovered logging")
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(current), "recovered logging") || strings.Contains(string(current), "failed reopen") {
		t.Fatalf("unexpected recovered log: %q", current)
	}
}

func TestReopenAfterClose(t *testing.T) {
	preserveLoggerState(t)
	path := filepath.Join(t.TempDir(), "sora.log")
	lf, err := Initialize(config.LoggingConfig{Output: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lf.Close() })
	if err := lf.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := lf.reopen(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("reopen after Close = %v, want os.ErrClosed", err)
	}
	if err := Reopen(); err != nil {
		t.Fatalf("package Reopen after Close: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Reopen after Close recreated the log path: %v", err)
	}
}

// Reopen on a non-file output has nothing to do and must not fail.
func TestReopenWithoutFile(t *testing.T) {
	preserveLoggerState(t)
	if _, err := Initialize(config.LoggingConfig{Output: "stderr"}); err != nil {
		t.Fatal(err)
	}
	if err := Reopen(); err != nil {
		t.Fatal(err)
	}
}
