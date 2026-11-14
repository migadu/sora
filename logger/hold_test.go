package logger

import (
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
)

// holdBeforeInitialize starts a test as sora starts: nothing initialized, then Hold.
func holdBeforeInitialize(t *testing.T) {
	t.Helper()
	preserveLoggerState(t)
	globalLogger.Store(nil)
	held.Store(nil)
	t.Cleanup(func() { held.Store(nil) })
	Hold()
}

// What is logged between Hold and Initialize (#398: the warnings about the config file
// that configures logging) reaches the configured output at the configured level, with
// the attributes and groups it was logged with.
func TestHoldWritesToTheConfiguredOutput(t *testing.T) {
	holdBeforeInitialize(t)
	Info("held info")
	slog.Warn("held warn", "key", "value")
	log.Printf("held stdlib log")
	taken := With("component", "config").WithGroup("g")
	taken.Warn("held with attrs", "k", 1)

	path := filepath.Join(t.TempDir(), "sora.log")
	lf, err := Initialize(config.LoggingConfig{Output: path, Level: "warn"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lf.Close() })

	// A logger taken while holding writes to the configured output from then on.
	taken.Warn("taken warn after initialize", "k", 2)
	taken.Info("taken info after initialize")
	// Hold after Initialize changes nothing.
	Hold()
	Warn("warn after a late hold")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range []string{
		`level=WARN msg="held warn" key=value`,
		`level=WARN msg="held with attrs" component=config g.k=1`,
		`level=WARN msg="taken warn after initialize" component=config g.k=2`,
		`level=WARN msg="warn after a late hold"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("log lacks %q:\n%s", want, got)
		}
	}
	for _, notWant := range []string{"held info", "held stdlib log", "taken info after initialize"} {
		if strings.Contains(got, notWant) {
			t.Errorf("log has %q below level = \"warn\":\n%s", notWant, got)
		}
	}
	if n := strings.Count(got, "held warn"); n != 1 {
		t.Errorf("\"held warn\" written %d times, want once:\n%s", n, got)
	}
}

// A process that stops before Initialize writes what is held to stderr.
func TestSyncWritesWhatIsHeldToStderr(t *testing.T) {
	holdBeforeInitialize(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	Warn("held warn")
	Debug("held debug")
	Sync()
	Sync()
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if n := strings.Count(got, `level=WARN msg="held warn"`); n != 1 {
		t.Errorf("stderr has the held warning %d times, want once:\n%s", n, got)
	}
	if strings.Contains(got, "held debug") {
		t.Errorf("stderr has a DEBUG record:\n%s", got)
	}
}
