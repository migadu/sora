package managesieve

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
)

// A SIGHUP whose new value for a reloadable setting does not parse keeps the running
// value and says so at WARN, naming the server and the key (#442).
func TestReloadConfigUnparsableValueKeepsRunningValueAndWarns(t *testing.T) {
	var logs bytes.Buffer
	prev := logger.Swap(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { logger.Swap(prev) })

	cfg := config.ServerConfig{
		Name: "sieve-reload", Type: "managesieve",
		Timeouts: &config.ServerTimeoutsConfig{CommandTimeout: "4 min", AbsoluteSessionTimeout: "2 hours"},
	}
	running := reloadableSettings{
		commandTimeout:         5 * time.Minute,
		absoluteSessionTimeout: 2 * time.Hour,
		maxScriptSize:          cfg.GetMaxScriptSizeWithDefault(),
	}
	s := &ManageSieveServer{name: "sieve-reload"}
	s.settings.Store(&running)

	if err := s.ReloadConfig(cfg); err != nil {
		t.Fatal(err)
	}

	got := s.settings.Load()
	if got.commandTimeout != running.commandTimeout {
		t.Errorf("command_timeout = %v, want the running %v", got.commandTimeout, running.commandTimeout)
	}
	if got.absoluteSessionTimeout != running.absoluteSessionTimeout {
		t.Errorf("absolute_session_timeout = %v, want the running %v", got.absoluteSessionTimeout, running.absoluteSessionTimeout)
	}
	for key, kept := range map[string]any{
		"command_timeout":          running.commandTimeout,
		"absolute_session_timeout": running.absoluteSessionTimeout,
	} {
		if !warnedKeeping(logs.String(), "sieve-reload", key, kept) {
			t.Errorf("no WARN record naming %s, its error and the kept value %v; logged:\n%s", key, kept, logs.String())
		}
	}
}

// warnedKeeping reports whether logs hold a WARN record for server name about key that
// carries the parse error and the value kept.
func warnedKeeping(logs, name, key string, kept any) bool {
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "level=WARN") && strings.Contains(line, " "+key) &&
			strings.Contains(line, "name="+name) && strings.Contains(line, "error=") &&
			strings.Contains(line, fmt.Sprintf("running=%v", kept)) {
			return true
		}
	}
	return false
}
