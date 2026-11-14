package pop3

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

	running := reloadableSettings{
		commandTimeout:         20 * time.Minute,
		libCommandTimeout:      20 * time.Minute,
		absoluteSessionTimeout: 2 * time.Hour,
		sessionMemoryLimit:     50 * 1024 * 1024,
	}
	s := &POP3Server{name: "pop3-reload"}
	s.settings.Store(&running)

	err := s.ReloadConfig(config.ServerConfig{
		Name: "pop3-reload", Type: "pop3",
		Limits:   &config.ServerLimitsConfig{SessionMemoryLimit: "50 megs"},
		Timeouts: &config.ServerTimeoutsConfig{CommandTimeout: "45 min", AbsoluteSessionTimeout: "2 hours"},
	})
	if err != nil {
		t.Fatal(err)
	}

	got := s.settings.Load()
	if got.commandTimeout != running.commandTimeout || got.libCommandTimeout != running.libCommandTimeout {
		t.Errorf("command_timeout = %v (idle %v), want the running %v", got.libCommandTimeout, got.commandTimeout, running.libCommandTimeout)
	}
	if got.absoluteSessionTimeout != running.absoluteSessionTimeout {
		t.Errorf("absolute_session_timeout = %v, want the running %v", got.absoluteSessionTimeout, running.absoluteSessionTimeout)
	}
	if got.sessionMemoryLimit != running.sessionMemoryLimit {
		t.Errorf("session_memory_limit = %d, want the running %d", got.sessionMemoryLimit, running.sessionMemoryLimit)
	}
	for key, kept := range map[string]any{
		"command_timeout":          running.libCommandTimeout,
		"absolute_session_timeout": running.absoluteSessionTimeout,
		"session_memory_limit":     running.sessionMemoryLimit,
	} {
		if !warnedKeeping(logs.String(), "pop3-reload", key, kept) {
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
