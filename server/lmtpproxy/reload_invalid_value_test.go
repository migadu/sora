package lmtpproxy

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
)

// A SIGHUP whose new absolute_session_timeout does not parse keeps the running value
// and says so at WARN, naming the server and the key (#442).
func TestReloadConfigUnparsableValueKeepsRunningValueAndWarns(t *testing.T) {
	var logs bytes.Buffer
	prev := logger.Swap(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { logger.Swap(prev) })

	cfg := config.ServerConfig{
		Name: "lmtp-proxy-reload", Type: "lmtp_proxy",
		Timeouts: &config.ServerTimeoutsConfig{AbsoluteSessionTimeout: "10 min"},
	}
	running := reloadableSettings{
		absoluteSessionTimeout: 10 * time.Minute,
		maxMessageSize:         cfg.GetMaxMessageSizeWithDefault(),
	}
	s := &Server{name: "lmtp-proxy-reload"}
	s.settings.Store(&running)

	if err := s.ReloadConfig(cfg); err != nil {
		t.Fatal(err)
	}

	if got := s.loadSettings().absoluteSessionTimeout; got != running.absoluteSessionTimeout {
		t.Errorf("absolute_session_timeout = %v, want the running %v", got, running.absoluteSessionTimeout)
	}
	warned := false
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "level=WARN") && strings.Contains(line, " absolute_session_timeout") &&
			strings.Contains(line, "name=lmtp-proxy-reload") && strings.Contains(line, "error=") &&
			strings.Contains(line, "running="+running.absoluteSessionTimeout.String()) {
			warned = true
		}
	}
	if !warned {
		t.Errorf("no WARN record naming absolute_session_timeout, its error and the kept value; logged:\n%s", logs.String())
	}
}
