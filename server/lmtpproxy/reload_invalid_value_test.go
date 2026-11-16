package lmtpproxy

import (
	"bytes"
	"log/slog"
	"math"
	"strconv"
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

// A SIGHUP whose max_message_size does not parse keeps the running limit (the SIZE the
// proxy advertises) and says so at WARN, naming the server, the key, the error and the
// kept value; it does not report max_message_size as reloaded (#669). Before, the reload
// replaced the running limit with the 50 MB default. A value that parses still applies,
// capped at the largest message sora can store, as at start-up.
func TestReloadConfigMaxMessageSize(t *testing.T) {
	logs := &lockedBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { logger.Swap(prev) })

	const running = 100 << 20
	for _, tt := range []struct {
		name         string
		reload       string
		want         int64
		wantReloaded bool
		wantWarn     bool
	}{
		{name: "unparsable keeps the running limit", reload: "100 MiB", want: running, wantWarn: true},
		{name: "unchanged", reload: "100mb", want: running},
		{name: "changed", reload: "60mb", want: 60 << 20, wantReloaded: true},
		{name: "omitted is the default", reload: "", want: 50 << 20, wantReloaded: true},
		{name: "above storable is clamped", reload: "3gb", want: math.MaxInt32, wantReloaded: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			name := "lmtp-proxy-" + strings.ReplaceAll(tt.name, " ", "-")
			s := &Server{name: name}
			s.settings.Store(&reloadableSettings{maxMessageSize: running})

			logsBefore := len(logs.String())
			if err := s.ReloadConfig(config.ServerConfig{Name: name, Type: "lmtp_proxy", MaxMessageSize: tt.reload}); err != nil {
				t.Fatal(err)
			}
			logged := logs.String()[logsBefore:]

			if got := s.loadSettings().maxMessageSize; got != tt.want {
				t.Errorf("max_message_size after reloading %q = %d, want %d", tt.reload, got, tt.want)
			}
			reported, warned := false, false
			for _, line := range strings.Split(logged, "\n") {
				if !strings.Contains(line, "max_message_size") || !strings.Contains(line, "name="+name) {
					continue
				}
				if strings.Contains(line, "config reloaded") {
					reported = true
				}
				if strings.Contains(line, "level=WARN") && strings.Contains(line, "error=") &&
					strings.Contains(line, "running="+strconv.Itoa(running)) {
					warned = true
				}
			}
			if reported != tt.wantReloaded {
				t.Errorf("reloading %q reported max_message_size as reloaded: %v, want %v; logged:\n%s", tt.reload, reported, tt.wantReloaded, logged)
			}
			if warned != tt.wantWarn {
				t.Errorf("WARN naming max_message_size, the error and the kept limit: %v, want %v; logged:\n%s", warned, tt.wantWarn, logged)
			}
		})
	}
}
