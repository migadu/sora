package lmtpproxy

import (
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

func TestReloadConfigPreservesLMTPTimeoutDefault(t *testing.T) {
	for _, timeouts := range []*config.ServerTimeoutsConfig{nil, {}} {
		s := &Server{}
		s.settings.Store(&reloadableSettings{absoluteSessionTimeout: 5 * time.Minute})
		if err := s.ReloadConfig(config.ServerConfig{Type: "lmtp_proxy", Timeouts: timeouts}); err != nil {
			t.Fatal(err)
		}
		if got := s.loadSettings().absoluteSessionTimeout; got != 5*time.Minute {
			t.Errorf("unchanged config reload changed 5m to %v", got)
		}
	}
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{{"0", 0}, {"2h", 2 * time.Hour}, {"24h", 24 * time.Hour}} {
		s := &Server{}
		s.settings.Store(&reloadableSettings{absoluteSessionTimeout: 5 * time.Minute})
		if err := s.ReloadConfig(config.ServerConfig{Type: "lmtp_proxy", Timeouts: &config.ServerTimeoutsConfig{AbsoluteSessionTimeout: tc.value}}); err != nil {
			t.Fatal(err)
		}
		if got := s.loadSettings().absoluteSessionTimeout; got != tc.want {
			t.Errorf("explicit %s became %v", tc.value, got)
		}
	}
}
