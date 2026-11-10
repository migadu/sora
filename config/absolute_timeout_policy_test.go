package config

import (
	"testing"
	"time"
)

func TestAbsoluteSessionTimeoutProtocolDefaults(t *testing.T) {
	for _, typ := range []string{"lmtp_proxy", "imap", "imap_proxy", "pop3", "managesieve"} {
		for _, timeouts := range []*ServerTimeoutsConfig{nil, {}} {
			cfg := ServerConfig{Type: typ, Timeouts: timeouts}
			got, err := cfg.GetAbsoluteSessionTimeout()
			want := 24 * time.Hour
			if typ == "lmtp_proxy" {
				want = 5 * time.Minute
			}
			if err != nil || got != want {
				t.Errorf("%s default: %v, %v; want %v", typ, got, err, want)
			}
		}
	}
}
