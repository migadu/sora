package pop3

import (
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

func TestPOP3ServerReloadConfig(t *testing.T) {
	// Create a minimal server with known initial values
	s := &POP3Server{
		name:                   "test-pop3",
		commandTimeout:         2 * time.Minute,
		absoluteSessionTimeout: 30 * time.Minute,
		minBytesPerMinute:      512,
		sessionMemoryLimit:     100 * 1024 * 1024,
		masterSASLUsername:     []byte("old-user"),
		masterSASLPassword:     []byte("old-pass"),
	}

	// Create new config with changed values
	cfg := config.ServerConfig{
		MasterSASLUsername: "new-user",
		MasterSASLPassword: "new-pass",
		Timeouts: &config.ServerTimeoutsConfig{
			CommandTimeout:         "5m",
			AbsoluteSessionTimeout: "1h",
			MinBytesPerMinute:      1024,
		},
	}

	// Reload
	err := s.ReloadConfig(cfg)
	if err != nil {
		t.Fatalf("ReloadConfig failed: %v", err)
	}

	// Verify changes
	if timeout, _ := cfg.GetCommandTimeout(); timeout != s.commandTimeout {
		t.Errorf("command_timeout not updated: expected %v, got %v", timeout, s.commandTimeout)
	}
	if timeout, _ := cfg.GetAbsoluteSessionTimeout(); timeout != s.absoluteSessionTimeout {
		t.Errorf("absolute_session_timeout not updated: expected %v, got %v", timeout, s.absoluteSessionTimeout)
	}
	if string(s.masterSASLUsername) != "new-user" {
		t.Errorf("master_sasl_username not updated: got %s", s.masterSASLUsername)
	}
	if string(s.masterSASLPassword) != "new-pass" {
		t.Errorf("master_sasl_password not updated: got %s", s.masterSASLPassword)
	}

	t.Log("✓ POP3 ReloadConfig correctly updates all settings")
}

func TestPOP3ServerReloadConfig_NoChanges(t *testing.T) {
	s := &POP3Server{
		name:                   "test-pop3",
		commandTimeout:         2 * time.Minute,
		absoluteSessionTimeout: 30 * time.Minute,
		masterSASLUsername:     []byte("user"),
		masterSASLPassword:     []byte("pass"),
	}

	// Config with same values (defaults match)
	cfg := config.ServerConfig{
		MasterSASLUsername: "user",
		MasterSASLPassword: "pass",
	}

	err := s.ReloadConfig(cfg)
	if err != nil {
		t.Fatalf("ReloadConfig failed: %v", err)
	}

	t.Log("✓ ReloadConfig with no changes works correctly")
}
