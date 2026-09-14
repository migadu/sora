package config

import (
	"testing"
	"time"
)

// The IMAP per-command timeout overrides are plumbed field by field, so a new command
// can be added to the struct and silently never reach the server. This pins the whole
// mapping, RENAME included (it had no cap at all until the mailbox_path rename fix).
func TestGetCommandTimeoutsOverrides(t *testing.T) {
	s := &ServerConfig{Timeouts: &ServerTimeoutsConfig{IMAPCommandTimeouts: &CommandTimeoutsConfig{
		Search:      "1s",
		Sort:        "2s",
		Thread:      "3s",
		MultiSearch: "4s",
		Fetch:       "5s",
		Store:       "6s",
		Copy:        "7s",
		Move:        "8s",
		Rename:      "9s",
	}}}

	got, err := s.GetCommandTimeoutsOverrides()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := map[string]time.Duration{
		"search": time.Second, "sort": 2 * time.Second, "thread": 3 * time.Second,
		"multi_search": 4 * time.Second, "fetch": 5 * time.Second, "store": 6 * time.Second,
		"copy": 7 * time.Second, "move": 8 * time.Second, "rename": 9 * time.Second,
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d overrides, got %d: %v", len(want), len(got), got)
	}
	for name, d := range want {
		if got[name] != d {
			t.Errorf("%s: expected %v, got %v", name, d, got[name])
		}
	}
}

// An unset command must not produce an override, so the server keeps its default.
func TestGetCommandTimeoutsOverrides_OnlySetFields(t *testing.T) {
	s := &ServerConfig{Timeouts: &ServerTimeoutsConfig{IMAPCommandTimeouts: &CommandTimeoutsConfig{Rename: "45s"}}}

	got, err := s.GetCommandTimeoutsOverrides()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got["rename"] != 45*time.Second {
		t.Fatalf("expected only a rename override of 45s, got %v", got)
	}
}
