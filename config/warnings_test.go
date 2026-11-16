package config

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
)

// Warning collection must not apply mutating defaults to the loaded file or log
// the same parse/cap warnings beside the caller's collected warning list.
func TestWarningsArePureAndRepeatable(t *testing.T) {
	cfg := NewDefaultConfig()
	cfg.LocalCache.Capacity = "huge"
	cfg.Cleanup.WakeInterval = "often"
	cfg.DynamicServers = []ServerConfig{
		{Type: "imap", Name: "imap", Addr: "127.0.0.1:143"},
		{Type: "lmtp", Name: "lmtp", Addr: "127.0.0.1:24", MaxMessageSize: "4gb"},
	}
	before, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	logs := captureWarnings(t)
	warnings := cfg.Warnings()
	if len(warnings) == 0 {
		t.Fatal("fixture produced no warnings")
	}
	if again := cfg.Warnings(); !slices.Equal(warnings, again) {
		t.Fatalf("non-repeatable warnings:\n%q\n%q", warnings, again)
	}
	after, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("warning collection modified the loaded configuration")
	}
	if logs.Len() != 0 {
		t.Fatalf("collection logged warnings outside its return value:\n%s", logs.String())
	}
}
