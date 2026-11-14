package config

import (
	"slices"
	"strings"
	"testing"
)

// validateServers runs the check that sora at startup and sora-admin config validate
// both run: Validate on every block GetAllServers returns.
func validateServers(cfg *Config) []error {
	var errs []error
	for _, s := range cfg.GetAllServers() {
		if err := s.Validate(); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

const completeIMAPBlock = `
[[server]]
type = "imap"
name = "imap"
addr = ":143"
`

// A [[server]] block without type, name or addr was dropped by GetAllServers before
// anything validated it, so Validate's "required" errors never fired and a forgotten
// addr made the listener disappear without a word.
func TestServerBlockMissingRequiredKeyFailsValidation(t *testing.T) {
	for _, tc := range []struct{ name, block, want string }{
		{"addr", "type = \"pop3\"\nname = \"pop3\"", "server address is required"},
		{"empty_addr", "type = \"pop3\"\nname = \"pop3\"\naddr = \"\"", "server address is required"},
		{"name", "type = \"pop3\"\naddr = \":110\"", "server name is required"},
		{"type", "name = \"pop3\"\naddr = \":110\"", "server type is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadPoolsConfig(t, completeIMAPBlock+"\n[[server]]\n"+tc.block+"\n")
			if err != nil {
				t.Fatal(err)
			}
			errs := validateServers(&cfg)
			if len(errs) != 1 || !strings.Contains(errs[0].Error(), tc.want) {
				t.Fatalf("validation errors = %v, want one with %q", errs, tc.want)
			}
		})
	}
}

// The error for a block without a name says which block it is.
func TestServerBlockMissingNameIsIdentified(t *testing.T) {
	cfg, err := loadPoolsConfig(t, completeIMAPBlock+`
[[server]]
type = "pop3"
addr = ":110"
`)
	if err != nil {
		t.Fatal(err)
	}
	errs := validateServers(&cfg)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), `"pop3"`) || !strings.Contains(errs[0].Error(), `":110"`) {
		t.Fatalf("validation errors = %v, want one naming type \"pop3\" and addr \":110\"", errs)
	}
}

// enabled = false keeps a block in the file without starting it: the block is neither
// started nor validated, however incomplete. Any other block is started.
func TestServerBlockEnabledFalseIsSkipped(t *testing.T) {
	cfg, err := loadPoolsConfig(t, completeIMAPBlock+`
[[server]]
enabled = true
type = "lmtp"
name = "lmtp"
addr = ":24"

[[server]]
enabled = false
type = "pop3"
name = "retired-pop3"
addr = ":110"

[[server]]
enabled = false
name = "half-written"
`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range cfg.GetAllServers() {
		names = append(names, s.Name)
	}
	if want := []string{"imap", "lmtp"}; !slices.Equal(names, want) {
		t.Fatalf("servers to start = %v, want %v", names, want)
	}
	if errs := validateServers(&cfg); len(errs) != 0 {
		t.Fatalf("validation errors = %v, want none", errs)
	}
}
