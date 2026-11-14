package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestStartupRefusesIncompleteServerBlock runs the server's start-up check on the
// configuration from #278: a [[server]] block without type, name or addr stops the
// server (it used to be skipped without a word, so its listener never started), and
// only enabled = false keeps a block in the file without starting it.
func TestStartupRefusesIncompleteServerBlock(t *testing.T) {
	tests := []struct {
		name    string
		block   string
		wantErr string // substring of the refusal, "" when start-up goes on
	}{
		{name: "addr forgotten", block: "type = \"pop3\"\nname = \"pop3\"\n", wantErr: "server address is required"},
		{name: "addr misspelled", block: "type = \"pop3\"\nname = \"pop3\"\nadr = \"127.0.0.1:1110\"\n", wantErr: "server address is required"},
		{name: "name forgotten", block: "type = \"pop3\"\naddr = \"127.0.0.1:1110\"\n", wantErr: "server name is required"},
		{name: "type forgotten", block: "name = \"pop3\"\naddr = \"127.0.0.1:1110\"\n", wantErr: "server type is required"},
		{name: "enabled = false", block: "enabled = false\ntype = \"pop3\"\nname = \"pop3\"\naddr = \"\"\n", wantErr: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			content := "[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:1143\"\n\n[[server]]\n" + tt.block
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestLoadAndValidateConfigHelper$")
			cmd.Env = append(os.Environ(), loadConfigHelperEnv+"="+path)
			out, err := cmd.CombinedOutput()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("start-up refused a valid configuration: %v\n%s", err, out)
				}
				return
			}
			if err == nil {
				t.Fatalf("start-up went on; want it refused with %q", tt.wantErr)
			}
			if !strings.Contains(string(out), tt.wantErr) {
				t.Errorf("start-up refused, but the output does not say %q:\n%s", tt.wantErr, out)
			}
		})
	}
}
