package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const configValidateHelperEnv = "SORA_ADMIN_CONFIG_VALIDATE_HELPER_PATH"

// TestConfigValidateCommandHelper is not a test: it is `sora-admin config validate`,
// run by the TestConfigValidateRejects* tests in a process of its own because the
// command exits.
func TestConfigValidateCommandHelper(t *testing.T) {
	path := os.Getenv(configValidateHelperEnv)
	if path == "" {
		t.Skip("helper process for the TestConfigValidateRejects* tests")
	}
	os.Args = []string{"sora-admin", "--config", path, "config", "validate"}
	handleConfigValidate(context.Background())
}

// TestConfigValidateRejectsUnsupportedRelayType: `sora-admin config validate` fails a
// [relay] type the server refuses to start with (#277).
func TestConfigValidateRejectsUnsupportedRelayType(t *testing.T) {
	tests := []struct {
		name    string
		relay   string
		wantErr string // substring of the failure, "" for a valid file
	}{
		{name: "smtp", relay: "[relay]\ntype = \"smtp\"\nsmtp_host = \"smtp.example.com:587\"\n", wantErr: ""},
		{name: "upper-case SMTP", relay: "[relay]\ntype = \"SMTP\"\nsmtp_host = \"smtp.example.com:587\"\n", wantErr: `unsupported [relay] type "SMTP"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			content := tt.relay + "\n[[server]]\ntype = \"lmtp\"\nname = \"lmtp\"\naddr = \"127.0.0.1:0\"\n"
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestConfigValidateCommandHelper$")
			cmd.Env = append(os.Environ(), configValidateHelperEnv+"="+path)
			out, err := cmd.CombinedOutput()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("config validate failed a valid file: %v\n%s", err, out)
				}
				return
			}
			if err == nil {
				t.Fatalf("config validate passed the file; want it failed with %q", tt.wantErr)
			}
			if !strings.Contains(string(out), tt.wantErr) {
				t.Errorf("config validate failed, but the output does not say %q:\n%s", tt.wantErr, out)
			}
		})
	}
}

// TestConfigValidateRejectsInvalidSharedNamespacePrefix: `sora-admin config validate`
// fails a [shared_mailboxes] namespace_prefix the server refuses to start with (#338).
func TestConfigValidateRejectsInvalidSharedNamespacePrefix(t *testing.T) {
	tests := []struct {
		name    string
		section string
		wantErr string // substring of the failure, "" for a valid file
	}{
		{name: "Shared/", section: "enabled = true\nnamespace_prefix = \"Shared/\"\n"},
		{name: "disabled with an empty prefix", section: "enabled = false\nnamespace_prefix = \"\"\n"},
		{name: "no trailing delimiter", section: "enabled = true\nnamespace_prefix = \"Shared\"\n",
			wantErr: `namespace_prefix "Shared"`},
		{name: "INBOX as the root", section: "enabled = true\nnamespace_prefix = \"INBOX/\"\n",
			wantErr: `namespace_prefix "INBOX/"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			content := "[shared_mailboxes]\n" + tt.section +
				"\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:0\"\n"
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestConfigValidateCommandHelper$")
			cmd.Env = append(os.Environ(), configValidateHelperEnv+"="+path)
			out, err := cmd.CombinedOutput()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("config validate failed a valid file: %v\n%s", err, out)
				}
				return
			}
			if err == nil {
				t.Fatalf("config validate passed the file; want it failed with %q", tt.wantErr)
			}
			if !strings.Contains(string(out), tt.wantErr) {
				t.Errorf("config validate failed, but the output does not say %q:\n%s", tt.wantErr, out)
			}
		})
	}
}
