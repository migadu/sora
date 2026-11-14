package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/errors"
)

const loadConfigHelperEnv = "SORA_LOAD_CONFIG_HELPER_PATH"

// TestLoadAndValidateConfigHelper is not a test: it is the server's start-up
// configuration check, run by TestStartupRefusesUnsupportedRelayType in a process of
// its own because a refused configuration exits.
func TestLoadAndValidateConfigHelper(t *testing.T) {
	path := os.Getenv(loadConfigHelperEnv)
	if path == "" {
		t.Skip("helper process for TestStartupRefusesUnsupportedRelayType")
	}
	cfg := config.NewDefaultConfig()
	loadAndValidateConfig(path, &cfg, errors.NewErrorHandler())
}

// TestStartupRefusesUnsupportedRelayType: a [relay] type other than "smtp" or "http"
// stops the server at start-up (#277). It used to be logged as FATAL while start-up went
// on with a relay queue and no worker, so every Sieve redirect and vacation reply was
// accepted into pending/ and never sent.
func TestStartupRefusesUnsupportedRelayType(t *testing.T) {
	tests := []struct {
		name    string
		relay   string
		wantErr string // substring of the refusal, "" when start-up goes on
	}{
		{name: "no relay", relay: "", wantErr: ""},
		{name: "smtp", relay: "[relay]\ntype = \"smtp\"\nsmtp_host = \"smtp.example.com:587\"\n", wantErr: ""},
		{name: "http", relay: "[relay]\ntype = \"http\"\nhttp_url = \"https://api.example.com/deliver\"\n", wantErr: ""},
		{name: "upper-case SMTP", relay: "[relay]\ntype = \"SMTP\"\nsmtp_host = \"smtp.example.com:587\"\n", wantErr: `unsupported [relay] type "SMTP"`},
		{name: "lmtp", relay: "[relay]\ntype = \"lmtp\"\nsmtp_host = \"smtp.example.com:24\"\n", wantErr: `unsupported [relay] type "lmtp"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			content := tt.relay + "\n[[server]]\ntype = \"lmtp\"\nname = \"lmtp\"\naddr = \"127.0.0.1:0\"\n"
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
