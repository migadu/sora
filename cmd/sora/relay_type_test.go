package main

import (
	"encoding/json"
	"fmt"
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
// configuration check, run by checkStartupConfig and
// TestStartupRefusesIncompleteServerBlock in a process of its own because a refused
// configuration exits.
func TestLoadAndValidateConfigHelper(t *testing.T) {
	path := os.Getenv(loadConfigHelperEnv)
	if path == "" {
		t.Skip("helper process for the start-up configuration tests")
	}
	cfg := config.NewDefaultConfig()
	loadAndValidateConfig(path, &cfg, errors.NewErrorHandler())
}

// checkStartupConfig runs the start-up configuration check on content in a process of
// its own, with a [logging] section that writes JSON to a file. It reports whether
// start-up refused the file, and returns the problems the refusal logged to that file,
// one "<section>: <reason>" per line: the reason start-up stops goes where [logging]
// says, not to stderr (#1762). out is what the process wrote to stdout and stderr.
func checkStartupConfig(t *testing.T, content string) (refused bool, problems string, out []byte) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "sora.log")
	path := filepath.Join(dir, "config.toml")
	content = fmt.Sprintf("[logging]\noutput = %q\nformat = \"json\"\n\n", logPath) + content
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLoadAndValidateConfigHelper$")
	cmd.Env = append(os.Environ(), loadConfigHelperEnv+"="+path)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return false, "", out
	}
	if _, exited := err.(*exec.ExitError); !exited {
		t.Fatalf("start-up check did not run: %v\n%s", err, out)
	}
	data, err := os.ReadFile(logPath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Errorf("the JSON log file has a line that is not JSON (%v): %q", err, line)
			continue
		}
		if rec["level"] == "ERROR" && rec["msg"] == "Invalid configuration" {
			fmt.Fprintf(&b, "%v: %v\n", rec["field"], rec["error"])
		}
	}
	return true, b.String(), out
}

// TestStartupRefusesUnsupportedRelayType: a [relay] type other than "smtp" or "http"
// stops the server at start-up (#277). It used to be logged as FATAL while start-up went
// on with a relay queue and no worker, so every Sieve redirect and vacation reply was
// accepted into pending/ and never sent. So does an "smtp" relay without a host:port
// smtp_host or an "http" relay without an http_url, which queued every message for
// attempts that could only fail (#532).
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
		{name: "smtp without smtp_host", relay: "[relay]\ntype = \"smtp\"\n", wantErr: `[relay] type "smtp" requires smtp_host as host:port`},
		{name: "smtp_host without port", relay: "[relay]\ntype = \"smtp\"\nsmtp_host = \"smtp.example.com\"\n", wantErr: `[relay] smtp_host "smtp.example.com" must be host:port`},
		{name: "http without http_url", relay: "[relay]\ntype = \"http\"\n", wantErr: `[relay] type "http" requires http_url`},
		// #643: a worker_interval of zero or less reached time.NewTicker in the relay
		// worker's goroutine and panicked; a negative failed_retention made every failed
		// message overdue for deletion. failed_retention = "0" keeps failed messages.
		{name: "worker_interval 0", relay: "[relay]\ntype = \"smtp\"\nsmtp_host = \"smtp.example.com:587\"\n[relay.queue]\nworker_interval = \"0\"\n", wantErr: `[relay.queue]: worker_interval must be positive, got "0"`},
		{name: "worker_interval negative", relay: "[relay]\ntype = \"smtp\"\nsmtp_host = \"smtp.example.com:587\"\n[relay.queue]\nworker_interval = \"-1m\"\n", wantErr: `[relay.queue]: worker_interval must be positive, got "-1m"`},
		{name: "failed_retention negative", relay: "[relay]\ntype = \"smtp\"\nsmtp_host = \"smtp.example.com:587\"\n[relay.queue]\nfailed_retention = \"-1h\"\n", wantErr: `[relay.queue]: failed_retention must not be negative, got "-1h"`},
		{name: "failed_retention 0", relay: "[relay]\ntype = \"smtp\"\nsmtp_host = \"smtp.example.com:587\"\n[relay.queue]\nfailed_retention = \"0\"\n", wantErr: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := storageTOML + tt.relay + "\n[[server]]\ntype = \"lmtp\"\nname = \"lmtp\"\naddr = \"127.0.0.1:0\"\n"
			refused, problems, out := checkStartupConfig(t, content)
			if tt.wantErr == "" {
				if refused {
					t.Fatalf("start-up refused a valid configuration:\n%s%s", problems, out)
				}
				return
			}
			if !refused {
				t.Fatalf("start-up went on; want it refused with %q", tt.wantErr)
			}
			if !strings.Contains(problems, tt.wantErr) {
				t.Errorf("start-up refused, but the log does not say %q:\nlog:\n%s\noutput:\n%s", tt.wantErr, problems, out)
			}
		})
	}
}
