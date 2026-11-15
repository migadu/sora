package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const adminMainHelperEnv = "SORA_ADMIN_MAIN_HELPER_ARGS"

// TestAdminMainHelper is not a test: it is `sora-admin` itself, run by runAdminMain in a
// process of its own because commands exit. The arguments come separated by US (0x1f) in the
// environment.
func TestAdminMainHelper(t *testing.T) {
	args := os.Getenv(adminMainHelperEnv)
	if args == "" {
		t.Skip("helper process for runAdminMain")
	}
	os.Args = append([]string{"sora-admin"}, strings.Split(args, "\x1f")...)
	main()
}

// runAdminMain runs sora-admin with args and returns its output and exit code.
func runAdminMain(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestAdminMainHelper$")
	cmd.Env = append(os.Environ(), adminMainHelperEnv+"="+strings.Join(args, "\x1f"))
	out, err := cmd.CombinedOutput()
	if exitErr, ok := err.(*exec.ExitError); ok {
		return string(out), exitErr.ExitCode()
	}
	if err != nil {
		t.Fatalf("running sora-admin %v: %v", args, err)
	}
	return string(out), 0
}

// adminAPIStub is an Admin API that counts the requests it is sent and answers each
// with body. It returns a config file whose [admin_cli] points at it.
func adminAPIStub(t *testing.T, body string) (configPath string, requests *atomic.Int64) {
	t.Helper()
	requests = new(atomic.Int64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	configPath = filepath.Join(t.TempDir(), "config.toml")
	content := fmt.Sprintf("[admin_cli]\naddr = %q\napi_key = \"test-key\"\n", srv.URL)
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath, requests
}

// TestCommandHelpSendsNoRequest (#316 item 4): --help prints the usage on stdout and
// exits 0, and never sends the request the command would send.
func TestCommandHelpSendsNoRequest(t *testing.T) {
	for _, args := range [][]string{
		{"config", "--help"},
		{"config", "-h"},
		{"auth-cache", "status", "--help"},
		{"auth-cache", "status", "-h"},
		{"affinity-cache", "status", "--help"},
		{"affinity-cache", "status", "-h"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			configPath, requests := adminAPIStub(t, `{"enabled":true,"stats":{"enabled":true}}`)
			out, code := runAdminMain(t, append([]string{"--config", configPath}, args...)...)
			if code != 0 {
				t.Errorf("exit code %d, want 0:\n%s", code, out)
			}
			if !strings.Contains(out, "Usage:") {
				t.Errorf("no usage printed:\n%s", out)
			}
			if n := requests.Load(); n != 0 {
				t.Errorf("--help sent %d request(s) to the Admin API", n)
			}
		})
	}
}

// TestConfigValidateHelp: `config validate --help` prints its usage and exits 0, as
// `config --help` promises ("config <subcommand> --help"), wherever --config is. It
// validated the file instead, and without --config printed "Error: --config is
// required" and exited 1.
func TestConfigValidateHelp(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(configPath, []byte("[database]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no config", []string{"config", "validate", "--help"}},
		{"no config -h", []string{"config", "validate", "-h"}},
		{"config before", []string{"--config", configPath, "config", "validate", "--help"}},
		{"config after", []string{"config", "validate", "--config", configPath, "-h"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, code := runAdminMain(t, tc.args...)
			if code != 0 {
				t.Errorf("exit code %d, want 0:\n%s", code, out)
			}
			if !strings.Contains(out, "Usage:") {
				t.Errorf("no usage printed:\n%s", out)
			}
			if strings.Contains(out, "Validating configuration file") || strings.Contains(out, "Error:") {
				t.Errorf("--help did not stop at the usage:\n%s", out)
			}
		})
	}
}

// TestAffinityCacheStatusPartialMemoryUsage (#316 item 5): a memory_usage block without
// broadcast_queue_max or queue_utilization (another server version) is printed as far as
// it goes instead of panicking.
func TestAffinityCacheStatusPartialMemoryUsage(t *testing.T) {
	configPath, requests := adminAPIStub(t,
		`{"stats":{"enabled":true,"total_entries":2,"memory_usage":{"broadcast_queue":3}}}`)
	out, code := runAdminMain(t, "--config", configPath, "affinity-cache", "status")
	if code != 0 {
		t.Fatalf("exit code %d, want 0:\n%s", code, out)
	}
	if requests.Load() != 1 {
		t.Errorf("sent %d request(s), want 1", requests.Load())
	}
	for _, want := range []string{"Cached entries:      2", "Broadcast queue:   3"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}
