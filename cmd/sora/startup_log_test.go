package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startupMainEnv names the config file a child test process runs main with.
const startupMainEnv = "SORA_TEST_STARTUP_MAIN_CONFIG"

// What start-up logs before the [logging] section is applied, the warnings about the
// configuration file among it, is written where that section says and at its level
// (#398). It went to stderr whatever the file said, so with output = syslog or a file
// a misspelt key was never in the log.
func TestStartupConfigWarningsReachTheConfiguredLog(t *testing.T) {
	if path := os.Getenv(startupMainEnv); path != "" {
		os.Args = []string{"sora", "-config", path}
		main()
		os.Exit(0)
	}

	run := func(t *testing.T, toml string) (string, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(path, []byte(toml), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStartupConfigWarningsReachTheConfiguredLog$")
		cmd.Env = append(os.Environ(), startupMainEnv+"="+path)
		out, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatalf("start-up did not stop:\n%s", out)
		}
		return string(out), err
	}

	const misspelt = "[cleanup]\ngrace_periood = \"7d\"\n"
	const metricsServer = "\n[[server]]\ntype = \"metrics\"\nname = \"metrics\"\naddr = \"127.0.0.1:0\"\n"

	t.Run("logging configured", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "sora.log")
		// A [tls] certificate that cannot be read stops start-up once logging is
		// configured: the whole-file checks do not read it, service setup does. A node
		// that runs only a metrics server needs no database or S3, so nothing is
		// connected to and no listener is opened before that.
		missing := filepath.Join(dir, "missing.pem")
		tlsTOML := fmt.Sprintf("[tls]\nenabled = true\nprovider = \"file\"\ncert_file = %q\nkey_file = %q\n\n", missing, missing)
		out, err := run(t, fmt.Sprintf("[logging]\noutput = %q\nlevel = \"warn\"\n\n", logPath)+tlsTOML+misspelt+metricsServer)
		if err == nil {
			t.Fatalf("start-up went on; want it stopped by the unreadable certificate:\n%s", out)
		}
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("%v\nstderr:\n%s", err, out)
		}
		logged := string(data)
		if !strings.Contains(logged, `operation="initialize TLS manager"`) {
			t.Fatalf("start-up did not stop at the TLS manager:\n%s\nstderr:\n%s", logged, out)
		}
		if !strings.Contains(logged, "level=WARN") || !strings.Contains(logged, "cleanup.grace_periood") {
			t.Errorf("the log file has no WARN record naming cleanup.grace_periood:\n%s\nstderr:\n%s", logged, out)
		}
		if strings.Contains(logged, "level=INFO") {
			t.Errorf("the log file has INFO records with level = \"warn\":\n%s", logged)
		}
	})

	// A start-up refused before logging is configured still shows what it held.
	t.Run("refused before logging is configured", func(t *testing.T) {
		out, err := run(t, misspelt+"\n[[server]]\ntype = \"pop3\"\nname = \"pop3\"\n")
		if err == nil {
			t.Fatalf("start-up went on; want it refused for the missing addr:\n%s", out)
		}
		for _, want := range []string{"cleanup.grace_periood", "server address is required"} {
			if !strings.Contains(out, want) {
				t.Errorf("output does not name %q:\n%s", want, out)
			}
		}
	})
}
