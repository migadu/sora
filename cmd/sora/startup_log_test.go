package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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

	t.Run("logging configured", func(t *testing.T) {
		logPath := filepath.Join(t.TempDir(), "sora.log")
		// A reserved local metrics address stops start-up after logging is configured.
		// It needs no database or S3, and still exercises held startup warnings now
		// that invalid scheduler settings are refused by the configuration check.
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		metrics := fmt.Sprintf("\n[[server]]\ntype = \"metrics\"\nname = \"metrics\"\naddr = %q\n", listener.Addr().String())
		out, err := run(t, fmt.Sprintf("[logging]\noutput = %q\nlevel = \"warn\"\n\n", logPath)+misspelt+metrics)
		if err == nil {
			t.Fatalf("start-up went on; want it stopped by the occupied metrics address:\n%s", out)
		}
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("%v\nstderr:\n%s", err, out)
		}
		logged := string(data)
		if !strings.Contains(logged, "metrics server failed") {
			t.Fatalf("start-up did not stop at the metrics listener:\n%s\nstderr:\n%s", logged, out)
		}
		if !strings.Contains(logged, "level=WARN") || !strings.Contains(logged, "cleanup.grace_periood") {
			t.Errorf("the log file has no WARN record naming cleanup.grace_periood:\n%s\nstderr:\n%s", logged, out)
		}
		if strings.Contains(logged, "level=INFO") {
			t.Errorf("the log file has INFO records with level = \"warn\":\n%s", logged)
		}
	})

	// A file the configuration check refuses has a [logging] section, so the reason
	// start-up stops goes there with what it held (#1762). It went to stderr, as a plain
	// "[ERROR] ... invalid configuration - ..." line, so with output = syslog or a file the
	// log never said why sora did not start.
	t.Run("refused by the configuration check", func(t *testing.T) {
		logPath := filepath.Join(t.TempDir(), "sora.log")
		out, err := run(t, fmt.Sprintf("[logging]\noutput = %q\nformat = \"json\"\nlevel = \"warn\"\n\n", logPath)+
			misspelt+"\n[[server]]\ntype = \"pop3\"\nname = \"pop3\"\n")
		if err == nil {
			t.Fatalf("start-up went on; want it refused for the missing addr:\n%s", out)
		}
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("%v\nstderr:\n%s", err, out)
		}
		var warned, refused bool
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Errorf("the JSON log file has a line that is not JSON (%v): %q", err, line)
				continue
			}
			switch {
			case rec["level"] == "WARN" && strings.Contains(line, "cleanup.grace_periood"):
				warned = true
			case rec["level"] == "ERROR" && rec["msg"] == "Invalid configuration" &&
				strings.Contains(fmt.Sprint(rec["error"]), "server address is required"):
				refused = true
			case rec["level"] == "INFO":
				t.Errorf("the log file has an INFO record with level = \"warn\": %s", line)
			}
		}
		if !warned || !refused {
			t.Errorf("the log file does not have the held warning for cleanup.grace_periood (%v) and the refusal (%v):\n%s\nstderr:\n%s",
				warned, refused, data, out)
		}
		if strings.Contains(out, "server address is required") {
			t.Errorf("the refusal was also written to stderr:\n%s", out)
		}
	})

	// Without a [logging] section the output is stderr, which shows what start-up held
	// and then the refusal.
	t.Run("refused by the configuration check without [logging]", func(t *testing.T) {
		out, err := run(t, misspelt+"\n[[server]]\ntype = \"pop3\"\nname = \"pop3\"\n")
		if err == nil {
			t.Fatalf("start-up went on; want it refused for the missing addr:\n%s", out)
		}
		held := strings.Index(out, "cleanup.grace_periood")
		refusal := strings.Index(out, "server address is required")
		if held < 0 || refusal < 0 || held > refusal {
			t.Errorf("output does not show the held warning and then the refusal:\n%s", out)
		}
	})

	// A file that cannot be parsed has no [logging] to follow, even when it names one:
	// the failure, after what start-up held, goes to stderr.
	t.Run("refused before logging is configured", func(t *testing.T) {
		logPath := filepath.Join(t.TempDir(), "sora.log")
		out, err := run(t, fmt.Sprintf("[logging]\noutput = %q\n\n[cleanup\n", logPath))
		if err == nil {
			t.Fatalf("start-up went on; want it refused for the syntax error:\n%s", out)
		}
		for _, want := range []string{"SORA application starting", "ERROR: failed to parse configuration file"} {
			if !strings.Contains(out, want) {
				t.Errorf("output does not name %q:\n%s", want, out)
			}
		}
		if _, err := os.Stat(logPath); !os.IsNotExist(err) {
			t.Errorf("the log file named by a file that cannot be parsed was opened (%v)", err)
		}
	})
}
