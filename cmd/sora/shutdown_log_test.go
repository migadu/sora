package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// shutdownMainEnv names the config file a child test process runs main with, until the
// test stops it with SIGTERM.
const shutdownMainEnv = "SORA_TEST_SHUTDOWN_MAIN_CONFIG"

// A JSON log file stays one JSON record per line through a graceful stop, so a log
// collector can parse every line of it (#680). main wrote "SORA: Closing log file
// <path>" into it as a plain line, through logger.Stderr, on every stop.
func TestShutdownKeepsAJSONLogFileJSON(t *testing.T) {
	if path := os.Getenv(shutdownMainEnv); path != "" {
		os.Args = []string{"sora", "-config", path}
		main()
		os.Exit(0)
	}

	dir := t.TempDir()
	logPath := filepath.Join(dir, "sora.log")
	// An IMAP proxy whose remote lookup answers for every user needs neither the
	// database nor S3. No client connects, so the lookup URL is never asked.
	toml := fmt.Sprintf(`
[logging]
output = %q
format = "json"

[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = "127.0.0.1:0"
remote_addrs = ["192.0.2.10:143"]

[server.remote_lookup]
enabled = true
url = "http://127.0.0.1:1/lookup/$email"
lookup_local_users = false
`, logPath)
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestShutdownKeepsAJSONLogFileJSON$")
	cmd.Env = append(os.Environ(), shutdownMainEnv+"="+cfgPath)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	// main takes SIGTERM before it starts the services, which log the node's identity.
	for {
		data, _ := os.ReadFile(logPath)
		if strings.Contains(string(data), "Resolved instance ID") {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("sora stopped during start-up (%v):\n%s\nlog:\n%s", err, out.String(), data)
		case <-time.After(20 * time.Millisecond):
		}
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("sora did not stop cleanly on SIGTERM (%v):\n%s", err, out.String())
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	closing := false
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Errorf("the JSON log file has a line that is not JSON (%v): %q", err, line)
			continue
		}
		if rec["msg"] == "Closing log file" && rec["path"] == logPath {
			closing = true
		}
	}
	if !closing {
		t.Errorf("the JSON log file has no record of its closing:\n%s", data)
	}
}
