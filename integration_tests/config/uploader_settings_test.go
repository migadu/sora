//go:build integration

package config_test

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestSoraRefusesNonPositiveUploaderSettings starts the real sora binary as a storage
// node with an [uploader] setting that is zero or negative and expects it to refuse to
// start, naming the key, instead of running an upload worker that blocks for good
// (concurrency = 0, which also silences the instance heartbeat), panics (a negative
// concurrency), or leases nothing (batch_size or max_attempts <= 0) while LMTP keeps
// staging mail (#288).
func TestSoraRefusesNonPositiveUploaderSettings(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	bin := common.GetSoraBinary(t)

	dbName := os.Getenv("SORA_TEST_DB_NAME")
	if dbName == "" {
		dbName = "sora_test_db"
	}

	for _, tc := range []struct{ key, value string }{
		{"concurrency", "0"},
		{"concurrency", "-1"},
		{"batch_size", "0"},
		{"max_attempts", "-1"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			dir := t.TempDir()
			lmtpAddr := common.GetRandomAddress(t)
			// Defaults for the other keys; the setting under test overrides one of them.
			settings := map[string]string{"batch_size": "10", "concurrency": "20", "max_attempts": "20"}
			settings[tc.key] = tc.value
			// The S3 endpoint is never contacted: the node must stop before its first upload.
			cfg := fmt.Sprintf(`
[logging]
output = "stdout"
format = "console"
level = "info"

[database.write]
hosts = ["localhost"]
port = 5432
user = "postgres"
name = %q

[s3]
endpoint = "127.0.0.1:1"
disable_tls = true
access_key = "test-access-key"
secret_key = "test-secret-key"
bucket = "test-bucket"

[local_cache]
path = %q

[uploader]
path = %q
instance_id = "uploader-settings-test-%d"
batch_size = %s
concurrency = %s
max_attempts = %s

[[server]]
type = "lmtp"
name = "lmtp"
addr = %q
`, dbName, filepath.Join(dir, "cache"), filepath.Join(dir, "uploads"), time.Now().UnixNano(),
				settings["batch_size"], settings["concurrency"], settings["max_attempts"], lmtpAddr)
			cfgPath := filepath.Join(dir, "sora.toml")
			if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(bin, "-config", cfgPath)
			out := &bytes.Buffer{}
			cmd.Stdout, cmd.Stderr = out, out
			if err := cmd.Start(); err != nil {
				t.Fatalf("start sora: %v", err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			stop := func() {
				_ = cmd.Process.Signal(syscall.SIGTERM)
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					_ = cmd.Process.Kill()
					<-done
				}
			}

			deadline := time.Now().Add(60 * time.Second)
			for {
				select {
				case err := <-done:
					var exitErr *exec.ExitError
					if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
						t.Fatalf("sora exited with %v, want exit status 1 (invalid configuration)\n--- output ---\n%s", err, out.String())
					}
					want := fmt.Sprintf("[uploader] %s must be positive", tc.key)
					if !strings.Contains(out.String(), want) {
						t.Fatalf("sora output does not say %q\n--- output ---\n%s", want, out.String())
					}
					return
				default:
				}
				if conn, err := net.DialTimeout("tcp", lmtpAddr, 100*time.Millisecond); err == nil {
					conn.Close()
					stop()
					t.Fatalf("sora started (LMTP accepting) with [uploader] %s = %s\n--- output ---\n%s", tc.key, tc.value, out.String())
				}
				if time.Now().After(deadline) {
					stop()
					t.Fatalf("sora neither refused nor started within 60s\n--- output ---\n%s", out.String())
				}
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}
