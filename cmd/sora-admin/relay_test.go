//go:build unix

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server/relayqueue"
	"golang.org/x/sys/unix"
)

const (
	relayHelperConfigEnv = "SORA_ADMIN_RELAY_HELPER_CONFIG"
	relayHelperArgsEnv   = "SORA_ADMIN_RELAY_HELPER_ARGS"
)

// TestRelayCommandHelper is not a test: it is `sora-admin --config <file> relay <args>`,
// run by the relay tests in a process of its own because the commands exit on failure.
func TestRelayCommandHelper(t *testing.T) {
	path := os.Getenv(relayHelperConfigEnv)
	if path == "" {
		t.Skip("helper process for the relay command tests")
	}
	if err := loadAdminConfig(path, &globalConfig); err != nil {
		t.Fatal(err)
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv(relayHelperArgsEnv)), &args); err != nil {
		t.Fatal(err)
	}
	os.Args = append([]string{"sora-admin", "relay"}, args...)
	handleRelayCommand(context.Background())
}

// relayCommand returns `sora-admin relay args...` for a config whose [relay] section is
// smtp with its queue at queuePath and the extra [relay.queue] lines in queueTOML.
func relayCommand(t *testing.T, queuePath, queueTOML string, args ...string) *exec.Cmd {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	content := "[relay]\ntype = \"smtp\"\nsmtp_host = \"localhost:25\"\n\n[relay.queue]\npath = \"" + queuePath + "\"\n" + queueTOML
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRelayCommandHelper$")
	cmd.Env = append(os.Environ(), relayHelperConfigEnv+"="+path, relayHelperArgsEnv+"="+string(encoded))
	return cmd
}

// runRelay runs `sora-admin relay args...` and returns what it printed; it fails the
// test when the command fails.
func runRelay(t *testing.T, queuePath, queueTOML string, args ...string) string {
	t.Helper()
	out, err := relayCommand(t, queuePath, queueTOML, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("sora-admin relay %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// failedRelayMessage puts one message into the failed queue the way the server does,
// and returns its ID and body.
func failedRelayMessage(t *testing.T, queuePath string) (string, []byte) {
	t.Helper()
	q, err := relayqueue.NewDiskQueue(queuePath, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("From: alice@example.com\r\nTo: bob@example.org\r\nSubject: redirected\r\n\r\nHello.\r\n")
	if err := q.Enqueue("alice@example.com", "bob@example.org", "redirect", body); err != nil {
		t.Fatal(err)
	}
	msg, _, err := q.AcquireNext()
	if err != nil || msg == nil {
		t.Fatalf("AcquireNext = %v, %v", msg, err)
	}
	if err := q.MarkPermanentFailure(msg.ID, "550 5.1.1 no such user"); err != nil {
		t.Fatal(err)
	}
	return msg.ID, body
}

// #328 item 1: with no max_attempts or worker_interval configured, stats printed the raw
// zero values instead of the defaults the server runs with.
func TestRelayStatsPrintsEffectiveSettings(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		out := runRelay(t, t.TempDir(), "", "stats")
		for _, want := range []string{"Max Attempts:     10\n", "Worker Interval:  1m0s\n"} {
			if !strings.Contains(out, want) {
				t.Errorf("stats output does not contain %q:\n%s", want, out)
			}
		}
	})

	t.Run("configured", func(t *testing.T) {
		out := runRelay(t, t.TempDir(), "max_attempts = 3\nworker_interval = \"30s\"\n", "stats")
		for _, want := range []string{"Max Attempts:     3\n", "Worker Interval:  30s\n"} {
			if !strings.Contains(out, want) {
				t.Errorf("stats output does not contain %q:\n%s", want, out)
			}
		}
	})
}

// #328 item 2: list printed IDs cut to 8 characters, which show, delete and requeue
// (which take the exact ID) do not accept.
func TestRelayListPrintsIDsTheOtherCommandsAccept(t *testing.T) {
	queuePath := t.TempDir()
	id, _ := failedRelayMessage(t, queuePath)

	out := runRelay(t, queuePath, "", "list", "--queue", "failed")
	var listed string
	for _, line := range strings.Split(out, "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && len(fields[0]) >= 8 && strings.HasPrefix(id, fields[0]) {
			listed = fields[0]
		}
	}
	if listed == "" {
		t.Fatalf("list does not show message %s:\n%s", id, out)
	}

	cmd := relayCommand(t, queuePath, "", "show", "--queue", "failed", "--id", listed)
	if shown, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("show --id %s (the ID list printed) failed: %v\n%s\nlist printed:\n%s", listed, err, shown, out)
	} else if !strings.Contains(string(shown), "ID:           "+id+"\n") {
		t.Errorf("show --id %s does not show message %s:\n%s", listed, id, shown)
	}
}

// #328 item 3: requeue wrote the metadata into pending/ before it had even read the body
// from failed/, so a worker resyncing in between found metadata with no body beside it
// (the queue's own writers put the body first). The failed body is replaced by a FIFO
// here so the test can look at pending/ while requeue is still reading it.
func TestRelayRequeueWritesBodyBeforeMetadata(t *testing.T) {
	queuePath := t.TempDir()
	id, body := failedRelayMessage(t, queuePath)
	failedBody := filepath.Join(queuePath, "failed", id+".msg")
	pendingMeta := filepath.Join(queuePath, "pending", id+".json")
	pendingBody := filepath.Join(queuePath, "pending", id+".msg")

	if err := os.Remove(failedBody); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(failedBody, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := relayCommand(t, queuePath, "", "requeue", "--id", id, "--confirm")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	// Opening the FIFO for writing returns once requeue has opened it to read the body.
	opened := make(chan *os.File, 1)
	go func() {
		if w, err := os.OpenFile(failedBody, os.O_WRONLY, 0); err == nil {
			opened <- w
		}
	}()
	var w *os.File
	select {
	case w = <-opened:
	case err := <-done:
		t.Fatalf("requeue exited before reading the body: %v\n%s", err, out.String())
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("requeue never read the body\n%s", out.String())
	}

	if _, err := os.Stat(pendingMeta); err == nil {
		t.Errorf("the metadata is in pending/ while the body is still being read from failed/: a worker resyncing now finds no body")
	}

	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	w.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("requeue failed: %v\n%s", err, out.String())
		}
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("requeue did not finish\n%s", out.String())
	}

	// The message is pending with the whole body and a fresh attempt count, and gone
	// from failed/.
	if got, err := os.ReadFile(pendingBody); err != nil || string(got) != string(body) {
		t.Errorf("pending body = %q, %v; want %q", got, err, body)
	}
	data, err := os.ReadFile(pendingMeta)
	if err != nil {
		t.Fatal(err)
	}
	var msg relayqueue.QueuedMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.ID != id || msg.Attempts != 0 || len(msg.Errors) != 0 {
		t.Errorf("pending metadata = %+v; want ID %s with no attempts or errors", msg, id)
	}
	for _, name := range []string{id + ".json", id + ".msg"} {
		if _, err := os.Lstat(filepath.Join(queuePath, "failed", name)); !os.IsNotExist(err) {
			t.Errorf("failed/%s still exists after requeue (err %v)", name, err)
		}
	}
}
