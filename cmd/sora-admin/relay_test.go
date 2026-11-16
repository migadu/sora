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

// relayQueue creates an empty relay queue the way the server does and returns its path.
func relayQueue(t *testing.T) string {
	t.Helper()
	queuePath := t.TempDir()
	if _, err := relayqueue.NewDiskQueue(queuePath, 0, nil); err != nil {
		t.Fatal(err)
	}
	return queuePath
}

// #328 item 1: with no max_attempts or worker_interval configured, stats printed the raw
// zero values instead of the defaults the server runs with.
func TestRelayStatsPrintsEffectiveSettings(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		out := runRelay(t, relayQueue(t), "", "stats")
		for _, want := range []string{"Max Attempts:     10\n", "Worker Interval:  1m0s\n"} {
			if !strings.Contains(out, want) {
				t.Errorf("stats output does not contain %q:\n%s", want, out)
			}
		}
	})

	t.Run("configured", func(t *testing.T) {
		out := runRelay(t, relayQueue(t), "max_attempts = 3\nworker_interval = \"30s\"\n", "stats")
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

// requeue on a node whose relay queue the server never created must not create it:
// made by `sudo sora-admin`, pending/ and failed/ would belong to root, and the server,
// running as its own user, could not queue into them.
func TestRelayRequeueDoesNotCreateTheQueue(t *testing.T) {
	queuePath := filepath.Join(t.TempDir(), "relay")
	for _, id := range []string{"all", "3f2b9c1e-8d4a-4f6b-9a7e-2c5d1e0f4b8a"} {
		out, err := relayCommand(t, queuePath, "", "requeue", "--id", id, "--confirm").CombinedOutput()
		if err == nil {
			t.Errorf("requeue --id %s on a queue that does not exist succeeded:\n%s", id, out)
		}
		if _, err := os.Stat(queuePath); !os.IsNotExist(err) {
			t.Fatalf("requeue --id %s created the relay queue at %s (stat: %v)\n%s", id, queuePath, err, out)
		}
	}
}

// Opening an incomplete existing queue must not create a root-owned processing directory.
func TestRelayRequeueDoesNotRepairAnIncompleteQueue(t *testing.T) {
	queuePath := t.TempDir()
	for _, dir := range []string{"failed", "pending"} {
		if err := os.Mkdir(filepath.Join(queuePath, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	out, err := relayCommand(t, queuePath, "", "requeue", "--id", "all", "--confirm").CombinedOutput()
	if err == nil {
		t.Errorf("requeue on an incomplete queue succeeded:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(queuePath, "processing")); !os.IsNotExist(err) {
		t.Fatalf("requeue created processing/ (stat: %v)\n%s", err, out)
	}
}

// stats only reads the queue, so on a node whose server has never created it, it must
// not create it either (#643): made by `sudo sora-admin`, pending/ would belong to root,
// and the server, running as its own user, could not queue into it. Like list, it says
// the queue does not exist.
func TestRelayStatsDoesNotCreateTheQueue(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		queuePath := filepath.Join(t.TempDir(), "relay")
		out := runRelay(t, queuePath, "", "stats")
		if _, err := os.Stat(queuePath); !os.IsNotExist(err) {
			t.Fatalf("stats created the relay queue at %s (stat: %v)\n%s", queuePath, err, out)
		}
		if !strings.Contains(out, "does not exist") {
			t.Errorf("stats does not say the queue does not exist:\n%s", out)
		}
	})

	t.Run("incomplete", func(t *testing.T) {
		queuePath := t.TempDir()
		for _, dir := range []string{"failed", "pending"} {
			if err := os.Mkdir(filepath.Join(queuePath, dir), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		out := runRelay(t, queuePath, "", "stats")
		if _, err := os.Stat(filepath.Join(queuePath, "processing")); !os.IsNotExist(err) {
			t.Fatalf("stats created processing/ (stat: %v)\n%s", err, out)
		}
		if !strings.Contains(out, "does not exist") {
			t.Errorf("stats does not say the queue does not exist:\n%s", out)
		}
	})
}

// relay delete --queue pending --id all must delete only committed messages (paired with
// <id>.json) and leave in-flight uncommitted holds (<id>.held + <id>.msg) intact so an
// active delivery can still commit and relay its redirect body.
func TestRelayDeleteAllLeavesHeldMessagesIntact(t *testing.T) {
	queuePath := t.TempDir()
	q, err := relayqueue.NewDiskQueue(queuePath, 10, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := q.Enqueue("committed@example.com", "drop@example.org", "redirect", []byte("committed body")); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	wantBody := []byte("From: alice@example.com\r\nTo: keep@example.org\r\n\r\nHeld redirect body.\r\n")
	commit, abort, err := q.Hold("alice@example.com", "keep@example.org", "redirect", wantBody)
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	defer abort()

	out := runRelay(t, queuePath, "", "delete", "--queue", "pending", "--id", "all", "--confirm")
	if !strings.Contains(out, "Deleted 1 messages from pending queue\n") {
		t.Errorf("unexpected delete output:\n%s", out)
	}

	entries, err := os.ReadDir(filepath.Join(queuePath, "pending"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 2 {
		t.Fatalf("pending holds %v after delete --id all; want the held redirect's .held and .msg (2 files)", names)
	}

	if err := commit(); err != nil {
		t.Fatalf("commit held redirect after delete --id all: %v", err)
	}
	msg, gotBody, err := q.AcquireNext()
	if err != nil || msg == nil {
		t.Fatalf("AcquireNext after committing held redirect = %v, %v; want the held message", msg, err)
	}
	if msg.To != "keep@example.org" || string(gotBody) != string(wantBody) {
		t.Errorf("acquired To=%q body=%q; want To=%q body=%q", msg.To, gotBody, "keep@example.org", wantBody)
	}
}

func TestDeleteAllMessagesInQueueDir(t *testing.T) {
	queuePath := t.TempDir()
	q, err := relayqueue.NewDiskQueue(queuePath, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	pendingDir := filepath.Join(queuePath, "pending")

	if err := q.Enqueue("a@example.com", "b@example.org", "redirect", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue("c@example.com", "d@example.org", "redirect", []byte("two")); err != nil {
		t.Fatal(err)
	}
	_, abort, err := q.Hold("h@example.com", "k@example.org", "redirect", []byte("held"))
	if err != nil {
		t.Fatal(err)
	}
	defer abort()
	scratch := filepath.Join(pendingDir, ".tmp-scratch")
	if err := os.WriteFile(scratch, []byte("scratch"), 0o600); err != nil {
		t.Fatal(err)
	}
	stagingMsg := filepath.Join(pendingDir, "unpaired-staging.msg")
	if err := os.WriteFile(stagingMsg, []byte("staging"), 0o600); err != nil {
		t.Fatal(err)
	}

	deleted, err := deleteAllMessagesInQueueDir(pendingDir)
	if err != nil {
		t.Fatalf("deleteAllMessagesInQueueDir: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted = %d, want 2", deleted)
	}
	for _, keep := range []string{scratch, stagingMsg} {
		if _, err := os.Stat(keep); err != nil {
			t.Errorf("expected %s to remain untouched: %v", filepath.Base(keep), err)
		}
	}
	abort()
	entries, err := os.ReadDir(pendingDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected only scratch and unpaired .msg to remain after abort, got %d entries", len(entries))
	}
}

// The CLI is another process; a worker's live lease must protect both files.
func TestRelayDeleteAllSkipsLiveProcessing(t *testing.T) {
	dir := t.TempDir()
	q, err := relayqueue.NewDiskQueue(dir, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue("from@example.com", "to@example.com", "redirect", []byte("body")); err != nil {
		t.Fatal(err)
	}
	msg, _, err := q.AcquireNext()
	if err != nil || msg == nil {
		t.Fatalf("claim: %v %v", msg, err)
	}
	out := runRelay(t, dir, "", "delete", "--queue", "processing", "--id", "all", "--confirm")
	if !strings.Contains(out, "Deleted 0 messages") || !strings.Contains(out, "busy") {
		t.Fatalf("busy deletion result: %s", out)
	}
	for _, ext := range []string{".json", ".msg"} {
		if _, err := os.Stat(filepath.Join(dir, "processing", msg.ID+ext)); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.MarkSuccess(msg.ID); err != nil {
		t.Fatal(err)
	}
}
func TestRelayDeleteRequeuedMessageCannotResurrect(t *testing.T) {
	dir := t.TempDir()
	q, err := relayqueue.NewDiskQueue(dir, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue("from@example.com", "to@example.com", "redirect", []byte("body")); err != nil {
		t.Fatal(err)
	}
	msg, _, err := q.AcquireNext()
	if err != nil || msg == nil {
		t.Fatalf("claim: %v %v", msg, err)
	}
	if err := q.MarkPermanentFailure(msg.ID, "550 failed"); err != nil {
		t.Fatal(err)
	}
	if err := q.Requeue(msg.ID); err != nil {
		t.Fatal(err)
	}
	out := runRelay(t, dir, "", "delete", "--queue", "pending", "--id", msg.ID, "--confirm")
	if !strings.Contains(out, "Deleted message "+msg.ID) {
		t.Fatalf("delete result: %s", out)
	}
	if _, err := q.RecoverOrphanedMessages(); err != nil {
		t.Fatal(err)
	}
	pending, processing, failed, err := q.GetStats()
	if err != nil || pending+processing+failed != 0 {
		t.Fatalf("discard resurrected: %d/%d/%d %v", pending, processing, failed, err)
	}
}
