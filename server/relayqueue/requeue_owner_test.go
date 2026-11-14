//go:build unix

package relayqueue

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// sora-admin relay requeue is often run as root while the server reads pending/ as its
// own user. The copies Requeue writes are new 0600 files, so unless they are given to
// the queue's owner the server cannot open them and the message never leaves pending/.
// Only root can give a file away, so this replaces geteuid to make the queue belong to
// another user and records the hand-over instead of making it.
func TestRequeueGivesTheCopiesToTheQueueOwner(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := failMessage(t, queue, "recipient@example.com", "550 5.1.1 no such user")

	info, err := os.Stat(queue.pendingDir)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)

	type handOver struct {
		name, published string
		uid, gid        int
	}
	var handOvers []handOver
	realGeteuid, realChown := geteuid, chownFile
	t.Cleanup(func() { geteuid, chownFile = realGeteuid, realChown })
	geteuid = func() int { return int(st.Uid) + 1 }
	chownFile = func(f *os.File, uid, gid int) error {
		var published []string
		for _, name := range []string{id + ".msg", id + ".json"} {
			if fileExists(filepath.Join(queue.pendingDir, name)) {
				published = append(published, name)
			}
		}
		handOvers = append(handOvers, handOver{filepath.Base(f.Name()), strings.Join(published, ","), uid, gid})
		return nil
	}

	if err := queue.Requeue(id); err != nil {
		t.Fatalf("Requeue: %v", err)
	}

	// The body, then the metadata, each given away while still a temp file: the server
	// must never see a name it cannot open, nor metadata without its body.
	want := []string{"", id + ".msg"}
	if len(handOvers) != len(want) {
		t.Fatalf("Requeue gave %d files to the queue owner, want %d (body and metadata): %+v", len(handOvers), len(want), handOvers)
	}
	for i, h := range handOvers {
		if h.uid != int(st.Uid) || h.gid != int(st.Gid) {
			t.Errorf("file %d given to %d:%d, want the pending directory's owner %d:%d", i, h.uid, h.gid, st.Uid, st.Gid)
		}
		if !strings.HasPrefix(h.name, tempFilePrefix) {
			t.Errorf("file %d given away as %s, after it was published", i, h.name)
		}
		if h.published != want[i] {
			t.Errorf("when file %d was given away, pending/ held %q, want %q", i, h.published, want[i])
		}
	}
	for _, name := range []string{id + ".msg", id + ".json"} {
		if !fileExists(filepath.Join(queue.pendingDir, name)) {
			t.Errorf("pending/%s missing after Requeue", name)
		}
	}
}

// A process that owns the queue - the server's user, or a test - keeps its files.
func TestRequeueKeepsTheOwnerWhenItOwnsTheQueue(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := failMessage(t, queue, "recipient@example.com", "550 5.1.1 no such user")

	realChown := chownFile
	t.Cleanup(func() { chownFile = realChown })
	chownFile = func(f *os.File, uid, gid int) error {
		t.Errorf("Requeue gave %s to %d:%d although this process owns the queue", f.Name(), uid, gid)
		return nil
	}

	if err := queue.Requeue(id); err != nil {
		t.Fatalf("Requeue: %v", err)
	}
}

// The real hand-over, where it can be made.
func TestRequeueAsRootGivesTheCopiesToTheQueueOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("only root can give a file to another user")
	}
	const nobody = 65534
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := failMessage(t, queue, "recipient@example.com", "550 5.1.1 no such user")
	if err := os.Chown(queue.pendingDir, nobody, nobody); err != nil {
		t.Fatal(err)
	}

	if err := queue.Requeue(id); err != nil {
		t.Fatalf("Requeue: %v", err)
	}
	for _, name := range []string{id + ".msg", id + ".json"} {
		info, err := os.Stat(filepath.Join(queue.pendingDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if st := info.Sys().(*syscall.Stat_t); st.Uid != nobody || st.Gid != nobody {
			t.Errorf("pending/%s belongs to %d:%d, want the queue owner %d:%d", name, st.Uid, st.Gid, nobody, nobody)
		}
	}
}
