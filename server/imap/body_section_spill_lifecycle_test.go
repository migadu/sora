package imap

import (
	"bytes"
	"math"
	"os"
	"testing"

	"github.com/migadu/go-imap"
)

func TestSpilledBodySectionLifecycle(t *testing.T) {
	data := bytes.Repeat([]byte("s"), maxCachedBodySectionBytes+1)
	s, tracker := newFetchTestSession(1024)
	t.Cleanup(s.releaseBodySectionCache)
	if !s.spillBodySection("first", data) {
		t.Fatal("section did not spill")
	}
	f := s.bodySectionCacheFile
	if _, err := os.Stat(f.Name()); !os.IsNotExist(err) {
		t.Fatalf("spill remains accessible by name: %v", err)
	}
	buf := make([]byte, 17)
	if !s.readSpilledSectionInto("first", 19, buf) || !bytes.Equal(buf, data[19:36]) {
		t.Fatal("unlinked spill cannot answer positional read")
	}
	if !s.memoryAvailable(1024) || s.bodySectionCacheFile != f || tracker.Current() != 0 {
		t.Fatal("heap pressure incorrectly evicted or charged the disk spill")
	}
	// Selection clearing uses the same release path as CLOSE/UNSELECT and session
	// shutdown. It must close the descriptor and release the node reservation.
	s.clearSelectedMailboxStateLocked()
	if _, err := f.Stat(); err == nil {
		t.Fatal("selection clear left the spill descriptor open")
	}
	if s.server.spilledBodySectionBytes.Load() != 0 || s.bodySectionCacheFile != nil {
		t.Fatal("selection clear left a spill reservation")
	}
	if !s.spillBodySection("second", data) {
		t.Fatal("second spill refused after release")
	}
	f = s.bodySectionCacheFile
	if err := tracker.Allocate(3); err != nil {
		t.Fatal(err)
	}
	if !s.retainBodySection("small", []byte("new")) {
		t.Fatal("small section did not replace the spill")
	}
	if _, err := f.Stat(); err == nil || s.server.spilledBodySectionBytes.Load() != 0 {
		t.Fatal("in-memory replacement leaked the spill")
	}
}

func TestSpilledBodySectionRefusalPreservesExistingCache(t *testing.T) {
	s, tracker := newFetchTestSession(0)
	t.Cleanup(s.releaseBodySectionCache)
	if err := tracker.Allocate(3); err != nil {
		t.Fatal(err)
	}
	if !s.retainBodySection("small", []byte("old")) {
		t.Fatal("small section not retained")
	}
	data := make([]byte, maxCachedBodySectionBytes+1)
	t.Run("node budget", func(t *testing.T) {
		s.server.spilledBodySectionBytes.Store(maxServerSpilledBodySectionBytes)
		defer s.server.spilledBodySectionBytes.Store(0)
		if s.spillBodySection("large", data) {
			t.Fatal("spill exceeded node budget")
		}
		if got := s.server.spilledBodySectionBytes.Load(); got != maxServerSpilledBodySectionBytes {
			t.Fatalf("failed reservation changed budget: %d", got)
		}
	})
	t.Run("temporary file creation", func(t *testing.T) {
		t.Setenv("TMPDIR", t.TempDir()+"/missing")
		if s.spillBodySection("large", data) {
			t.Fatal("spill succeeded without a temporary directory")
		}
		if got := s.server.spilledBodySectionBytes.Load(); got != 0 {
			t.Fatalf("failed creation leaked reservation: %d", got)
		}
	})
	if !bytes.Equal(s.cachedBodySection("small"), []byte("old")) || tracker.Current() != 3 {
		t.Fatal("optional spill failure replaced or uncharged the existing section")
	}
}

func TestSpilledSectionPartialBoundsMatchMemory(t *testing.T) {
	data := []byte("0123456789")
	for _, p := range []*imap.SectionPartial{nil, {Offset: -1, Size: 2}, {Offset: 0, Size: 0}, {Offset: 2, Size: 3}, {Offset: 8, Size: 99}, {Offset: 10, Size: 1}, {Offset: 11, Size: 1}, {Offset: 1, Size: math.MaxInt64}, {Offset: math.MaxInt64, Size: 1}} {
		off, n := partialBounds(len(data), p)
		want := applyPartial(data, p)
		if !bytes.Equal(data[off:int(off)+n], want) {
			t.Fatalf("partial %v differs between disk and memory", p)
		}
	}
}
