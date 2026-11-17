package imap

import (
	"bytes"
	"math"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// Over-budget reservation attempts must never transiently push the atomic counter
// above its cap: doing so makes concurrent negative releases look "over cap" and
// undo themselves (permanently leaking node budget) while spuriously rejecting
// concurrent smaller reservations that fit within the remaining headroom.
func TestReserveBodySectionBudgets_ConcurrentOverCapDoesNotLeakOrReject(t *testing.T) {
	if runtime.GOMAXPROCS(0) < 4 {
		defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	}

	srv := &IMAPServer{}
	cases := []struct {
		name    string
		limit   int64
		counter *atomic.Int64
		reserve func(int64) bool
	}{
		{
			name:    "spilled budget",
			limit:   maxServerSpilledBodySectionBytes,
			counter: &srv.spilledBodySectionBytes,
			reserve: srv.reserveSpilledBodySectionBytes,
		},
		{
			name:    "in-memory budget",
			limit:   maxServerBodySectionCacheBytes,
			counter: &srv.bodySectionCacheBytes,
			reserve: srv.reserveBodySectionCacheBytes,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.counter.Store(0)
			defer tc.counter.Store(0)

			const (
				workers     = 4
				overCallers = 4
				iters       = 20000
			)
			unit := tc.limit / 64
			pinned := 58 * unit // 6*unit headroom: 4 workers of 1*unit always fit, 10*unit never fits.
			over := 10 * unit

			if !tc.reserve(pinned) {
				t.Fatalf("pinned reservation of %d failed", pinned)
			}

			var (
				start           = make(chan struct{})
				wg              sync.WaitGroup
				overGranted     atomic.Int64
				spuriousRejects atomic.Int64
			)

			for range overCallers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					for range iters {
						if tc.reserve(over) {
							overGranted.Add(1)
							tc.reserve(-over)
						}
					}
				}()
			}

			for range workers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					for range iters {
						if !tc.reserve(unit) {
							spuriousRejects.Add(1)
							continue
						}
						tc.reserve(-unit)
					}
				}()
			}

			close(start)
			wg.Wait()
			tc.reserve(-pinned)

			if got := overGranted.Load(); got != 0 {
				t.Errorf("granted %d over-budget reservations, want 0", got)
			}
			if got := spuriousRejects.Load(); got != 0 {
				t.Errorf("spuriously rejected %d fitting reservations while over-budget attempts raced", got)
			}
			if got := tc.counter.Load(); got != 0 {
				t.Errorf("node budget after releasing all reservations = %d bytes, want 0 (leaked)", got)
			}
		})
	}
}

// Once IMAPSession.Close has run, late or concurrent retainBodySection and
// spillBodySection calls must not store an unclosed file descriptor or leak
// node-wide / session memory reservations.
func TestBodySectionCache_ClosePreventsLateRetainAndSpillLeak(t *testing.T) {
	spillData := bytes.Repeat([]byte("z"), maxCachedBodySectionBytes+1)
	smallData := []byte("small-section")

	t.Run("after Close", func(t *testing.T) {
		s, tracker := newFetchTestSession(0)
		s.server.sessions.Add()
		t.Cleanup(func() {
			if s.bodySectionCacheFile != nil {
				_ = s.bodySectionCacheFile.Close()
			}
			s.server.spilledBodySectionBytes.Store(0)
			s.server.bodySectionCacheBytes.Store(0)
		})

		if !s.spillBodySection("initial", spillData) {
			t.Fatal("initial spill failed")
		}
		initialFile := s.bodySectionCacheFile
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if _, err := initialFile.Stat(); err == nil {
			t.Fatal("Close left initial spill descriptor open")
		}

		if err := tracker.Allocate(int64(len(smallData))); err != nil {
			t.Fatal(err)
		}
		if s.retainBodySection("late-mem", smallData) {
			t.Error("retainBodySection succeeded after Close")
		} else {
			tracker.Free(int64(len(smallData)))
		}

		if s.spillBodySection("late-spill", spillData) {
			t.Error("spillBodySection succeeded after Close")
		}

		if s.bodySectionCacheFile != nil || s.bodySectionCacheData != nil || s.bodySectionCacheKey != "" {
			t.Errorf("cache populated after Close: key=%q data=%d file=%v",
				s.bodySectionCacheKey, len(s.bodySectionCacheData), s.bodySectionCacheFile)
		}
		if got := s.server.bodySectionCacheBytes.Load(); got != 0 {
			t.Errorf("bodySectionCacheBytes after Close = %d, want 0", got)
		}
		if got := s.server.spilledBodySectionBytes.Load(); got != 0 {
			t.Errorf("spilledBodySectionBytes after Close = %d, want 0", got)
		}
		if got := tracker.Current(); got != 0 {
			t.Errorf("session memory tracker after Close = %d, want 0", got)
		}
	})

	t.Run("Close during unlocked spill write", func(t *testing.T) {
		largeSpill := bytes.Repeat([]byte("w"), 16<<20)
		for iter := range 8 {
			s, _ := newFetchTestSession(0)
			s.server.sessions.Add()

			done := make(chan bool, 1)
			go func() {
				done <- s.spillBodySection("inflight", largeSpill)
			}()

			deadline := time.Now().Add(5 * time.Second)
			for s.server.spilledBodySectionBytes.Load() == 0 && len(done) == 0 {
				if time.Now().After(deadline) {
					t.Fatal("timed out waiting for spillBodySection to reserve bytes")
				}
				runtime.Gosched()
			}

			if err := s.Close(); err != nil {
				t.Fatalf("iter %d Close: %v", iter, err)
			}
			<-done

			leakedFile := s.bodySectionCacheFile
			leakedBytes := s.server.spilledBodySectionBytes.Load()
			if leakedFile != nil {
				_ = leakedFile.Close()
			}
			s.server.spilledBodySectionBytes.Store(0)

			if leakedFile != nil || s.bodySectionCacheKey != "" || leakedBytes != 0 {
				t.Fatalf("iter %d: concurrent Close + spill leaked file=%v key=%q spilledBytes=%d",
					iter, leakedFile, s.bodySectionCacheKey, leakedBytes)
			}
		}
	})
}
