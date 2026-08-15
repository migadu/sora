package imap

import (
	"bytes"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
)

// TestRetainBodySection_Bounds pins the bounds on what a session may keep between
// commands: one section, capped per session and node-wide.
func TestRetainBodySection_Bounds(t *testing.T) {
	t.Run("one section per session", func(t *testing.T) {
		s, tracker := newFetchTestSession(0)
		first := bytes.Repeat([]byte("a"), 1024)
		second := bytes.Repeat([]byte("b"), 2048)

		if err := tracker.Allocate(int64(len(first))); err != nil {
			t.Fatal(err)
		}
		if !s.retainBodySection("first", first) {
			t.Fatal("first section not retained")
		}
		if err := tracker.Allocate(int64(len(second))); err != nil {
			t.Fatal(err)
		}
		if !s.retainBodySection("second", second) {
			t.Fatal("second section not retained")
		}

		if got := s.cachedBodySection("first"); got != nil {
			t.Error("first section still retained after a second one was cached")
		}
		if got := s.cachedBodySection("second"); !bytes.Equal(got, second) {
			t.Error("second section not readable from the cache")
		}
		if got, want := tracker.Current(), int64(len(second)); got != want {
			t.Errorf("tracker = %d bytes, want %d (the evicted section was not given back)", got, want)
		}
		if got, want := s.server.bodySectionCacheBytes.Load(), int64(len(second)); got != want {
			t.Errorf("node-wide retained bytes = %d, want %d", got, want)
		}

		s.releaseBodySectionCache()
		if got := tracker.Current(); got != 0 {
			t.Errorf("tracker after release = %d bytes, want 0", got)
		}
		if got := s.server.bodySectionCacheBytes.Load(); got != 0 {
			t.Errorf("node-wide retained bytes after release = %d, want 0", got)
		}
	})

	t.Run("oversized section is not retained", func(t *testing.T) {
		s, _ := newFetchTestSession(0)
		if s.retainBodySection("big", make([]byte, maxCachedBodySectionBytes+1)) {
			t.Error("section larger than the per-session cap was retained")
		}
		if got := s.server.bodySectionCacheBytes.Load(); got != 0 {
			t.Errorf("node-wide retained bytes = %d, want 0", got)
		}
	})

	t.Run("hashless message is not retained", func(t *testing.T) {
		s, _ := newFetchTestSession(0)
		if s.retainBodySection("", bytes.Repeat([]byte("a"), 1024)) {
			t.Error("section retained under an empty cache key")
		}
		if got := s.cachedBodySection(""); got != nil {
			t.Error("empty cache key returned data")
		}
	})

	t.Run("node-wide cap refuses further retention", func(t *testing.T) {
		s, _ := newFetchTestSession(0)
		s.server.bodySectionCacheBytes.Store(maxServerBodySectionCacheBytes)
		if s.retainBodySection("late", bytes.Repeat([]byte("c"), 1024)) {
			t.Error("section retained past the node-wide cap")
		}
		if got, want := s.server.bodySectionCacheBytes.Load(), int64(maxServerBodySectionCacheBytes); got != want {
			t.Errorf("node-wide retained bytes = %d, want %d", got, want)
		}
	})

	t.Run("retention never starves a later allocation", func(t *testing.T) {
		s, tracker := newFetchTestSession(4096)
		retained := bytes.Repeat([]byte("d"), 3072)
		if err := tracker.Allocate(int64(len(retained))); err != nil {
			t.Fatal(err)
		}
		if !s.retainBodySection("retained", retained) {
			t.Fatal("section not retained")
		}
		if !s.memoryAvailable(4096) {
			t.Error("a full-budget allocation was refused because of a retained section")
		}
		if got := tracker.Current(); got != 0 {
			t.Errorf("tracker = %d bytes, want 0 after reclaiming the retained section", got)
		}
		if got := s.cachedBodySection("retained"); got != nil {
			t.Error("reclaimed section is still readable")
		}
	})
}

// TestApplyPartial_ClientSuppliedBounds covers the arithmetic on the client-supplied
// <offset.size>, including the addition that would otherwise wrap and panic on a slice.
func TestApplyPartial_ClientSuppliedBounds(t *testing.T) {
	data := []byte("0123456789")
	tests := []struct {
		name    string
		partial *imap.SectionPartial
		want    string
	}{
		{"nil partial", nil, "0123456789"},
		{"inside", &imap.SectionPartial{Offset: 2, Size: 3}, "234"},
		{"clamped to end", &imap.SectionPartial{Offset: 8, Size: 100}, "89"},
		{"offset at end", &imap.SectionPartial{Offset: 10, Size: 1}, ""},
		{"offset past end", &imap.SectionPartial{Offset: 11, Size: 1}, ""},
		{"size overflows int64", &imap.SectionPartial{Offset: 1, Size: 1<<63 - 1}, "123456789"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(applyPartial(data, tt.partial)); got != tt.want {
				t.Errorf("applyPartial = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBodySectionCacheKey_DistinguishesSections keeps chunk requests for different
// sections of the same message from sharing one cache entry.
func TestBodySectionCacheKey_DistinguishesSections(t *testing.T) {
	hash := strings.Repeat("a", 64)
	keys := map[string]string{
		"full":      bodySectionCacheKey(hash, &imap.FetchItemBodySection{}),
		"part 1":    bodySectionCacheKey(hash, &imap.FetchItemBodySection{Part: []int{1}}),
		"part 2":    bodySectionCacheKey(hash, &imap.FetchItemBodySection{Part: []int{2}}),
		"part 2.1":  bodySectionCacheKey(hash, &imap.FetchItemBodySection{Part: []int{2, 1}}),
		"header":    bodySectionCacheKey(hash, &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader}),
		"text":      bodySectionCacheKey(hash, &imap.FetchItemBodySection{Specifier: imap.PartSpecifierText}),
		"fields":    bodySectionCacheKey(hash, &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader, HeaderFields: []string{"From"}}),
		"fieldsnot": bodySectionCacheKey(hash, &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader, HeaderFieldsNot: []string{"From"}}),
		"other msg": bodySectionCacheKey(strings.Repeat("b", 64), &imap.FetchItemBodySection{Part: []int{2}}),
	}
	seen := make(map[string]string, len(keys))
	for name, key := range keys {
		if other, dup := seen[key]; dup {
			t.Errorf("%s and %s share cache key %q", name, other, key)
		}
		seen[key] = name
	}

	// The <offset.size> slice is not part of the identity: chunks share one entry.
	withPartial := bodySectionCacheKey(hash, &imap.FetchItemBodySection{
		Part:    []int{2},
		Partial: &imap.SectionPartial{Offset: 4096, Size: 4096},
	})
	if withPartial != keys["part 2"] {
		t.Errorf("chunked request key %q differs from %q", withPartial, keys["part 2"])
	}

	// A message with no content hash gets no key at all.
	if got := bodySectionCacheKey("", &imap.FetchItemBodySection{Part: []int{2}}); got != "" {
		t.Errorf("cache key for a hashless message = %q, want \"\"", got)
	}
}
