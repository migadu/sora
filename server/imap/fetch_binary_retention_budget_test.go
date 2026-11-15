package imap

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/migadu/go-imap"
)

func TestFetch_BinaryPartialDoesNotRequireRetentionBudget(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		hash bool
	}{
		{"cacheable", 24 << 10, true},
		{"no content hash", 24 << 10, false},
		{"over retention limit", 9 << 20, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte("x"), tc.size)
			encoded := base64.StdEncoding.EncodeToString(payload)
			var raw strings.Builder
			raw.WriteString("Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n")
			for len(encoded) > 76 {
				raw.WriteString(encoded[:76] + "\r\n")
				encoded = encoded[76:]
			}
			raw.WriteString(encoded + "\r\n")
			body := []byte(raw.String())
			msg := fetchTestMessage(body)
			if !tc.hash {
				msg.ContentHash = ""
			}
			const chunk = 1024
			s, tracker := newFetchTestSession(int64(len(body) + 4096))
			if err := tracker.Allocate(int64(len(body))); err != nil {
				t.Fatal(err)
			}
			fetched := true
			b, err := s.decodeBinary(context.Background(), &body, &fetched, &imap.FetchOptions{
				BinarySection: []*imap.FetchItemBinarySection{{Part: []int{1}, Peek: true, Partial: &imap.SectionPartial{Offset: 0, Size: chunk}}},
			}, msg)
			if err != nil {
				t.Fatalf("loaded body=%d decoded=%d remaining=4096 requested=%d: %v", len(body), tc.size, chunk, err)
			}
			defer s.freeSectionCopies(b.charged)
			defer s.releaseBodySectionCache()
			if !bytes.Equal(b.sections[0], payload[:chunk]) {
				t.Fatalf("partial=%d, want %d", len(b.sections[0]), chunk)
			}
			if got, want := tracker.Current(), int64(len(body)+chunk); got != want {
				t.Fatalf("memory=%d, want body+response=%d", got, want)
			}
		})
	}
}

func TestFetch_BinaryCachedWholeItemsShareResponseCharge(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 64<<10)
	s, tracker := newFetchTestSession(int64(len(payload) + 4096))
	msg := fetchTestMessage(nil)
	if err := tracker.Allocate(int64(len(payload))); err != nil {
		t.Fatal(err)
	}
	if !s.retainBodySection(binarySectionCacheKey(msg.ContentHash, []int{1}), payload) {
		t.Fatal("not retained")
	}
	var body []byte
	fetched := true
	b, err := s.decodeBinary(context.Background(), &body, &fetched, &imap.FetchOptions{
		BinarySection: []*imap.FetchItemBinarySection{{Part: []int{1}}, {Part: []int{1}}},
	}, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.sections[0], payload) || !bytes.Equal(b.sections[1], payload) {
		t.Fatal("wrong response")
	}
	if b.charged != int64(len(payload)) || tracker.Current() != b.charged {
		t.Fatalf("whole charge=%d tracker=%d", b.charged, tracker.Current())
	}
	s.freeSectionCopies(b.charged)
	if tracker.Current() != 0 || s.server.bodySectionCacheBytes.Load() != 0 {
		t.Fatal("cache or response charge leaked")
	}
}

func TestFetch_BinaryRetentionFailureCleanup(t *testing.T) {
	t.Run("reclaim cached section during partials", func(t *testing.T) {
		payload := bytes.Repeat([]byte("x"), 32<<10)
		s, tracker := newFetchTestSession(int64(len(payload) + 512))
		msg := fetchTestMessage(nil)
		if err := tracker.Allocate(int64(len(payload))); err != nil {
			t.Fatal(err)
		}
		if !s.retainBodySection(binarySectionCacheKey(msg.ContentHash, []int{1}), payload) {
			t.Fatal("not retained")
		}
		var body []byte
		fetched := true
		b, err := s.decodeBinary(context.Background(), &body, &fetched, &imap.FetchOptions{
			BinarySection: []*imap.FetchItemBinarySection{
				{Part: []int{1}, Partial: &imap.SectionPartial{Offset: 0, Size: 1024}},
				{Part: []int{1}, Partial: &imap.SectionPartial{Offset: 1024, Size: 1024}},
			},
		}, msg)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b.sections[0], payload[:1024]) || !bytes.Equal(b.sections[1], payload[1024:2048]) {
			t.Fatal("cached slices were not copied correctly")
		}
		if tracker.Current() != 2048 || b.charged != 2048 || s.server.bodySectionCacheBytes.Load() != 0 {
			t.Fatalf("response=%d tracker=%d node=%d", b.charged, tracker.Current(), s.server.bodySectionCacheBytes.Load())
		}
		s.freeSectionCopies(b.charged)
		s.releaseBodySectionCache()
		if tracker.Current() != 0 {
			t.Fatal("charge leaked")
		}
	})
	t.Run("node admission", func(t *testing.T) {
		body := []byte(binaryDecodeTestBody)
		s, tracker := newFetchTestSession(0)
		s.server.bodySectionCacheBytes.Store(maxServerBodySectionCacheBytes)
		fetched := true
		b, err := s.decodeBinary(context.Background(), &body, &fetched, &imap.FetchOptions{
			BinarySection: []*imap.FetchItemBinarySection{{Part: []int{1}, Partial: &imap.SectionPartial{Offset: 0, Size: 4}}},
		}, fetchTestMessage(body))
		if err != nil {
			t.Fatal(err)
		}
		if tracker.Current() != 4 || s.server.bodySectionCacheBytes.Load() != maxServerBodySectionCacheBytes {
			t.Fatalf("tracker=%d node=%d", tracker.Current(), s.server.bodySectionCacheBytes.Load())
		}
		s.freeSectionCopies(b.charged)
		if tracker.Current() != 0 {
			t.Fatal("response charge leaked")
		}
	})
	t.Run("later part fails", func(t *testing.T) {
		body := []byte(binaryDecodeTestBody)
		s, tracker := newFetchTestSession(0)
		fetched := true
		_, err := s.decodeBinary(context.Background(), &body, &fetched, &imap.FetchOptions{
			BinarySection: []*imap.FetchItemBinarySection{{Part: []int{1}, Partial: &imap.SectionPartial{Offset: 0, Size: 4}}, {Part: []int{2}}},
		}, fetchTestMessage(body))
		if err == nil {
			t.Fatal("unknown CTE accepted")
		}
		if got := tracker.Current(); got != s.server.bodySectionCacheBytes.Load() || got == 0 {
			t.Fatalf("response charges remain: tracker=%d node=%d", got, s.server.bodySectionCacheBytes.Load())
		}
		s.releaseBodySectionCache()
		if tracker.Current() != 0 || s.server.bodySectionCacheBytes.Load() != 0 {
			t.Fatal("retained charge leaked")
		}
	})
}
