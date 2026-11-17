package imap

import (
	"bytes"
	"context"
	"testing"

	"github.com/migadu/go-imap"
)

// A part larger than the 8 MiB in-memory section cap (such as the 20 MB base64
// attachment in #1076) must still be decoded once across a sequence of
// <offset.size> chunk fetches, without holding 20 MiB in the session's heap
// budget between commands.
func TestFetch_LargeBinaryAndBodyChunksReuseSpilledSection(t *testing.T) {
	const partSize = 20 << 20 // 20 MiB decoded attachment (> 8 MiB RAM cap)
	const chunk = 64 << 10    // 64 KiB chunk

	pattern := []byte("0123456789abcdeffedcba9876543210")
	payload := bytes.Repeat(pattern, partSize/len(pattern))
	body := base64AttachmentMessage(payload)
	msg := fetchTestMessage(body)

	t.Run("20 MiB BINARY chunked download", func(t *testing.T) {
		s, tracker := newFetchTestSession(100 << 20)
		defer s.releaseBodySectionCache()

		// Command 1: load raw message, decode part 2 once, return first 64 KiB chunk,
		// then release command-scoped body and response copies as FETCH does.
		bodyData, bodyFetched := body, true
		if err := tracker.Allocate(int64(len(bodyData))); err != nil {
			t.Fatalf("allocate body: %v", err)
		}
		first, err := s.decodeBinary(context.Background(), &bodyData, &bodyFetched, &imap.FetchOptions{
			BinarySection: []*imap.FetchItemBinarySection{{
				Part: []int{2}, Peek: true, Partial: &imap.SectionPartial{Offset: 0, Size: chunk},
			}},
		}, msg)
		if err != nil {
			t.Fatalf("chunk 1: %v", err)
		}
		if !bytes.Equal(first.sections[0], payload[:chunk]) {
			t.Fatalf("chunk 1 mismatch")
		}
		s.freeSectionCopies(first.charged)
		tracker.Free(int64(len(bodyData)))

		if got := tracker.Current(); got != 0 {
			t.Fatalf("heap tracker between commands = %d, want 0", got)
		}
		if got := s.server.bodySectionCacheBytes.Load(); got != 0 {
			t.Fatalf("in-memory node cache = %d, want 0 for >8 MiB spilled section", got)
		}

		// Subsequent chunk commands pass no raw body: if the decoded 20 MiB section
		// was not retained, they cannot answer at all. Also verify allocations stay
		// proportional to the 64 KiB chunk, not 20 MiB.
		var noBody []byte
		noBodyFetched := true
		for _, offset := range []int64{chunk, 2 * chunk, 10<<20 + 123, partSize - 4096} {
			var next *decodedBinary
			alloc := allocatedBy(func() {
				next, err = s.decodeBinary(context.Background(), &noBody, &noBodyFetched, &imap.FetchOptions{
					BinarySection: []*imap.FetchItemBinarySection{{
						Part: []int{2}, Peek: true, Partial: &imap.SectionPartial{Offset: offset, Size: chunk},
					}},
					BinarySectionSize: []*imap.FetchItemBinarySectionSize{{Part: []int{2}}},
				}, msg)
			})
			if err != nil {
				t.Fatalf("offset %d: %v", offset, err)
			}
			wantEnd := min(int(offset)+chunk, len(payload))
			wantSlice := payload[offset:wantEnd]
			if !bytes.Equal(next.sections[0], wantSlice) {
				t.Fatalf("offset %d: got %d bytes, want %d bytes from retained 20 MiB section",
					offset, len(next.sections[0]), len(wantSlice))
			}
			if next.sizes[0] != uint32(len(payload)) {
				t.Fatalf("offset %d: BINARY.SIZE[2] = %d, want %d", offset, next.sizes[0], len(payload))
			}
			if alloc > 1<<20 {
				t.Errorf("offset %d: chunk fetch allocated %d bytes, want O(chunk) not full re-decode", offset, alloc)
			}
			s.freeSectionCopies(next.charged)
		}

		// Key isolation: retained BINARY[2] never answers BINARY[1] or BODY[2].
		otherBin, err := s.decodeBinary(context.Background(), &noBody, &noBodyFetched, &imap.FetchOptions{
			BinarySection: []*imap.FetchItemBinarySection{{
				Part: []int{1}, Peek: true, Partial: &imap.SectionPartial{Offset: 0, Size: 16},
			}},
		}, msg)
		if err != nil || len(otherBin.sections[0]) != 0 {
			t.Fatalf("BINARY[1] without body = %d bytes, err %v; want empty", len(otherBin.sections[0]), err)
		}

		w := &fakeBodySectionWriter{tracker: tracker}
		if err := fetchBodySections(s, w, &noBody, &noBodyFetched, &imap.FetchOptions{
			BodySection: []*imap.FetchItemBodySection{{
				Part: []int{2}, Peek: true, Partial: &imap.SectionPartial{Offset: 0, Size: 16},
			}},
		}, msg); err != nil {
			t.Fatalf("BODY[2] without body: %v", err)
		}
		if len(w.sections) != 1 || len(w.sections[0].data) != 0 {
			t.Fatalf("BODY[2] answered from retained BINARY[2]")
		}
	})

	t.Run("20 MiB BODY chunked download", func(t *testing.T) {
		s, tracker := newFetchTestSession(100 << 20)
		defer s.releaseBodySectionCache()

		rawPart2 := safeExtractPartForTest(body, 2)
		bodyData, bodyFetched := body, true
		if err := tracker.Allocate(int64(len(bodyData))); err != nil {
			t.Fatalf("allocate body: %v", err)
		}
		w1 := &fakeBodySectionWriter{tracker: tracker}
		if err := fetchBodySections(s, w1, &bodyData, &bodyFetched, &imap.FetchOptions{
			BodySection: []*imap.FetchItemBodySection{{
				Part: []int{2}, Peek: true, Partial: &imap.SectionPartial{Offset: 0, Size: chunk},
			}},
		}, msg); err != nil {
			t.Fatalf("BODY chunk 1: %v", err)
		}
		if !bytes.Equal(w1.sections[0].data, rawPart2[:chunk]) {
			t.Fatalf("BODY chunk 1 mismatch")
		}
		tracker.Free(int64(len(bodyData)))
		if got := tracker.Current(); got != 0 {
			t.Fatalf("heap tracker after BODY chunk 1 = %d, want 0", got)
		}

		var noBody []byte
		noBodyFetched := true
		w2 := &fakeBodySectionWriter{tracker: tracker}
		if err := fetchBodySections(s, w2, &noBody, &noBodyFetched, &imap.FetchOptions{
			BodySection: []*imap.FetchItemBodySection{{
				Part: []int{2}, Peek: true, Partial: &imap.SectionPartial{Offset: chunk, Size: chunk},
			}},
		}, msg); err != nil {
			t.Fatalf("BODY chunk 2: %v", err)
		}
		if !bytes.Equal(w2.sections[0].data, rawPart2[chunk:2*chunk]) {
			t.Fatalf("BODY chunk 2 = %d bytes, want %d bytes from spilled section", len(w2.sections[0].data), chunk)
		}
	})
}

func safeExtractPartForTest(raw []byte, partNum int) []byte {
	full, _ := safeExtractBodySection(raw, &imap.FetchItemBodySection{Part: []int{partNum}})
	return full
}

// If reading a spilled BINARY section fails mid-part (e.g., after reading the
// first <partial> slice, or on a whole-part read) and the raw-body fallback
// returns (nil, nil), decodeBinary must not leave dirty BINARY.SIZE entries or
// uncharged slice buffers in b.sections.
func TestFetch_AnswerBinaryFromSpillFallbackClearsPartialState(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789abcdef"), (maxCachedBodySectionBytes+128)/16)
	msg := fetchTestMessage(nil)
	key := binarySectionCacheKey(msg.ContentHash, []int{2})

	t.Run("chunked mid-part spill read failure with nil body fallback", func(t *testing.T) {
		s, tracker := newFetchTestSession(100 << 20)
		defer s.releaseBodySectionCache()

		if !s.spillBodySection(key, payload) {
			t.Fatal("spillBodySection failed")
		}
		// Truncate at 64 octets so <0.64> reads cleanly from the spill file,
		// then <64.64> hits EOF and triggers the fallback path.
		if err := s.bodySectionCacheFile.Truncate(64); err != nil {
			t.Fatalf("Truncate: %v", err)
		}

		var noBody []byte
		noBodyFetched := true
		b, err := s.decodeBinary(context.Background(), &noBody, &noBodyFetched, &imap.FetchOptions{
			BinarySection: []*imap.FetchItemBinarySection{
				{Part: []int{2}, Peek: true, Partial: &imap.SectionPartial{Offset: 0, Size: 64}},
				{Part: []int{2}, Peek: true, Partial: &imap.SectionPartial{Offset: 64, Size: 64}},
			},
			BinarySectionSize: []*imap.FetchItemBinarySectionSize{{Part: []int{2}}},
		}, msg)
		if err != nil {
			t.Fatalf("decodeBinary: %v", err)
		}
		if b.charged != 0 || tracker.Current() != 0 {
			t.Errorf("charged=%d tracker=%d, want 0", b.charged, tracker.Current())
		}
		if b.sizes[0] != 0 {
			t.Errorf("BINARY.SIZE[2] = %d after nil-body fallback, want 0", b.sizes[0])
		}
		if b.sections[0] != nil || b.sections[1] != nil {
			t.Errorf("BINARY[2] sections = [%d bytes, %d bytes] (uncharged), want [nil, nil]",
				len(b.sections[0]), len(b.sections[1]))
		}
	})

	t.Run("whole-part spill read failure with nil body fallback", func(t *testing.T) {
		s, tracker := newFetchTestSession(100 << 20)
		defer s.releaseBodySectionCache()

		if !s.spillBodySection(key, payload) {
			t.Fatal("spillBodySection failed")
		}
		if err := s.bodySectionCacheFile.Truncate(64); err != nil {
			t.Fatalf("Truncate: %v", err)
		}

		var noBody []byte
		noBodyFetched := true
		b, err := s.decodeBinary(context.Background(), &noBody, &noBodyFetched, &imap.FetchOptions{
			BinarySection:     []*imap.FetchItemBinarySection{{Part: []int{2}, Peek: true}},
			BinarySectionSize: []*imap.FetchItemBinarySectionSize{{Part: []int{2}}},
		}, msg)
		if err != nil {
			t.Fatalf("decodeBinary: %v", err)
		}
		if b.charged != 0 || tracker.Current() != 0 {
			t.Errorf("charged=%d tracker=%d, want 0", b.charged, tracker.Current())
		}
		if b.sizes[0] != 0 || b.sections[0] != nil {
			t.Errorf("whole-part fallback left BINARY.SIZE=%d section=%d bytes, want 0 and nil",
				b.sizes[0], len(b.sections[0]))
		}
	})

	t.Run("chunked mid-part memory refusal clears earlier slice and size", func(t *testing.T) {
		s, tracker := newFetchTestSession(96) // fits <0.64>, refuses <64.64>
		defer s.releaseBodySectionCache()

		if !s.spillBodySection(key, payload) {
			t.Fatal("spillBodySection failed")
		}
		options := &imap.FetchOptions{
			BinarySection: []*imap.FetchItemBinarySection{
				{Part: []int{2}, Peek: true, Partial: &imap.SectionPartial{Offset: 0, Size: 64}},
				{Part: []int{2}, Peek: true, Partial: &imap.SectionPartial{Offset: 64, Size: 64}},
			},
			BinarySectionSize: []*imap.FetchItemBinarySectionSize{{Part: []int{2}}},
		}
		b := &decodedBinary{
			sections: make([][]byte, 2),
			sizes:    make([]uint32, 1),
		}
		ok, err := s.answerBinaryFromSpill(b, binaryParts(options)[0], options, msg.UID, key, len(payload), true, 0)
		requireMemoryRefusal(t, err, imap.ResponseCodeLimit)
		if ok {
			t.Fatal("answerBinaryFromSpill reported ok on memory refusal")
		}
		if tracker.Current() != 0 || b.charged != 0 {
			t.Errorf("tracker=%d charged=%d, want 0", tracker.Current(), b.charged)
		}
		if b.sizes[0] != 0 || b.sections[0] != nil || b.sections[1] != nil {
			t.Errorf("memory refusal left dirty state: sizes=%v sections=[%d, %d]",
				b.sizes, len(b.sections[0]), len(b.sections[1]))
		}
	})
}
