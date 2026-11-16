package imap

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/metrics"
	serverPkg "github.com/migadu/sora/server"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// requireMemoryRefusal fails t unless err is NO with code, the answer to a body
// or section the session memory budget refuses: [LIMIT] when it can never fit
// the budget, [UNAVAILABLE] when the budget is only short for now.
func requireMemoryRefusal(t *testing.T, err error, code imap.ResponseCode) {
	t.Helper()
	var imapErr *imap.Error
	if !errors.As(err, &imapErr) {
		t.Fatalf("error = %v, want NO [%s]", err, code)
	}
	if imapErr.Type != imap.StatusResponseTypeNo || imapErr.Code != code {
		t.Fatalf("error = %v [%v], want NO [%s]", imapErr.Type, imapErr.Code, code)
	}
}

// newBudgetTestSession returns a session with the given memory budget, whose
// body cache holds body, and body's message with the given size (0: unknown).
func newBudgetTestSession(t *testing.T, limit int64, body []byte, size int) (*IMAPSession, *serverPkg.SessionMemoryTracker, *db.Message) {
	t.Helper()
	s, tracker := newFetchTestSession(limit)
	c, err := cache.New(t.TempDir(), 1<<20, 1<<20, time.Hour, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	s.server.cache = c
	msg := fetchTestMessage(body)
	msg.Size = size
	msg.IsUploaded = true
	putCacheFile(t, s, msg.ContentHash, string(body))
	return s, tracker, msg
}

// fetchItemsBeforeResponse runs what writeMessageFetchData runs for msg's
// BINARY and BODY items before it sets the message's implicit \Seen and opens
// its response, and gives back what that charged, as writeMessageFetchData
// does once the response is written.
func fetchItemsBeforeResponse(s *IMAPSession, msg *db.Message, options *imap.FetchOptions) error {
	ctx := context.Background()
	var bodyData []byte
	var bodyFetched bool
	defer func() {
		if bodyFetched && bodyData != nil {
			s.memTracker.Free(int64(len(bodyData)))
		}
	}()
	var binaryCopies int64
	if len(options.BinarySection) > 0 || len(options.BinarySectionSize) > 0 {
		b, err := s.decodeBinary(ctx, &bodyData, &bodyFetched, options, msg)
		if err != nil {
			return err
		}
		defer s.freeSectionCopies(b.charged)
		binaryCopies = b.charged
	}
	if len(options.BodySection) > 0 {
		b, err := s.extractBodySections(ctx, &bodyData, &bodyFetched, options, msg, binaryCopies)
		if err != nil {
			return err
		}
		defer s.freeSectionCopies(b.charged)
	}
	return nil
}

// TestFetch_BodyOverSessionBudgetIsRefused: a body the session memory budget
// cannot hold fails the FETCH at its message before the message's response is
// opened and its implicit \Seen set, as a section copy the budget refuses does
// (#1256). An empty BODY[] literal, or empty BINARY[] data with BINARY.SIZE 0,
// for a body that exists is wrong data the client caches as the message. The
// budget refuses the body before reading it when the message size is known,
// and after reading it otherwise. A body larger than the whole budget can never
// be fetched, so the refusal is NO [LIMIT] (RFC 5530: "The operation ran up
// against an implementation limit of some kind"), not NO [UNAVAILABLE]
// ("Temporary failure"), which clients retry on every sync.
func TestFetch_BodyOverSessionBudgetIsRefused(t *testing.T) {
	body := multipartTestMessage(64 * 1024)
	const limit = 1024

	for _, size := range []struct {
		name string
		size int
	}{
		{"size known, refused before the read", len(body)},
		{"size unknown, refused after the read", 0},
	} {
		t.Run(size.name, func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				section *imap.FetchItemBodySection
			}{
				{"BODY[]", &imap.FetchItemBodySection{}},
				{"BODY[2]", &imap.FetchItemBodySection{Part: []int{2}}},
				{"BODY[2]<0.1024>", &imap.FetchItemBodySection{Part: []int{2}, Partial: &imap.SectionPartial{Offset: 0, Size: 1024}}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					s, tracker, msg := newBudgetTestSession(t, limit, body, size.size)
					var bodyData []byte
					var bodyFetched bool
					options := &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{tc.section}}
					write, err := bodySectionsBeforeResponse(s, &bodyData, &bodyFetched, options, msg)
					if err == nil {
						w := &fakeBodySectionWriter{}
						err = write(w)
						for _, written := range w.sections {
							t.Errorf("answered a %d-octet message with a %d-octet literal", len(body), written.declaredSize)
						}
					}
					requireMemoryRefusal(t, err, imap.ResponseCodeLimit)
					if got := tracker.Current(); got != 0 {
						t.Errorf("memory tracker after refusal = %d bytes, want 0", got)
					}
				})
			}

			t.Run("BINARY[2] BINARY.SIZE[2]", func(t *testing.T) {
				s, tracker, msg := newBudgetTestSession(t, limit, body, size.size)
				var bodyData []byte
				var bodyFetched bool
				b, err := s.decodeBinary(context.Background(), &bodyData, &bodyFetched, &imap.FetchOptions{
					BinarySection:     []*imap.FetchItemBinarySection{{Part: []int{2}}},
					BinarySectionSize: []*imap.FetchItemBinarySectionSize{{Part: []int{2}}},
				}, msg)
				if err == nil {
					t.Errorf("answered BINARY[2] with %d octets and BINARY.SIZE[2] %d", len(b.sections[0]), b.sizes[0])
					s.freeSectionCopies(b.charged)
				}
				requireMemoryRefusal(t, err, imap.ResponseCodeLimit)
				if got := tracker.Current(); got != 0 {
					t.Errorf("memory tracker after refusal = %d bytes, want 0", got)
				}
			})
		})
	}
}

// TestFetch_SectionOverBudgetRefusedBeforeResponse: a section copy the session
// memory budget refuses fails the FETCH at its message before the message's
// response is opened and its implicit \Seen set, as everything else that fails
// the command at a message does (#1222). Refused while the sections were being
// written, it left a partial "* n FETCH (FLAGS (\Seen))" behind, and the message
// \Seen though its body was never sent. A section larger than the whole budget
// is NO [LIMIT].
func TestFetch_SectionOverBudgetRefusedBeforeResponse(t *testing.T) {
	body := multipartTestMessage(64 * 1024)
	for _, tc := range []struct {
		name    string
		section *imap.FetchItemBodySection
	}{
		{"BODY[2]", &imap.FetchItemBodySection{Part: []int{2}}},
		{"BODY[2]<0.512>", &imap.FetchItemBodySection{Part: []int{2}, Partial: &imap.SectionPartial{Offset: 0, Size: 512}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, tracker := newFetchTestSession(1024)
			bodyData, bodyFetched := body, true
			_, err := bodySectionsBeforeResponse(s, &bodyData, &bodyFetched,
				&imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{tc.section}}, fetchTestMessage(body))
			requireMemoryRefusal(t, err, imap.ResponseCodeLimit)
			if got := tracker.Current(); got != 0 {
				t.Errorf("memory tracker after refusal = %d bytes, want 0", got)
			}
		})
	}
}

// TestFetch_SectionBesideItsBodyOverBudgetIsLimit: a section copy is held next
// to the body it is taken from, so a section that fits the session memory
// budget alone but not beside its body can never be fetched either, however
// often the client retries: NO [LIMIT], as for a body larger than the budget.
// BODY[] of the same message, which needs no copy, is still answered.
func TestFetch_SectionBesideItsBodyOverBudgetIsLimit(t *testing.T) {
	body := multipartTestMessage(64 * 1024)
	section := imapserver.ExtractBodySection(bytes.NewReader(body), &imap.FetchItemBodySection{Part: []int{2}})
	limit := int64(len(body) + len(section)/2)

	t.Run("BODY[] fits", func(t *testing.T) {
		s, tracker, msg := newBudgetTestSession(t, limit, body, len(body))
		if err := fetchItemsBeforeResponse(s, msg, &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{}}}); err != nil {
			t.Fatalf("BODY[] = %v, want the body: it fits the budget", err)
		}
		if got := tracker.Current(); got != 0 {
			t.Errorf("memory tracker after the fetch = %d bytes, want 0", got)
		}
	})
	for _, tc := range []struct {
		name    string
		options *imap.FetchOptions
	}{
		{"BODY[2]", &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{Part: []int{2}}}}},
		{"BODY[2]<0.1024>", &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{Part: []int{2}, Partial: &imap.SectionPartial{Offset: 0, Size: 1024}}}}},
		{"BINARY[2]", &imap.FetchOptions{BinarySection: []*imap.FetchItemBinarySection{{Part: []int{2}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, tracker, msg := newBudgetTestSession(t, limit, body, len(body))
			requireMemoryRefusal(t, fetchItemsBeforeResponse(s, msg, tc.options), imap.ResponseCodeLimit)
			if got := tracker.Current(); got != 0 {
				t.Errorf("memory tracker after refusal = %d bytes, want 0", got)
			}
		})
	}
}

// TestFetch_BudgetShortForNowIsUnavailable: a body or section the session
// memory budget could hold, but not beside what other allocations of the
// session hold at the moment, can be fetched once they are given back: NO
// [UNAVAILABLE], which the client retries, and not NO [LIMIT].
func TestFetch_BudgetShortForNowIsUnavailable(t *testing.T) {
	body := multipartTestMessage(64 * 1024)
	limit := int64(4 * len(body))
	for _, tc := range []struct {
		name    string
		size    int   // the message's recorded size, 0 when unknown
		held    int64 // what other allocations hold
		options *imap.FetchOptions
	}{
		{"BODY[], size known, refused before the read", len(body), limit - int64(len(body)/2),
			&imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{}}}},
		{"BODY[], size unknown, refused after the read", 0, limit - int64(len(body)/2),
			&imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{}}}},
		{"BODY[2], section copy refused", len(body), limit - int64(len(body)) - 1024,
			&imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{Part: []int{2}}}}},
		{"BINARY[2], section copy refused", len(body), limit - int64(len(body)) - 1024,
			&imap.FetchOptions{BinarySection: []*imap.FetchItemBinarySection{{Part: []int{2}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, tracker, msg := newBudgetTestSession(t, limit, body, tc.size)
			if err := tracker.Allocate(tc.held); err != nil {
				t.Fatal(err)
			}
			requireMemoryRefusal(t, fetchItemsBeforeResponse(s, msg, tc.options), imap.ResponseCodeUnavailable)
			if got := tracker.Current(); got != tc.held {
				t.Errorf("memory tracker after refusal = %d bytes, want the %d held before", got, tc.held)
			}
		})
	}
}

// TestFetch_ChunkStaysChargedUntilWritten: the sections of a FETCH are held
// until its response is written, and a chunk of a retained section stays
// charged that long even when a later section of the same FETCH takes the
// retention over (memoryAvailable may also give it up): the chunk is a copy
// of its own, not a slice of a section nothing charges any more.
func TestFetch_ChunkStaysChargedUntilWritten(t *testing.T) {
	body := multipartTestMessage(64 * 1024)
	const chunk = 16 * 1024
	s, tracker := newFetchTestSession(0)
	w := &fakeBodySectionWriter{tracker: tracker}
	bodyData, bodyFetched := body, true
	err := fetchBodySections(s, w, &bodyData, &bodyFetched, &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{
		{Part: []int{2}, Partial: &imap.SectionPartial{Offset: 0, Size: chunk}},
		{Part: []int{1}, Partial: &imap.SectionPartial{Offset: 0, Size: 3}},
	}}, fetchTestMessage(body))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(w.sections) != 2 || len(w.sections[0].data) != chunk || string(w.sections[1].data) != "hel" {
		t.Fatalf("written sections = %+v, want a %d-octet chunk of BODY[2] and \"hel\"", w.sections, chunk)
	}
	if got := w.sections[0].trackerAtWrite; got < chunk {
		t.Errorf("memory tracker while writing the BODY[2] chunk = %d bytes, want at least the %d-octet chunk", got, chunk)
	}
	retained := int64(len(s.cachedBodySection(bodySectionCacheKey(fetchTestMessage(body).ContentHash, &imap.FetchItemBodySection{Part: []int{1}}))))
	if retained == 0 {
		t.Fatal("BODY[1] was not retained")
	}
	if got := tracker.Current(); got != retained {
		t.Errorf("memory tracker after the response = %d bytes, want the %d retained", got, retained)
	}
}

// TestFetch_RetainedSectionYieldsToUnsizedBody: the section a session retains
// for its next chunk gives way to a body the budget could otherwise hold,
// also when the body has no recorded size and is only charged after the read
// (memoryAvailable): bytes kept only to make the next chunk cheaper must never
// be what refuses a FETCH. A refusal is NO [UNAVAILABLE] (#1256), and a retry
// would find the same retained section in the way.
func TestFetch_RetainedSectionYieldsToUnsizedBody(t *testing.T) {
	body := multipartTestMessage(64 * 1024)
	const retainedSize = 32 * 1024
	for _, size := range []struct {
		name string
		size int
	}{
		{"size known", len(body)},
		{"size unknown", 0},
	} {
		t.Run(size.name, func(t *testing.T) {
			s, tracker := newFetchTestSession(int64(len(body)) + retainedSize/2)
			c, err := cache.New(t.TempDir(), 1<<20, 1<<20, time.Hour, time.Hour, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close() })
			s.server.cache = c
			msg := fetchTestMessage(body)
			msg.Size = size.size
			msg.IsUploaded = true
			putCacheFile(t, s, msg.ContentHash, string(body))

			// A section of another message, retained for its next chunk.
			if err := tracker.Allocate(retainedSize); err != nil {
				t.Fatal(err)
			}
			if !s.retainBodySection("other", make([]byte, retainedSize)) {
				t.Fatal("the other section was not retained")
			}

			var bodyData []byte
			var bodyFetched bool
			w := &fakeBodySectionWriter{}
			if err := fetchBodySections(s, w, &bodyData, &bodyFetched,
				&imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{}}}, msg); err != nil {
				t.Fatalf("BODY[] = %v, want the body", err)
			}
			if len(w.sections) != 1 || len(w.sections[0].data) != len(body) {
				t.Fatalf("written sections = %d, want BODY[] with the %d-octet body", len(w.sections), len(body))
			}
			if s.cachedBodySection("other") != nil {
				t.Error("the other section is still retained")
			}
		})
	}
}

// Every prepared response copy stays owned until that response ends. The same
// FETCH is permanently over budget when their total cannot fit, but allocations
// belonging to other work must leave the refusal temporary.
func TestFetch_MultipleCopiesClassifyRequestOwnership(t *testing.T) {
	body := multipartTestMessage(64 * 1024)
	section := imapserver.ExtractBodySection(bytes.NewReader(body), &imap.FetchItemBodySection{Part: []int{2}})
	cases := []struct {
		name    string
		options *imap.FetchOptions
	}{
		{"BODY copies", &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{Part: []int{2}}, {Part: []int{2}}}}},
		{"BINARY partial copies", &imap.FetchOptions{BinarySection: []*imap.FetchItemBinarySection{{Part: []int{2}, Partial: &imap.SectionPartial{Size: int64(len(section))}}, {Part: []int{2}, Partial: &imap.SectionPartial{Size: int64(len(section))}}}}},
		{"mixed BINARY and BODY", &imap.FetchOptions{BinarySection: []*imap.FetchItemBinarySection{{Part: []int{2}}}, BodySection: []*imap.FetchItemBodySection{{Part: []int{2}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, temporary := range []bool{false, true} {
				label := "request cannot fit"
				if temporary {
					label = "other work holds budget"
				}
				t.Run(label, func(t *testing.T) {
					limit := int64(len(body) + 3*len(section)/2)
					held := int64(0)
					want := imap.ResponseCodeLimit
					if temporary {
						limit = int64(len(body) + 3*len(section))
						held = int64(2 * len(section))
						want = imap.ResponseCodeUnavailable
					}
					sess, tracker, msg := newBudgetTestSession(t, limit, body, len(body))
					sess.server.name = t.Name()
					if err := tracker.Allocate(held); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { tracker.Free(held) })
					counter := metrics.SessionMemoryLimitExceeded.WithLabelValues("imap", sess.server.name, sess.server.hostname)
					before := testutil.ToFloat64(counter)
					requireMemoryRefusal(t, fetchItemsBeforeResponse(sess, msg, tc.options), want)
					if got := tracker.Current(); got != held {
						t.Errorf("memory after refusal=%d, want unrelated allocation %d", got, held)
					}
					if got := testutil.ToFloat64(counter) - before; got != 1 {
						t.Errorf("memory refusal metric increased by%v, want1", got)
					}
				})
			}
		})
	}
}

// A retained BINARY chunk can be prepared without loading the message body.
// A subsequent BODY[] must include that owned chunk when its body load fails.
func TestFetch_BodyLoadCountsPreviouslyPreparedCachedChunk(t *testing.T) {
	body := multipartTestMessage(64 * 1024)
	const chunk = 16 * 1024
	sess, tracker, msg := newBudgetTestSession(t, int64(len(body)+chunk/2), body, len(body))
	sess.server.name = t.Name()
	decoded, err := safeDecodeBinarySection(body, &imap.FetchItemBinarySection{Part: []int{2}})
	if err != nil {
		t.Fatal(err)
	}
	charge, ok := sess.chargeSectionCopy(len(decoded))
	if !ok {
		t.Fatal("cannot prepare optional retention")
	}
	if !sess.retainBodySection(binarySectionCacheKey(msg.ContentHash, []int{2}), decoded) {
		sess.freeSectionCopies(charge)
		t.Fatal("section was not retained")
	}
	counter := metrics.SessionMemoryLimitExceeded.WithLabelValues("imap", sess.server.name, sess.server.hostname)
	before := testutil.ToFloat64(counter)
	options := &imap.FetchOptions{BinarySection: []*imap.FetchItemBinarySection{{Part: []int{2}, Partial: &imap.SectionPartial{Size: chunk}}}, BodySection: []*imap.FetchItemBodySection{{}}}
	requireMemoryRefusal(t, fetchItemsBeforeResponse(sess, msg, options), imap.ResponseCodeLimit)
	if got := tracker.Current(); got != 0 {
		t.Errorf("memory after refusal=%d, want0", got)
	}
	if got := testutil.ToFloat64(counter) - before; got != 1 {
		t.Errorf("memory refusal metric increased by%v, want1", got)
	}
}
