package imap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	serverPkg "github.com/migadu/sora/server"
)

// requireMemoryUnavailable fails t unless err is NO [UNAVAILABLE], the answer to
// a body or section the session memory budget cannot hold.
func requireMemoryUnavailable(t *testing.T, err error) {
	t.Helper()
	var imapErr *imap.Error
	if !errors.As(err, &imapErr) {
		t.Fatalf("error = %v, want NO [UNAVAILABLE]", err)
	}
	if imapErr.Type != imap.StatusResponseTypeNo || imapErr.Code != imap.ResponseCodeUnavailable {
		t.Fatalf("error = %v [%v], want NO [UNAVAILABLE]", imapErr.Type, imapErr.Code)
	}
}

// TestFetch_BodyOverSessionBudgetIsRefused: a body the session memory budget
// cannot hold fails the FETCH at its message with NO [UNAVAILABLE], before the
// message's response is opened and its implicit \Seen set, as a section copy the
// budget refuses does (#1256). An empty BODY[] literal, or empty BINARY[] data
// with BINARY.SIZE 0, for a body that exists is wrong data the client caches as
// the message. The budget refuses the body before reading it when the message
// size is known, and after reading it otherwise.
func TestFetch_BodyOverSessionBudgetIsRefused(t *testing.T) {
	body := multipartTestMessage(64 * 1024)

	// newSession returns a session with a 1 KiB budget, whose body cache holds
	// the message, and the message with the given size.
	newSession := func(t *testing.T, size int) (*IMAPSession, *serverPkg.SessionMemoryTracker, *db.Message) {
		s, tracker := newFetchTestSession(1024)
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
					s, tracker, msg := newSession(t, size.size)
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
					requireMemoryUnavailable(t, err)
					if got := tracker.Current(); got != 0 {
						t.Errorf("memory tracker after refusal = %d bytes, want 0", got)
					}
				})
			}

			t.Run("BINARY[2] BINARY.SIZE[2]", func(t *testing.T) {
				s, tracker, msg := newSession(t, size.size)
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
				requireMemoryUnavailable(t, err)
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
// \Seen though its body was never sent.
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
			requireMemoryUnavailable(t, err)
			if got := tracker.Current(); got != 0 {
				t.Errorf("memory tracker after refusal = %d bytes, want 0", got)
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
