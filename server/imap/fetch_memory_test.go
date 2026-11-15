package imap

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/db"
	serverPkg "github.com/migadu/sora/server"
)

// multipartTestMessage builds a well-formed multipart/mixed message whose second part
// carries payloadSize bytes. A well-formed message matters: safeExtractBodySection
// returns the ORIGINAL body slice (no second copy) when MIME parsing yields nothing for
// BODY[], so a degenerate message would make the accounting assertions pass vacuously.
func multipartTestMessage(payloadSize int) []byte {
	var b strings.Builder
	b.WriteString("From: sender@example.com\r\n")
	b.WriteString("To: rcpt@example.com\r\n")
	b.WriteString("Subject: memory accounting\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n")
	b.WriteString("\r\n")
	b.WriteString("--BOUNDARY\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString("hello\r\n")
	b.WriteString("--BOUNDARY\r\n")
	b.WriteString("Content-Type: application/octet-stream\r\n")
	b.WriteString("Content-Disposition: attachment; filename=\"payload.bin\"\r\n")
	b.WriteString("\r\n")
	for written := 0; written < payloadSize; written += 64 {
		b.WriteString(strings.Repeat("x", 62))
		b.WriteString("\r\n")
	}
	b.WriteString("--BOUNDARY--\r\n")
	return []byte(b.String())
}

// writtenSection records one WriteBodySection call.
type writtenSection struct {
	declaredSize   int64
	data           []byte
	trackerAtWrite int64 // tracker.Current() at the moment the payload is handed over
}

type fakeBodySectionWriter struct {
	tracker  *serverPkg.SessionMemoryTracker
	sections []writtenSection
}

func (w *fakeBodySectionWriter) WriteBodySection(section *imap.FetchItemBodySection, size int64) io.WriteCloser {
	return &fakeSectionWriteCloser{parent: w, declaredSize: size}
}

type fakeSectionWriteCloser struct {
	parent         *fakeBodySectionWriter
	declaredSize   int64
	buf            bytes.Buffer
	trackerAtWrite int64
}

func (c *fakeSectionWriteCloser) Write(p []byte) (int, error) {
	if c.parent.tracker != nil {
		c.trackerAtWrite = c.parent.tracker.Current()
	}
	return c.buf.Write(p)
}

func (c *fakeSectionWriteCloser) Close() error {
	c.parent.sections = append(c.parent.sections, writtenSection{
		declaredSize:   c.declaredSize,
		data:           c.buf.Bytes(),
		trackerAtWrite: c.trackerAtWrite,
	})
	return nil
}

func fetchTestMessage(body []byte) *db.Message {
	return &db.Message{
		UID:         1,
		AccountID:   7,
		ContentHash: strings.Repeat("a", 64),
		Size:        len(body),
	}
}

func newFetchTestSession(limit int64) (*IMAPSession, *serverPkg.SessionMemoryTracker) {
	tracker := serverPkg.NewSessionMemoryTracker(limit)
	return &IMAPSession{server: &IMAPServer{}, memTracker: tracker}, tracker
}

// bodySectionsBeforeResponse runs, for msg's BODY sections, what
// writeMessageFetchData runs before it sets the message's implicit \Seen and
// opens its response: a refusal there fails the FETCH at this message with
// nothing written and nothing set. write then writes the sections.
func bodySectionsBeforeResponse(s *IMAPSession, bodyData *[]byte, bodyFetched *bool, options *imap.FetchOptions, msg *db.Message) (write func(bodySectionWriter) error, err error) {
	sections, err := s.extractBodySections(context.Background(), bodyData, bodyFetched, options, msg)
	if err != nil {
		return nil, err
	}
	return func(w bodySectionWriter) error {
		defer s.freeSectionCopies(sections.charged)
		return writeBodySections(w, options, sections)
	}, nil
}

// fetchBodySections runs msg's BODY sections through to the write.
func fetchBodySections(s *IMAPSession, w bodySectionWriter, bodyData *[]byte, bodyFetched *bool, options *imap.FetchOptions, msg *db.Message) error {
	write, err := bodySectionsBeforeResponse(s, bodyData, bodyFetched, options, msg)
	if err != nil {
		return err
	}
	return write(w)
}

// TestFetch_BodySectionCopyIsCharged covers FETCH-1(a): the buffer the section extractor
// allocates is a second full copy of the served bytes and must be visible to the session
// memory tracker while it is live.
func TestFetch_BodySectionCopyIsCharged(t *testing.T) {
	body := multipartTestMessage(64 * 1024)
	section := &imap.FetchItemBodySection{Part: []int{2}}

	expected := imapserver.ExtractBodySection(bytes.NewReader(body), section)
	if len(expected) == 0 {
		t.Fatal("test message yielded an empty section; the fixture is not well-formed")
	}
	if len(expected) == len(body) {
		t.Fatal("section equals the whole body; the extractor made no second copy")
	}

	s, tracker := newFetchTestSession(0)
	w := &fakeBodySectionWriter{tracker: tracker}
	bodyData := body
	bodyFetched := true

	options := &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{section}}
	if err := fetchBodySections(s, w, &bodyData, &bodyFetched, options, fetchTestMessage(body)); err != nil {
		t.Fatalf("fetchBodySections: %v", err)
	}

	if len(w.sections) != 1 {
		t.Fatalf("expected 1 written section, got %d", len(w.sections))
	}
	if !bytes.Equal(w.sections[0].data, expected) {
		t.Fatalf("written section differs from the extracted section (%d vs %d bytes)", len(w.sections[0].data), len(expected))
	}
	if got, want := w.sections[0].trackerAtWrite, int64(len(expected)); got != want {
		t.Errorf("memory tracker during write = %d bytes, want %d (the section copy is untracked)", got, want)
	}
	if got := tracker.Current(); got != 0 {
		t.Errorf("memory tracker after write = %d bytes, want 0", got)
	}
}

// TestFetch_SectionOverBudgetIsRefused: once the extractor's copy is charged, a section
// that does not fit the session budget must be refused explicitly. Handing the client an
// empty literal instead would be indistinguishable from a genuinely empty message. A
// section larger than the whole budget can never be fetched: NO [LIMIT].
func TestFetch_SectionOverBudgetIsRefused(t *testing.T) {
	body := multipartTestMessage(64 * 1024)
	section := &imap.FetchItemBodySection{Part: []int{2}}

	s, tracker := newFetchTestSession(1024)
	w := &fakeBodySectionWriter{tracker: tracker}
	bodyData := body
	bodyFetched := true

	err := fetchBodySections(s, w, &bodyData, &bodyFetched,
		&imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{section}}, fetchTestMessage(body))

	requireMemoryRefusal(t, err, imap.ResponseCodeLimit)
	if len(w.sections) != 0 {
		t.Errorf("wrote %d sections for a refused fetch, want 0", len(w.sections))
	}
	if got := tracker.Current(); got != 0 {
		t.Errorf("memory tracker after refusal = %d bytes, want 0", got)
	}
}

// TestFetch_PartialChunksReuseExtractedSection covers FETCH-1(b): a client pulling one
// section in <offset.size> chunks must not reload and re-extract the whole message for
// every chunk. The second chunk is issued with no body available (as a separate FETCH
// command would be), so it can only be answered from what the session retained.
func TestFetch_PartialChunksReuseExtractedSection(t *testing.T) {
	body := multipartTestMessage(64 * 1024)
	full := imapserver.ExtractBodySection(bytes.NewReader(body), &imap.FetchItemBodySection{Part: []int{2}})
	const chunk = 16 * 1024
	if len(full) < 2*chunk {
		t.Fatalf("fixture section too small: %d bytes", len(full))
	}

	s, tracker := newFetchTestSession(0)
	msg := fetchTestMessage(body)

	first := &imap.FetchItemBodySection{Part: []int{2}, Partial: &imap.SectionPartial{Offset: 0, Size: chunk}}
	w1 := &fakeBodySectionWriter{tracker: tracker}
	bodyData := body
	bodyFetched := true
	if err := fetchBodySections(s, w1, &bodyData, &bodyFetched,
		&imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{first}}, msg); err != nil {
		t.Fatalf("first chunk: %v", err)
	}
	if len(w1.sections) != 1 || !bytes.Equal(w1.sections[0].data, full[:chunk]) {
		t.Fatalf("first chunk mismatch: got %d bytes", len(w1.sections[0].data))
	}

	// Second chunk: a fresh command, and this time the body cannot be loaded at all.
	second := &imap.FetchItemBodySection{Part: []int{2}, Partial: &imap.SectionPartial{Offset: chunk, Size: chunk}}
	w2 := &fakeBodySectionWriter{tracker: tracker}
	var noBody []byte
	noBodyFetched := false
	// Nor does what runs ahead of the response, which loads the body for
	// sections the retained one cannot answer.
	write, err := bodySectionsBeforeResponse(s, &noBody, &noBodyFetched,
		&imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{second}}, msg)
	if err != nil {
		t.Fatalf("second chunk before the response: %v", err)
	}
	if noBodyFetched {
		t.Fatal("loading ahead of the second chunk consulted the body loader; the retained section answers it")
	}
	if err := write(w2); err != nil {
		t.Fatalf("second chunk: %v", err)
	}
	if len(w2.sections) != 1 {
		t.Fatalf("expected 1 written section, got %d", len(w2.sections))
	}
	if !bytes.Equal(w2.sections[0].data, full[chunk:2*chunk]) {
		t.Errorf("second chunk = %d bytes, want %d (the message was reloaded and re-extracted instead of reusing the section)",
			len(w2.sections[0].data), chunk)
	}
	if noBodyFetched {
		t.Error("second chunk consulted the body loader; the retained section should have answered it")
	}

	// What the session retains between the chunks stays charged, and is given back
	// when the mailbox selection is dropped.
	if got, want := tracker.Current(), int64(len(full)); got != want {
		t.Errorf("retained section charge = %d bytes, want %d", got, want)
	}
	s.mutex.Lock()
	s.clearSelectedMailboxStateLocked()
	s.mutex.Unlock()
	if got := tracker.Current(); got != 0 {
		t.Errorf("memory tracker after clearing mailbox state = %d bytes, want 0", got)
	}
}

// TestFetch_PartialOfMalformedBodyIsSliced guards the fallback path: BODY[] on a message
// the MIME parser cannot read still honours <offset.size> rather than returning
// everything the client did not ask for.
func TestFetch_PartialOfMalformedBodyIsSliced(t *testing.T) {
	body := []byte("this is not a message")
	section := &imap.FetchItemBodySection{Partial: &imap.SectionPartial{Offset: 5, Size: 4}}

	s, tracker := newFetchTestSession(0)
	w := &fakeBodySectionWriter{tracker: tracker}
	bodyData := body
	bodyFetched := true
	if err := fetchBodySections(s, w, &bodyData, &bodyFetched,
		&imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{section}}, fetchTestMessage(body)); err != nil {
		t.Fatalf("fetchBodySections: %v", err)
	}
	if len(w.sections) != 1 {
		t.Fatalf("expected 1 written section, got %d", len(w.sections))
	}
	if got, want := string(w.sections[0].data), "is n"; got != want {
		t.Errorf("partial of malformed body = %q, want %q", got, want)
	}
}

// TestFetch_FullBodyOfMalformedMessageIsVerbatim guards the same fallback for a
// BODY[] with no <offset.size>: the MIME parser tolerates a malformed header block
// and hands back only the "\r\n" that terminates an empty header, so a fallback
// keyed on an empty extraction would silently serve 2 bytes for the whole message.
func TestFetch_FullBodyOfMalformedMessageIsVerbatim(t *testing.T) {
	body := []byte("this is not a message")

	s, tracker := newFetchTestSession(0)
	w := &fakeBodySectionWriter{tracker: tracker}
	bodyData := body
	bodyFetched := true
	if err := fetchBodySections(s, w, &bodyData, &bodyFetched,
		&imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{}}}, fetchTestMessage(body)); err != nil {
		t.Fatalf("fetchBodySections: %v", err)
	}
	if len(w.sections) != 1 {
		t.Fatalf("expected 1 written section, got %d", len(w.sections))
	}
	if got := w.sections[0].data; !bytes.Equal(got, body) {
		t.Errorf("BODY[] of malformed message = %q, want the message verbatim %q", got, body)
	}
}
