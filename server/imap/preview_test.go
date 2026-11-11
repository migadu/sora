package imap

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/storage"
)

const previewTestBody = "From: a@example.com\r\nSubject: hi\r\nContent-Type: text/plain\r\n\r\nLunch at noon?\r\n"

type recordedPreview struct {
	text      string
	available bool
}

type fakePreviewWriter struct {
	written []recordedPreview
}

func (w *fakePreviewWriter) WritePreview(text string, available bool) {
	w.written = append(w.written, recordedPreview{text, available})
}

// newPreviewTestSession returns a session on a server with a real body cache in
// a temporary directory, and an S3 stub that fails every download.
func newPreviewTestSession(t *testing.T, options PreviewOptions) *IMAPSession {
	t.Helper()
	c, err := cache.New(t.TempDir(), 1<<20, 1<<20, time.Hour, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	addr, err := serverPkg.NewAddress("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	return &IMAPSession{
		server: &IMAPServer{
			cache:   c,
			s3:      resilient.NewResilientS3Storage(&storage.S3Storage{}),
			preview: newPreviewState(options),
		},
		IMAPUser:   NewIMAPUser(addr, 7),
		memTracker: serverPkg.NewSessionMemoryTracker(64 << 20),
	}
}

func previewTestMessage(uploaded bool) *db.Message {
	return &db.Message{
		UID:         1,
		AccountID:   7,
		ContentHash: strings.Repeat("ab", 32),
		Size:        len(previewTestBody),
		IsUploaded:  uploaded,
		S3Domain:    "example.com",
		S3Localpart: "user",
	}
}

func putCacheFile(t *testing.T, s *IMAPSession, hash, body string) {
	t.Helper()
	path := s.server.cache.GetPathForContentHash(hash)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (s *IMAPSession) previewOnce(msg *db.Message, lazy bool, run *previewRun) (recordedPreview, string) {
	var bodyData []byte
	var fetched bool
	text, available, source := s.findPreview(context.Background(), msg, lazy, run, &bodyData, &fetched)
	return recordedPreview{text, available}, source
}

func TestPreviewSources(t *testing.T) {
	t.Run("LAZY without a local body is NIL and downloads nothing", func(t *testing.T) {
		s := newPreviewTestSession(t, PreviewOptions{Enabled: true})
		run := newPreviewRun()
		got, source := s.previewOnce(previewTestMessage(true), true, run)
		if got.available || source != "nil" || run.downloads != 0 {
			t.Errorf("got %+v from %q with %d downloads, want NIL from nil with none", got, source, run.downloads)
		}
	})

	t.Run("LAZY from the body cache", func(t *testing.T) {
		s := newPreviewTestSession(t, PreviewOptions{Enabled: true})
		msg := previewTestMessage(true)
		putCacheFile(t, s, msg.ContentHash, previewTestBody)
		got, source := s.previewOnce(msg, true, newPreviewRun())
		if got != (recordedPreview{"Lunch at noon?", true}) || source != "local" {
			t.Errorf("got %+v from %q, want the text from local", got, source)
		}
		// A second message with the same body is answered from memory.
		if got, source := s.previewOnce(msg, true, newPreviewRun()); got.text != "Lunch at noon?" || source != "memo" {
			t.Errorf("second answer %+v from %q, want the text from memo", got, source)
		}
	})

	t.Run("a truncated cache file is a miss", func(t *testing.T) {
		s := newPreviewTestSession(t, PreviewOptions{Enabled: true})
		msg := previewTestMessage(true)
		putCacheFile(t, s, msg.ContentHash, previewTestBody[:20])
		if got, source := s.previewOnce(msg, true, newPreviewRun()); got.available || source != "nil" {
			t.Errorf("got %+v from %q, want NIL", got, source)
		}
	})

	t.Run("LAZY stops generating past its per-command cap", func(t *testing.T) {
		s := newPreviewTestSession(t, PreviewOptions{Enabled: true})
		msg := previewTestMessage(true)
		putCacheFile(t, s, msg.ContentHash, previewTestBody)
		run := newPreviewRun()
		run.lazyLocalLeft = 0
		if got, source := s.previewOnce(msg, true, run); got.available || source != "nil" {
			t.Errorf("got %+v from %q, want NIL past the cap", got, source)
		}
		// Without LAZY the cap does not apply: the client must get the text.
		if got, source := s.previewOnce(msg, false, run); got.text != "Lunch at noon?" || source != "local" {
			t.Errorf("without LAZY got %+v from %q, want the text from local", got, source)
		}
	})

	t.Run("a body the FETCH already loaded", func(t *testing.T) {
		s := newPreviewTestSession(t, PreviewOptions{Enabled: true})
		body, fetched := []byte(previewTestBody), true
		text, available, source := s.findPreview(context.Background(), previewTestMessage(true), true, newPreviewRun(), &body, &fetched)
		if text != "Lunch at noon?" || !available || source != "loaded" {
			t.Errorf("got %q %v from %q, want the text from loaded", text, available, source)
		}
	})

	t.Run("a body that failed to load is not loaded again", func(t *testing.T) {
		s := newPreviewTestSession(t, PreviewOptions{Enabled: true})
		var body []byte
		fetched := true
		run := newPreviewRun()
		_, available, source := s.findPreview(context.Background(), previewTestMessage(true), false, run, &body, &fetched)
		if available || source != "unavailable" || run.downloads != 0 {
			t.Errorf("got available=%v from %q with %d downloads, want unavailable and no download", available, source, run.downloads)
		}
	})

	t.Run("without LAZY, a body not uploaded and not here is empty", func(t *testing.T) {
		s := newPreviewTestSession(t, PreviewOptions{Enabled: true})
		run := newPreviewRun()
		got, source := s.previewOnce(previewTestMessage(false), false, run)
		if got != (recordedPreview{"", true}) || source != "unavailable" || run.downloads != 0 {
			t.Errorf("got %+v from %q with %d downloads, want \"\" from unavailable", got, source, run.downloads)
		}
	})

	t.Run("without LAZY, a large body is not downloaded", func(t *testing.T) {
		s := newPreviewTestSession(t, PreviewOptions{Enabled: true, S3MaxSize: 10})
		run := newPreviewRun()
		got, source := s.previewOnce(previewTestMessage(true), false, run)
		if got != (recordedPreview{"", true}) || source != "too_large" || run.downloads != 0 {
			t.Errorf("got %+v from %q with %d downloads, want \"\" from too_large", got, source, run.downloads)
		}
	})

	t.Run("without LAZY, a failed download is empty and not remembered", func(t *testing.T) {
		s := newPreviewTestSession(t, PreviewOptions{Enabled: true})
		msg := previewTestMessage(true)
		run := newPreviewRun()
		got, source := s.previewOnce(msg, false, run)
		if got != (recordedPreview{"", true}) || source != "error" || run.downloads != 1 {
			t.Errorf("got %+v from %q with %d downloads, want \"\" from error after one", got, source, run.downloads)
		}
		if _, ok := s.server.preview.memo.get(msg.ContentHash); ok {
			t.Errorf("a failed download was remembered")
		}
		if n := s.memTracker.Current(); n != 0 {
			t.Errorf("session memory still charged %d bytes", n)
		}
	})

	t.Run("without LAZY, the account budget", func(t *testing.T) {
		s := newPreviewTestSession(t, PreviewOptions{Enabled: true, S3PerMin: 1, S3Burst: 1})
		run := newPreviewRun()
		s.previewOnce(previewTestMessage(true), false, run) // spends the budget
		got, source := s.previewOnce(previewTestMessage(true), false, run)
		if got != (recordedPreview{"", true}) || source != "limited" || run.downloads != 1 {
			t.Errorf("got %+v from %q after %d downloads, want \"\" from limited after one", got, source, run.downloads)
		}
	})

	t.Run("without LAZY, the server budget", func(t *testing.T) {
		s := newPreviewTestSession(t, PreviewOptions{Enabled: true, S3NodePerMin: 1})
		run := newPreviewRun()
		s.previewOnce(previewTestMessage(true), false, run)
		if _, source := s.previewOnce(previewTestMessage(true), false, run); source != "limited" {
			t.Errorf("got %q, want limited", source)
		}
	})

	t.Run("a server not built by New", func(t *testing.T) {
		s := &IMAPSession{server: &IMAPServer{}}
		if got, source := s.previewOnce(previewTestMessage(true), false, newPreviewRun()); got.available || source != "unavailable" {
			t.Errorf("got %+v from %q, want unavailable", got, source)
		}
	})
}

func TestWritePreviewCountsAndWrites(t *testing.T) {
	s := newPreviewTestSession(t, PreviewOptions{Enabled: true})
	w := &fakePreviewWriter{}
	var body []byte
	var fetched bool
	s.writePreview(context.Background(), w, previewTestMessage(true), true, newPreviewRun(), &body, &fetched)
	if len(w.written) != 1 || w.written[0].available {
		t.Errorf("wrote %+v, want one unavailable preview", w.written)
	}
}

func TestPreviewMemoReusedWithLoadedBody(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
		text string
	}{
		{name: "loaded body", body: []byte(previewTestBody), text: "Remembered preview"},
		{name: "loaded body with empty preview", body: []byte(previewTestBody)},
		{name: "failed body load", text: "Remembered preview"},
		{name: "failed body load with empty preview"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newPreviewTestSession(t, PreviewOptions{Enabled: true})
			msg := previewTestMessage(true)
			s.server.preview.memo.put(msg.ContentHash, tc.text)
			body, fetched := tc.body, true
			run := newPreviewRun()
			// BODY.PEEK[] and PREVIEW share the loaded body. A remembered
			// preview must avoid parsing it again, even when loading it failed.
			text, available, source := s.findPreview(context.Background(), msg, false, run, &body, &fetched)
			if text != tc.text || !available || source != "memo" {
				t.Errorf("got %q %v from %q, want %q from memo", text, available, source, tc.text)
			}
			if run.downloads != 0 || run.lazyLocalLeft != previewLazyLocalMax {
				t.Errorf("memo consumed generation resources: %+v", run)
			}
		})
	}
}

func TestPreviewFromFileReleasesItsReservation(t *testing.T) {
	s := newPreviewTestSession(t, PreviewOptions{Enabled: true})
	path := filepath.Join(t.TempDir(), "body")
	if err := os.WriteFile(path, []byte(previewTestBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if text, ok := s.previewFromFile(path, len(previewTestBody)); !ok || text != "Lunch at noon?" {
		t.Errorf("previewFromFile() = %q, %v", text, ok)
	}
	if n := s.memTracker.Current(); n != 0 {
		t.Errorf("session memory still charged %d bytes", n)
	}
	if _, ok := s.previewFromFile(path, len(previewTestBody)+1); ok {
		t.Errorf("a file of the wrong size was used")
	}
	if _, ok := s.previewFromFile(filepath.Dir(path), 0); ok {
		t.Errorf("a directory was used")
	}

	tight := newPreviewTestSession(t, PreviewOptions{Enabled: true})
	tight.memTracker = serverPkg.NewSessionMemoryTracker(previewMemReserve - 1)
	if _, ok := tight.previewFromFile(path, len(previewTestBody)); ok {
		t.Errorf("a preview was parsed beyond the session memory budget")
	}
}

func TestPreviewMemoIsBoundedByBytes(t *testing.T) {
	m := previewMemo{maxBytes: 3 * (64 + 10 + previewMemoOverhead)}
	hash := func(i int) string { return strings.Repeat(string(rune('a'+i)), 64) }
	for i := 0; i < 5; i++ {
		m.put(hash(i), strings.Repeat("x", 10))
	}
	if m.bytes > m.maxBytes {
		t.Errorf("memo holds %d bytes, over its %d", m.bytes, m.maxBytes)
	}
	for i, want := range []bool{false, false, true, true, true} {
		if _, ok := m.get(hash(i)); ok != want {
			t.Errorf("entry %d present = %v, want %v", i, ok, want)
		}
	}
	m.put(hash(2), "") // updating an entry keeps the accounting right
	m.put(hash(5), strings.Repeat("y", 10))
	if _, ok := m.get(hash(2)); !ok {
		t.Errorf("the most recently used entry was evicted")
	}
	if m.bytes > m.maxBytes {
		t.Errorf("memo holds %d bytes, over its %d", m.bytes, m.maxBytes)
	}
}
