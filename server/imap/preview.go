package imap

import (
	"bytes"
	"container/list"
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	serverPkg "github.com/migadu/sora/server"

	"github.com/migadu/sora/pkg/metrics"
)

// FETCH PREVIEW (RFC 8970) without stored previews.
//
// Nothing is kept in the database: a preview is generated from the message body
// whenever it is asked for, and remembered only in a small in-memory cache keyed
// by content hash. What that costs depends on where the body is, so the sources
// are tried cheapest first:
//
//  1. the in-memory preview cache;
//  2. a body this FETCH already loaded for a BODY[] or BINARY[] item;
//  3. a local copy of the body: the body cache or the upload staging file,
//     checked against the stored size, read through a bounded parser;
//  4. for PREVIEW (LAZY), nothing more: the answer is NIL, which the client
//     can follow with a PREVIEW without LAZY when it wants the text;
//  5. for PREVIEW without LAZY, a download from S3, bounded by a size cutoff,
//     per-account and server-wide budgets and a short deadline. Anything that
//     stops it answers "" (RFC 8970 §3 forbids NIL here), which a client takes
//     as "no preview" for the message.
//
// So listing a mailbox with PREVIEW (LAZY) never reaches S3, and S3 is read only
// for messages a client explicitly asks a preview of.

// PreviewOptions configures FETCH PREVIEW.
type PreviewOptions struct {
	// Enabled advertises the PREVIEW capability. It is opt-in because answering
	// PREVIEW without LAZY can cost an S3 download per message.
	Enabled bool
	// S3PerMin and S3Burst bound how many bodies one account may have downloaded
	// from S3 to answer PREVIEW without LAZY (S3PerMin <= 0: no limit).
	S3PerMin int
	S3Burst  int
	// S3NodePerMin bounds the same downloads for the whole server (<= 0: no limit).
	S3NodePerMin int
	// S3MaxSize is the largest body downloaded for a preview; larger messages get
	// an empty preview unless their body is on this node (<= 0: the default).
	S3MaxSize int64
}

const (
	// defaultPreviewS3MaxSize matches the body cache's default max_object_size:
	// a body larger than that is never cached, so each preview would be a
	// fresh download.
	defaultPreviewS3MaxSize = 5 << 20
	// previewS3Timeout bounds one download for a preview. It is short of both
	// the FETCH response writer's deadline and a webmail's request timeout, so
	// a slow S3 costs one empty preview instead of the whole response.
	previewS3Timeout = 8 * time.Second
	// previewLazyLocalMax bounds how many previews one PREVIEW (LAZY) command
	// generates from local files; past it the answer is NIL, which LAZY allows.
	previewLazyLocalMax = 200
	// previewMemReserve is charged to the session memory budget while a preview
	// is parsed from a local file: bounded headers, MIME parser buffers, and the
	// selected text or HTML part (see helpers/preview_input.go).
	previewMemReserve = 2 << 20
	// previewMemoBytes bounds the in-memory preview cache.
	previewMemoBytes = 16 << 20
	// previewNodeKey is the node-wide budget's one bucket.
	previewNodeKey = 0
)

// previewState is the server's share of FETCH PREVIEW.
type previewState struct {
	memo         previewMemo
	accountLimit *serverPkg.SearchRateLimiter
	nodeLimit    *serverPkg.SearchRateLimiter
	s3MaxSize    int64
	closeOnce    sync.Once
}

func newPreviewState(options PreviewOptions) *previewState {
	maxSize := options.S3MaxSize
	if maxSize <= 0 {
		maxSize = defaultPreviewS3MaxSize
	}
	return &previewState{
		memo:         previewMemo{maxBytes: previewMemoBytes},
		accountLimit: serverPkg.NewCommandRateLimiter("IMAP", "", options.S3PerMin, time.Minute, options.S3Burst),
		nodeLimit:    serverPkg.NewCommandRateLimiter("IMAP", "", options.S3NodePerMin, time.Minute, 0),
		s3MaxSize:    maxSize,
	}
}

func (p *previewState) close() {
	if p != nil {
		p.closeOnce.Do(func() {
			p.accountLimit.Stop()
			p.nodeLimit.Stop()
		})
	}
}

// previewRun is one FETCH command's share of FETCH PREVIEW.
type previewRun struct {
	lazyLocalLeft int
	downloads     int
}

func newPreviewRun() *previewRun {
	return &previewRun{lazyLocalLeft: previewLazyLocalMax}
}

// previewWriter is the part of imapserver.FetchResponseWriter that writes a
// PREVIEW, so tests can stand in for it.
type previewWriter interface {
	WritePreview(text string, available bool)
}

// writePreview answers PREVIEW for one message. bodyData and bodyDataFetched
// are the message's body as loaded by this FETCH, shared with the BODY[] items:
// a body downloaded here is left in them so the caller's deferred release frees
// it from the session budget.
func (s *IMAPSession) writePreview(ctx context.Context, w previewWriter, msg *db.Message, lazy bool, run *previewRun, bodyData *[]byte, bodyDataFetched *bool) {
	text, available, source := s.findPreview(ctx, msg, lazy, run, bodyData, bodyDataFetched)
	metrics.IMAPPreviewTotal.WithLabelValues(source).Inc()
	w.WritePreview(text, available)
}

func (s *IMAPSession) findPreview(ctx context.Context, msg *db.Message, lazy bool, run *previewRun, bodyData *[]byte, bodyDataFetched *bool) (text string, available bool, source string) {
	p := s.server.preview
	if p == nil {
		return "", false, "unavailable" // PREVIEW disabled or server not built by New
	}

	// Reuse generated text even when this FETCH also loaded the body. Repeated
	// BODY.PEEK[] + PREVIEW requests must not repeat MIME and HTML parsing.
	if text, ok := p.memo.get(msg.ContentHash); ok {
		return text, true, "memo"
	}

	if *bodyDataFetched {
		if *bodyData == nil {
			// Loading the body already failed for this message; don't try again.
			return "", false, "unavailable"
		}
		text = helpers.MessagePreview(bytes.NewReader(*bodyData))
		p.memo.put(msg.ContentHash, text)
		return text, true, "loaded"
	}

	if !lazy || run.lazyLocalLeft > 0 {
		text, state := s.localPreview(msg)
		switch state {
		case previewLocalFound:
			if lazy {
				run.lazyLocalLeft--
			}
			p.memo.put(msg.ContentHash, text)
			return text, true, "local"
		case previewLocalLimited:
			// The body is already here. A memory refusal must not turn a
			// cheap local preview into a redundant S3 download.
			return "", !lazy, "limited"
		}
	}
	if lazy {
		return "", false, "nil"
	}

	return s.storagePreview(ctx, msg, run, bodyData, bodyDataFetched)
}

type previewLocalState uint8

const (
	previewLocalMiss previewLocalState = iota
	previewLocalFound
	previewLocalLimited
)

// localPreview generates a preview from a copy of the body on this node, if
// there is a whole one.
func (s *IMAPSession) localPreview(msg *db.Message) (string, previewLocalState) {
	if s.server.cache != nil {
		if text, state := s.previewFromFile(s.server.cache.GetPathForContentHash(msg.ContentHash), msg.Size); state != previewLocalMiss {
			return text, state
		}
	}
	if s.server.uploader != nil {
		if text, state := s.previewFromFile(s.server.uploader.FilePath(msg.ContentHash, msg.AccountID), msg.Size); state != previewLocalMiss {
			return text, state
		}
	}
	return "", previewLocalMiss
}

// previewFromFile parses a preview from a local copy of a body. The file is
// opened directly rather than through the body cache, so a probe neither counts
// as a cache hit or miss nor refreshes the entry; a file whose size disagrees
// with the message is a leftover of an interrupted write and is ignored, as
// loadMessageBody ignores it.
func (s *IMAPSession) previewFromFile(path string, size int) (string, previewLocalState) {
	f, err := os.Open(path)
	if err != nil {
		return "", previewLocalMiss
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || !bodyLenMatches(fi.Size(), size) {
		return "", previewLocalMiss
	}
	if !s.memoryAvailable(previewMemReserve) {
		return "", previewLocalLimited
	}
	if s.memTracker != nil {
		if err := s.memTracker.Allocate(previewMemReserve); err != nil {
			return "", previewLocalLimited
		}
		defer s.memTracker.Free(previewMemReserve)
	}
	return helpers.MessagePreview(f), previewLocalFound
}

// storagePreview downloads the body from S3 to answer PREVIEW without LAZY.
func (s *IMAPSession) storagePreview(ctx context.Context, msg *db.Message, run *previewRun, bodyData *[]byte, bodyDataFetched *bool) (string, bool, string) {
	p := s.server.preview
	if !msg.IsUploaded || s.server.s3 == nil {
		// Staged on another node and not uploaded yet: there is nothing to
		// download, and waiting for the upload is not worth a FETCH's time.
		return "", true, "unavailable"
	}
	if msg.Size <= 0 {
		// The normal loader accepts legacy rows without a recorded size, but
		// a preview must know the read fits its download and memory budgets.
		return "", true, "unavailable"
	}
	if int64(msg.Size) > p.s3MaxSize {
		return "", true, "too_large"
	}
	if !s.memoryAvailable(int64(msg.Size)) {
		return "", true, "limited"
	}
	if p.accountLimit.CanSearch(ctx, s.AccountID()) != nil || p.nodeLimit.CanSearch(ctx, previewNodeKey) != nil {
		return "", true, "limited"
	}

	ctx, cancel := context.WithTimeout(ctx, previewS3Timeout)
	defer cancel()
	run.downloads++
	data, err := s.fetchBodyFromS3(ctx, msg)
	if err != nil {
		s.DebugLog("PREVIEW: S3 download failed", "uid", msg.UID, "error", err)
		return "", true, "error"
	}
	if s.memTracker != nil {
		if err := s.memTracker.Allocate(int64(len(data))); err != nil {
			return "", true, "limited"
		}
	}
	*bodyData, *bodyDataFetched = data, true

	text := helpers.MessagePreview(bytes.NewReader(data))
	p.memo.put(msg.ContentHash, text)
	return text, true, "storage"
}

// previewMemo is a least-recently-used cache of generated previews by content
// hash, bounded by the bytes it holds. Sharing entries across accounts is safe:
// it is consulted only for a message the FETCH already authorised, and the same
// hash is the same body.
type previewMemo struct {
	mu       sync.Mutex
	maxBytes int
	bytes    int
	order    list.List // of *previewMemoEntry, most recently used first
	entries  map[string]*list.Element
}

type previewMemoEntry struct {
	hash, text string
}

// previewMemoOverhead approximates the bookkeeping cost of one entry.
const previewMemoOverhead = 96

func (e *previewMemoEntry) size() int {
	return len(e.hash) + len(e.text) + previewMemoOverhead
}

func (m *previewMemo) get(hash string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.entries[hash]
	if !ok {
		return "", false
	}
	m.order.MoveToFront(el)
	return el.Value.(*previewMemoEntry).text, true
}

func (m *previewMemo) put(hash, text string) {
	if hash == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries == nil {
		m.entries = make(map[string]*list.Element)
	}
	if el, ok := m.entries[hash]; ok {
		e := el.Value.(*previewMemoEntry)
		m.bytes += len(text) - len(e.text)
		e.text = strings.Clone(text)
		m.order.MoveToFront(el)
	} else {
		// Both strings may be slices of larger buffers. Own exactly the bytes
		// charged below, including the map key, rather than retain a body.
		e := &previewMemoEntry{hash: strings.Clone(hash), text: strings.Clone(text)}
		m.entries[e.hash] = m.order.PushFront(e)
		m.bytes += e.size()
	}
	for m.bytes > m.maxBytes && m.order.Len() > 0 {
		oldest := m.order.Back()
		e := oldest.Value.(*previewMemoEntry)
		m.order.Remove(oldest)
		delete(m.entries, e.hash)
		m.bytes -= e.size()
	}
}
