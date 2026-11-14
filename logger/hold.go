package logger

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
)

// held keeps what is logged between Hold and Initialize; nil when nothing is held.
var held atomic.Pointer[heldRecords]

// Hold keeps what is logged from now on, through this package, slog's default logger or
// the standard log package, until Initialize writes it to the configured output at the
// configured level. sora reads the file that configures its logging before it can call
// Initialize, and the warnings about that file are logged while it is read: without Hold
// they went to stderr whatever [logging] output and level said. A process that stops
// before Initialize writes what is held to stderr with Sync. Hold does nothing once
// Initialize has run or while it already holds.
func Hold() {
	if globalLogger.Load() != nil {
		return
	}
	h := &heldRecords{}
	if !held.CompareAndSwap(nil, h) {
		return
	}
	slog.SetDefault(slog.New(holdHandler{held: h, derive: sameHandler}))
}

// release writes what is held to out and stops holding.
func release(out slog.Handler) {
	if h := held.Swap(nil); h != nil {
		h.release(out)
	}
}

type heldRecords struct {
	mu      sync.Mutex
	records []heldRecord
	out     slog.Handler // set by release; a logger taken while holding then writes here
}

type heldRecord struct {
	derive func(slog.Handler) slog.Handler
	record slog.Record
}

func (h *heldRecords) release(out slog.Handler) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		_ = handle(context.Background(), r.derive(out), r.record)
	}
	h.records = nil
	h.out = out
}

func handle(ctx context.Context, h slog.Handler, r slog.Record) error {
	if !h.Enabled(ctx, r.Level) {
		return nil
	}
	return h.Handle(ctx, r)
}

// holdHandler is slog's default handler while records are held. The level is not known
// yet, so it keeps every record; release filters them by the handler it writes to.
type holdHandler struct {
	held *heldRecords
	// derive applies the WithAttrs and WithGroup calls this handler was made by to the
	// handler the records are released to.
	derive func(slog.Handler) slog.Handler
}

func sameHandler(h slog.Handler) slog.Handler { return h }

func (h holdHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h holdHandler) Handle(ctx context.Context, r slog.Record) error {
	h.held.mu.Lock()
	out := h.held.out
	if out == nil {
		h.held.records = append(h.held.records, heldRecord{derive: h.derive, record: r.Clone()})
	}
	h.held.mu.Unlock()
	if out == nil {
		return nil
	}
	return handle(ctx, h.derive(out), r)
}

func (h holdHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	derive := h.derive
	return holdHandler{held: h.held, derive: func(out slog.Handler) slog.Handler { return derive(out).WithAttrs(attrs) }}
}

func (h holdHandler) WithGroup(name string) slog.Handler {
	derive := h.derive
	return holdHandler{held: h.held, derive: func(out slog.Handler) slog.Handler { return derive(out).WithGroup(name) }}
}
