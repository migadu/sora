package server

import (
	"net"
	"sync"
	"testing"
	"time"
)

// throughputHarness drives SoraConn.checkTimeouts directly with a synthetic
// clock, so a multi-minute measurement history runs in milliseconds. Bytes go
// through the real Read/Write paths over a net.Pipe so the accounting that the
// check relies on is the production accounting.
type throughputHarness struct {
	t        *testing.T
	conn     *SoraConn
	peer     net.Conn
	now      time.Time
	mu       sync.Mutex
	timeouts []string
}

func newThroughputHarness(t *testing.T, minBytesPerMinute int64) *throughputHarness {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	h := &throughputHarness{t: t, peer: clientSide, now: time.Now()}
	h.conn = NewSoraConn(serverSide, SoraConnConfig{
		Protocol:             "test",
		IdleTimeout:          0,
		AbsoluteTimeout:      24 * time.Hour,
		MinBytesPerMinute:    minBytesPerMinute,
		EnableTimeoutChecker: false, // the test is the scheduler
		OnTimeout: func(_ net.Conn, reason string) {
			h.mu.Lock()
			h.timeouts = append(h.timeouts, reason)
			h.mu.Unlock()
		},
	})
	// Start past the two-minute post-handshake grace so every window counts.
	h.conn.mu.Lock()
	h.conn.sessionStart = h.now.Add(-10 * time.Minute)
	h.conn.lastThroughputCheck = h.now
	h.conn.mu.Unlock()
	t.Cleanup(func() { h.conn.Close(); clientSide.Close() })
	return h
}

// clientSends pushes bytes from the peer into the server-side conn.
func (h *throughputHarness) clientSends(b []byte) {
	h.t.Helper()
	errc := make(chan error, 1)
	go func() {
		buf := make([]byte, len(b))
		read := 0
		for read < len(b) {
			n, err := h.conn.Read(buf[read:])
			if err != nil {
				errc <- err
				return
			}
			read += n
		}
		errc <- nil
	}()
	if _, err := h.peer.Write(b); err != nil {
		h.t.Fatalf("client write: %v", err)
	}
	if err := <-errc; err != nil {
		h.t.Fatalf("server read: %v", err)
	}
}

// serverSends writes bytes from the server-side conn to the peer.
func (h *throughputHarness) serverSends(b []byte) {
	h.t.Helper()
	errc := make(chan error, 1)
	go func() {
		buf := make([]byte, len(b))
		read := 0
		for read < len(b) {
			n, err := h.peer.Read(buf[read:])
			if err != nil {
				errc <- err
				return
			}
			read += n
		}
		errc <- nil
	}()
	if _, err := h.conn.Write(b); err != nil {
		h.t.Fatalf("server write: %v", err)
	}
	if err := <-errc; err != nil {
		h.t.Fatalf("client read: %v", err)
	}
}

// tick advances the clock past one measurement window and runs the check.
func (h *throughputHarness) tick() {
	h.now = h.now.Add(61 * time.Second)
	h.conn.checkTimeouts(h.now)
}

func (h *throughputHarness) closed() bool {
	h.conn.closeMutex.Lock()
	defer h.conn.closeMutex.Unlock()
	return h.conn.closed
}

// Timeout notification and transport closure run outside the scheduler. Wait for
// the observable closure before asserting a timeout's final state.
func (h *throughputHarness) waitClosed() bool {
	deadline := time.Now().Add(time.Second)
	for !h.closed() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	return h.closed()
}

func (h *throughputHarness) timeoutReasons() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.timeouts...)
}

// A client that completes a tiny command every few seconds (Alpine's NOOP
// poll, any non-IDLE client) moves far fewer than 512 bytes a minute and is
// perfectly healthy. It must never be cut as "too slow".
func TestSoraConnThroughput_CompletedCommandPollerIsNotSlowloris(t *testing.T) {
	h := newThroughputHarness(t, 512)

	for window := 1; window <= 8; window++ {
		// Four NOOP round trips per minute: ~43 bytes each, ~170 bytes/min.
		for i := 0; i < 4; i++ {
			h.clientSends([]byte("00000042 NOOP\r\n"))
			h.serverSends([]byte("00000042 OK NOOP completed\r\n"))
		}
		h.tick()
		if h.closed() {
			t.Fatalf("poller closed after window %d with reasons %v; completed commands are not a slowloris", window, h.timeoutReasons())
		}
	}
}

// Bytes arriving without ever completing a command is the actual slowloris
// signature: the parser is fed, the server never gets to answer.
func TestSoraConnThroughput_TrickledPartialCommandIsDisconnected(t *testing.T) {
	h := newThroughputHarness(t, 512)

	h.clientSends([]byte("0000004")) // first fragment of a command line
	h.tick()
	if h.closed() {
		t.Fatal("one stalled window must not disconnect yet")
	}
	h.clientSends([]byte("2 NO"))
	h.tick()
	if !h.waitClosed() {
		t.Fatal("two consecutive stalled windows must disconnect")
	}
	if got := h.timeoutReasons(); len(got) != 1 || got[0] != "slow_throughput" {
		t.Fatalf("expected one slow_throughput timeout, got %v", got)
	}
}

// A completed command in between resets the stall count.
func TestSoraConnThroughput_ResponseResetsStallCount(t *testing.T) {
	h := newThroughputHarness(t, 512)

	h.clientSends([]byte("0000004"))
	h.tick()
	h.clientSends([]byte("2 NOOP\r\n"))
	h.serverSends([]byte("00000042 OK NOOP completed\r\n"))
	h.tick()
	h.clientSends([]byte("0000004"))
	h.tick()
	if h.closed() {
		t.Fatalf("a window with a server response must reset the stall count; reasons %v", h.timeoutReasons())
	}
	h.clientSends([]byte("3"))
	h.tick()
	if !h.waitClosed() {
		t.Fatal("two consecutive stalled windows after the reset must disconnect")
	}
}

// Silence is the idle timer's business, not the throughput check's. A quiet
// session must not be reported as "too slow" when its idle timeout is longer.
func TestSoraConnThroughput_SilentSessionIsLeftToIdleTimeout(t *testing.T) {
	h := newThroughputHarness(t, 512)

	for window := 1; window <= 6; window++ {
		h.tick()
		if h.closed() {
			t.Fatalf("silent session closed by throughput check after window %d: %v", window, h.timeoutReasons())
		}
	}
}

// A silent window must not wipe out a stall already counted: a client that
// trickled, paused, and trickles again still never completed a command.
func TestSoraConnThroughput_SilentWindowDoesNotResetStallCount(t *testing.T) {
	h := newThroughputHarness(t, 512)

	h.clientSends([]byte("0000004"))
	h.tick()
	h.tick() // silent
	h.clientSends([]byte("2"))
	h.tick()
	if !h.waitClosed() {
		t.Fatal("stall, silence, stall must disconnect: no command ever completed")
	}
}

// Counters zeroed by an IDLE exit between a check's snapshot and its window
// reset must not leave a deficit that hides the next window's input.
func TestSoraConnThroughput_WindowResetClampsAfterResumeRace(t *testing.T) {
	h := newThroughputHarness(t, 512)

	h.clientSends([]byte("0000004"))  // 7 bytes observed by the check's snapshot
	h.serverSends([]byte("+ go\r\n")) // 6 bytes
	h.conn.ResumeThroughputChecking() // zeroes the counters after the snapshot
	h.conn.openNextThroughputWindow(h.now, 7, 6)

	h.conn.mu.RLock()
	read, written := h.conn.bytesRead, h.conn.bytesWritten
	h.conn.mu.RUnlock()
	if read != 0 || written != 0 {
		t.Fatalf("window reset must clamp at zero after a Resume race, got read=%d written=%d", read, written)
	}

	// Bytes that landed between the snapshot and the reset must survive it.
	h.clientSends([]byte("late"))
	h.conn.openNextThroughputWindow(h.now, 0, 0)
	h.conn.mu.RLock()
	read = h.conn.bytesRead
	h.conn.mu.RUnlock()
	if read != 4 {
		t.Fatalf("bytes landing after the snapshot must carry into the next window, got %d", read)
	}
}
