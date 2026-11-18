package imaptest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func ftsPeerSession(t *testing.T, ctx context.Context, budget time.Duration, reply func(int, string, string) string) (*Session, *atomic.Int64) {
	t.Helper()
	local, remote := net.Pipe()
	c := &Client{conn: local, reader: bufio.NewReader(local), ctx: ctx, cfg: Config{CommandTimeout: 5 * time.Second}}
	var searches atomic.Int64
	done := make(chan error, 1)
	go func() {
		defer remote.Close()
		r := bufio.NewReader(remote)
		for {
			tag, command, err := wireReadCommand(r)
			if err != nil {
				done <- err
				return
			}
			n := int(searches.Load())
			if strings.HasPrefix(command, "SEARCH ") {
				n = int(searches.Add(1))
			}
			response := reply(n, tag, command)
			if response == "" {
				_, err := io.Copy(io.Discard, remote)
				done <- err
				return
			}
			if _, err := io.WriteString(remote, response); err != nil {
				done <- err
				return
			}
		}
	}()
	t.Cleanup(func() {
		c.Close()
		remote.Close()
		if err := <-done; err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("FTS peer: %v", err)
		}
	})
	return &Session{Client: c, ctx: ctx, cfg: Config{FTSTimeout: budget}}, &searches
}

func ftsSearchReply(tag string, ids ...uint64) string {
	var out strings.Builder
	out.WriteString("* SEARCH")
	for _, id := range ids {
		fmt.Fprintf(&out, " %d", id)
	}
	fmt.Fprintf(&out, "\r\n%s OK searched\r\n", tag)
	return out.String()
}

func TestFTSWaitAllowsPartialIndexingThenKeepsConnectionUsable(t *testing.T) {
	s, calls := ftsPeerSession(t, context.Background(), time.Second, func(n int, tag, command string) string {
		if command == "NOOP" {
			return tag + " OK alive\r\n"
		}
		switch n {
		case 1:
			return ftsSearchReply(tag)
		case 2:
			return ftsSearchReply(tag, 1)
		default:
			return ftsSearchReply(tag, 2, 1)
		}
	})
	if err := waitForIndexingEvery(s, "OR BODY alpha BODY beta", time.Millisecond, 1, 2); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("readiness polls=%d, want3", calls.Load())
	}
	if _, err := s.Client.OK("NOOP"); err != nil {
		t.Fatalf("successful readiness closed/interrupted connection: %v", err)
	}
}

func TestFTSWaitNeverReadyHasBoundedAssertionDiagnostic(t *testing.T) {
	s, _ := ftsPeerSession(t, context.Background(), 25*time.Millisecond, func(_ int, tag, _ string) string { return ftsSearchReply(tag, 1) })
	start := time.Now()
	err := waitForIndexingEvery(s, "BODY alpha", time.Millisecond, 1, 2)
	var assertion *AssertionError
	if !errors.As(err, &assertion) || !strings.Contains(err.Error(), "last matches [1], want [1 2]") {
		t.Fatalf("missing readiness assertion diagnostic: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("FTS wait exceeded its bound")
	}
}

func TestFTSWaitBoundsAnUnresponsiveSearch(t *testing.T) {
	s, _ := ftsPeerSession(t, context.Background(), 25*time.Millisecond, func(int, string, string) string { return "" })
	start := time.Now()
	err := waitForIndexingEvery(s, "BODY alpha", time.Millisecond, 1)
	var assertion *AssertionError
	if !errors.As(err, &assertion) {
		t.Fatalf("deadline must report readiness assertion: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("inflight SEARCH used command timeout rather than FTS deadline")
	}
}

func TestFTSWaitSupportsControlledClientWithoutParentContext(t *testing.T) {
	s, _ := ftsPeerSession(t, nil, 20*time.Millisecond, func(int, string, string) string { return "" })
	var assertion *AssertionError
	if err := waitForIndexingEvery(s, "BODY alpha", time.Millisecond, 1); !errors.As(err, &assertion) {
		t.Fatalf("background fallback deadline: %v", err)
	}
}

func TestFTSWaitParentCancellationInterruptsSearch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	s, _ := ftsPeerSession(t, ctx, time.Second, func(int, string, string) string { close(started); return "" })
	done := make(chan error, 1)
	go func() { done <- waitForIndexingEvery(s, "BODY alpha", time.Millisecond, 1) }()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("parent cancel=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt SEARCH")
	}
}

func TestFTSWaitDoesNotRetryRefusalsOrInvalidMatches(t *testing.T) {
	for _, tc := range []struct{ name, reply string }{
		{"limit", "%s NO [LIMIT] too many searches\r\n"},
		{"unexpected-id", "* SEARCH 1 9\r\n%s OK searched\r\n"},
		{"duplicate", "* SEARCH 1 1\r\n%s OK searched\r\n"},
		{"missing-search", "%s OK searched\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, calls := ftsPeerSession(t, context.Background(), time.Second, func(_ int, tag, _ string) string { return fmt.Sprintf(tc.reply, tag) })
			if err := waitForIndexingEvery(s, "BODY alpha", time.Millisecond, 1); err == nil {
				t.Fatal("invalid readiness response passed")
			}
			if calls.Load() != 1 {
				t.Fatalf("non-readiness failure retried %d times", calls.Load())
			}
		})
	}
}

func TestFTSReadinessDoesNotReplaceLaterAssertions(t *testing.T) {
	s, _ := ftsPeerSession(t, context.Background(), time.Second, func(n int, tag, _ string) string {
		if n == 1 {
			return ftsSearchReply(tag, 1)
		}
		return ftsSearchReply(tag)
	})
	if err := waitForIndexingEvery(s, "BODY alpha", time.Millisecond, 1); err != nil {
		t.Fatal(err)
	}
	if err := coreSearch(s.Client, "BODY alpha", 1); err == nil {
		t.Fatal("readiness result incorrectly replaced the later case assertion")
	}
}
