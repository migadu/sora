package cluster

import (
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// Gossip delivery runs on memberlist's packet receive loop, and every
// connection and IP handler on this bus serializes on a tracker mutex that the
// accept path also takes. Delivery therefore has to be bounded in both
// goroutines and retained memory: a handler that is slow or wedged behind that
// mutex must cost dropped events, not one goroutine and one buffer per message.

// TestGossipDeliveryDoesNotSpawnGoroutinePerMessage drives a burst of messages
// at a wedged handler and asserts the goroutine count does not grow with the
// burst.
func TestGossipDeliveryDoesNotSpawnGoroutinePerMessage(t *testing.T) {
	m, d := newTestDelegate(t)

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	m.RegisterConnectionHandler(func([]byte) { <-release })

	// Settle so the baseline already counts whatever registration started.
	time.Sleep(100 * time.Millisecond)
	base := runtime.NumGoroutine()

	const messages = 500
	for i := 0; i < messages; i++ {
		d.NotifyMsg([]byte{'C', 'N', byte(i)})
	}
	time.Sleep(300 * time.Millisecond)

	growth := runtime.NumGoroutine() - base
	if growth > messages/10 {
		t.Errorf("delivering %d gossip messages to one wedged handler left %d extra goroutines "+
			"(baseline %d); delivery must not spawn per message, or gossip volume turns handler "+
			"contention into unbounded goroutine growth", messages, growth, base)
	}
	t.Logf("extra goroutines after %d messages to a wedged handler: %d", messages, growth)
}

// TestGossipDeliveryDropsEventsForWedgedHandler asserts the retained backlog is
// bounded: a handler that has stopped consuming must lose events rather than
// have every message held for it.
func TestGossipDeliveryDropsEventsForWedgedHandler(t *testing.T) {
	m, d := newTestDelegate(t)

	release := make(chan struct{})
	var invocations atomic.Int64
	m.RegisterConnectionHandler(func([]byte) {
		invocations.Add(1)
		<-release
	})

	const messages = 2000
	for i := 0; i < messages; i++ {
		d.NotifyMsg([]byte{'C', 'N', byte(i)})
	}

	time.Sleep(200 * time.Millisecond)
	close(release)

	// Let everything that was retained run to completion.
	deadline := time.Now().Add(5 * time.Second)
	var settled int64
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		if got := invocations.Load(); got == settled {
			break
		} else {
			settled = got
		}
	}

	got := invocations.Load()
	if got == 0 {
		t.Fatal("setup problem: the wedged handler was never invoked at all")
	}
	if got > messages/2 {
		t.Errorf("a wedged handler eventually ran %d of %d gossip messages; a handler that stopped "+
			"consuming must degrade to dropped events, not retain the whole burst", got, messages)
	}
	t.Logf("invocations that survived a %d-message burst at a wedged handler: %d", messages, got)
}

// TestGossipDeliveryCopiesReceiveBuffer covers memberlist's NotifyMsg contract:
// "the byte slice may be modified after the call returns, so it should be
// copied if needed". Delivery outlives the call, so the payload has to be
// copied before it is handed on.
func TestGossipDeliveryCopiesReceiveBuffer(t *testing.T) {
	m, d := newTestDelegate(t)

	entered := make(chan struct{})
	release := make(chan struct{})
	got := make(chan string, 1)
	m.RegisterConnectionHandler(func(b []byte) {
		close(entered)
		<-release
		got <- string(b)
	})

	buf := []byte{'C', 'N', 'p', 'a', 'y'}
	d.NotifyMsg(buf)

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("setup problem: NotifyMsg did not reach the registered connection handler")
	}

	// memberlist reuses the receive buffer once NotifyMsg has returned.
	copy(buf[2:], "XXX")
	close(release)

	select {
	case payload := <-got:
		if payload != "pay" {
			t.Errorf("handler saw %q, want %q: the receive buffer was aliased, not copied", payload, "pay")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler never reported the payload it was given")
	}
}
