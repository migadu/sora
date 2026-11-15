package cluster

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRateLimitHandlerUnregisterReleasesWorkerAndCallback(t *testing.T) {
	m, d := newTestDelegate(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	var calls atomic.Int64
	unregister := m.RegisterRateLimitHandler(func([]byte) { calls.Add(1); close(entered); <-release })
	q := m.rateLimitHandlers[0]
	d.NotifyMsg([]byte{'R', 'L', 1})
	<-entered
	d.NotifyMsg([]byte{'R', 'L', 2})
	done := make(chan struct{})
	go func() { unregister(); close(done) }()
	// Removal precedes waiting: concurrent NotifyMsg cannot enqueue new work.
	for deadline := time.Now().Add(5 * time.Second); ; {
		m.rateLimitMu.RLock()
		n := len(m.rateLimitHandlers)
		m.rateLimitMu.RUnlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("handler remained registered")
		}
		time.Sleep(time.Millisecond)
	}
	for q.ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("unregister returned while its handler was active")
	default:
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("unregister did not finish")
	}
	unregister()
	select {
	case <-q.done:
	default:
		t.Fatal("handler worker is still running")
	}
	if q.handler != nil {
		t.Error("stopped queue retains its callback")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("ran %d callbacks, want only the already-active one", got)
	}
	d.NotifyMsg([]byte{'R', 'L', 3})
}

func TestRateLimitBroadcasterUnregisterRetiresOldSnapshots(t *testing.T) {
	m, _ := newTestDelegate(t)
	var first, second atomic.Int64
	stopFirst := m.RegisterRateLimitBroadcaster(func(int, int) [][]byte { first.Add(1); return nil })
	stopSecond := m.RegisterRateLimitBroadcaster(func(int, int) [][]byte { second.Add(1); return nil })
	old := m.rateLimitBroadcasts[0]
	oldSnapshot := old.get
	stopFirst()
	stopFirst()
	oldSnapshot(0, 100)
	m.getRateLimitBroadcasts(0, 100)
	if first.Load() != 0 || second.Load() != 1 {
		t.Fatalf("retired/live calls=%d/%d, want0/1", first.Load(), second.Load())
	}
	if old.callback != nil {
		t.Error("retired broadcaster retains callback")
	}
	if len(m.rateLimitBroadcasts) != 1 {
		t.Fatal("unregister removed the wrong registrations")
	}
	stopSecond()
	if len(m.rateLimitBroadcasts) != 0 {
		t.Fatal("broadcasters remained registered")
	}
}

func TestRateLimitUnregisterRacesDeliveryAndBroadcast(t *testing.T) {
	m, d := newTestDelegate(t)
	for range 20 {
		stopHandler := m.RegisterRateLimitHandler(func([]byte) {})
		stopBroadcast := m.RegisterRateLimitBroadcaster(func(int, int) [][]byte { return nil })
		done := make(chan struct{})
		started := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.NotifyMsg([]byte{'R', 'L', 1})
			m.getRateLimitBroadcasts(0, 100)
			close(started)
			for {
				select {
				case <-done:
					return
				default:
					d.NotifyMsg([]byte{'R', 'L', 1})
					m.getRateLimitBroadcasts(0, 100)
				}
			}
		}()
		<-started
		stopHandler()
		stopBroadcast()
		close(done)
		wg.Wait()
	}
	if len(m.rateLimitHandlers) != 0 || len(m.rateLimitBroadcasts) != 0 {
		t.Fatal("stopped registrations accumulated")
	}
}

func TestRateLimitBroadcasterUnregisterWaitsOutsideManagerLock(t *testing.T) {
	m, _ := newTestDelegate(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	unregister := m.RegisterRateLimitBroadcaster(func(int, int) [][]byte { close(entered); <-release; return nil })
	broadcastDone := make(chan struct{})
	go func() { defer close(broadcastDone); m.getRateLimitBroadcasts(0, 100) }()
	<-entered
	unregistered := make(chan struct{})
	go func() { unregister(); close(unregistered) }()
	for deadline := time.Now().Add(5 * time.Second); ; {
		m.broadcastMu.RLock()
		remaining := len(m.rateLimitBroadcasts)
		m.broadcastMu.RUnlock()
		if remaining == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("manager lock held while waiting for broadcaster")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-unregistered:
		t.Fatal("unregister returned while broadcaster was active")
	default:
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-unregistered:
	case <-time.After(5 * time.Second):
		t.Fatal("unregister did not finish")
	}
	<-broadcastDone
}
