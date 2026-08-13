package proxy

import (
	"sync"
	"testing"
	"time"
)

// TestConnectionManagerHealthConcurrency is a race-detector probe over the backend-health
// state, which is read on every routing decision and written on every connection outcome -
// i.e. concurrently, on every proxy, continuously.
//
// It exists because that state is a map of POINTERS (map[string]*BackendHealth). A reader
// that copies the pointer out under the read lock and dereferences it afterwards, or a
// helper that returns the pointer to a caller, reads fields a writer may be mutating in
// place - and neither the compiler nor a normal test can see it. Only -race can.
//
// The assertion is the race detector itself: this test has no expectations about values,
// because health state under concurrent mutation legitimately has no deterministic value.
// It fails only if two goroutines touch the same field without synchronisation.
//
// Run as: go test -race ./server/proxy/ -run TestConnectionManagerHealthConcurrency
func TestConnectionManagerHealthConcurrency(t *testing.T) {
	backends := []string{"backend1:143", "backend2:143", "backend3:143"}

	cm, err := NewConnectionManagerWithRoutingAndStartTLSAndHealthCheck(
		backends, 143, false, false, false, false,
		time.Second, nil, "race-probe", false, /* health checks ENABLED - the whole point */
	)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}

	const goroutines = 8
	const iterations = 300

	var wg sync.WaitGroup
	start := make(chan struct{})

	// Writers: the two paths a live proxy calls on every connection outcome.
	for w := 0; w < goroutines; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				backend := backends[(w+i)%len(backends)]
				if i%2 == 0 {
					cm.RecordConnectionSuccess(backend)
				} else {
					cm.RecordConnectionFailure(backend)
				}
			}
		}(w)
	}

	// Readers: every exported accessor that touches health or the address pool. Each is
	// listed explicitly rather than looped, so a new accessor added without locking is a
	// visible omission here rather than silently uncovered.
	readers := []func(backend string){
		func(b string) { _ = cm.IsBackendHealthy(b) },
		func(b string) { _ = cm.IsBackendHealthyForAffinity(b) },
		func(b string) { _ = cm.IsRemoteLookupBackendHealthy(b) },
		func(b string) { _ = cm.HasHealthyPoolBackends() },
		func(b string) { _ = cm.GetBackendHealthStatuses() },
		func(b string) { _ = cm.HasBackend(b) },
		func(b string) { _, _ = cm.FindPoolBackendByHost("backend1") },
		func(b string) { _ = cm.GetBackendByConsistentHash("user@example.com") },
		func(b string) { _ = cm.AllowRemoteLookupBackend(b) },
	}

	for r := range readers {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				readers[r](backends[i%len(backends)])
			}
		}(r)
	}

	close(start)
	wg.Wait()
}
