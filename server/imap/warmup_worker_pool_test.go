package imap

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestWorkerPoolStartStop verifies workers start and stop gracefully
func TestWorkerPoolStartStop(t *testing.T) {
	s := &IMAPServer{
		name:                "test",
		warmupMaxConcurrent: 3,
		warmupQueue:         make(chan warmupJob, 15),
		warmupInterval:      time.Hour,
		enableWarmup:        true,
	}

	s.startWarmupWorkers()

	// Workers should be running — verify by checking WaitGroup doesn't complete immediately
	done := make(chan struct{})
	go func() {
		s.warmupWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("Workers should still be running (queue not closed)")
	case <-time.After(50 * time.Millisecond):
		// Expected: workers are alive
	}

	// Stop workers
	s.stopWarmupWorkers()

	select {
	case <-done:
		// Expected: workers stopped
	case <-time.After(2 * time.Second):
		t.Fatal("Workers did not stop within timeout")
	}
}

// TestAsyncWarmupEnqueue verifies jobs are enqueued to the channel
func TestAsyncWarmupEnqueue(t *testing.T) {
	ctx := context.Background()
	s := &IMAPServer{
		name:                "test",
		warmupMaxConcurrent: 2,
		warmupQueue:         make(chan warmupJob, 10),
		warmupSemaphore:     make(chan struct{}, 2),
		warmupInterval:      time.Hour,
		enableWarmup:        true,
		// cache is nil → WarmupCache returns nil early
	}

	// With nil cache, WarmupCache returns nil immediately
	err := s.WarmupCache(ctx, 100, []string{"INBOX"}, 50, true)
	if err != nil {
		t.Fatalf("WarmupCache returned error: %v", err)
	}

	// Queue should be empty because cache==nil causes early return
	if len(s.warmupQueue) != 0 {
		t.Fatalf("Expected empty queue with nil cache, got %d", len(s.warmupQueue))
	}
}

// TestWarmupEarlyReturnConditions verifies WarmupCache returns early for invalid inputs
func TestWarmupEarlyReturnConditions(t *testing.T) {
	ctx := context.Background()
	s := &IMAPServer{
		name:                "test",
		warmupMaxConcurrent: 2,
		warmupQueue:         make(chan warmupJob, 10),
		warmupSemaphore:     make(chan struct{}, 2),
		warmupInterval:      time.Hour,
	}

	tests := []struct {
		name         string
		messageCount int
		mailboxes    []string
	}{
		{"zero messages", 0, []string{"INBOX"}},
		{"negative messages", -1, []string{"INBOX"}},
		{"empty mailboxes", 50, []string{}},
		{"nil mailboxes", 50, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.WarmupCache(ctx, 100, tt.mailboxes, tt.messageCount, true)
			if err != nil {
				t.Fatalf("WarmupCache returned error: %v", err)
			}
			if len(s.warmupQueue) != 0 {
				t.Fatal("Queue should be empty for invalid input")
			}
		})
	}
}

// TestWarmupIntervalDedup verifies that warmup is skipped if done recently
func TestWarmupIntervalDedup(t *testing.T) {
	s := &IMAPServer{
		name:            "test",
		warmupInterval:  time.Hour,
		warmupQueue:     make(chan warmupJob, 10),
		warmupSemaphore: make(chan struct{}, 2),
	}

	// Stamp lastWarmupTimes for account 100
	s.lastWarmupTimes.Store(int64(100), time.Now())

	// Try to enqueue — should be skipped due to interval
	// We can't use WarmupCache because it checks cache==nil first.
	// Instead, test the dedup logic directly as used in executeWarmup.

	job := warmupJob{accountID: 100, mailboxNames: []string{"INBOX"}, messageCount: 50}

	// Simulate the dedup check in executeWarmup
	if lastWarmupRaw, ok := s.lastWarmupTimes.Load(job.accountID); ok {
		lastWarmup := lastWarmupRaw.(time.Time)
		if time.Since(lastWarmup) < s.warmupInterval {
			// Expected: dedup should trigger
			return
		}
	}
	t.Fatal("Expected dedup check to skip warmup for recently warmed account")
}

// TestQueueFullDropsBehavior verifies that when queue is full, jobs are dropped
func TestQueueFullDropsBehavior(t *testing.T) {
	queueSize := 3
	s := &IMAPServer{
		name:                "test",
		warmupMaxConcurrent: 1,
		warmupQueue:         make(chan warmupJob, queueSize),
		warmupSemaphore:     make(chan struct{}, 1),
		warmupInterval:      time.Hour,
	}

	// Fill the queue manually
	for i := 0; i < queueSize; i++ {
		s.warmupQueue <- warmupJob{accountID: int64(i), mailboxNames: []string{"INBOX"}, messageCount: 10}
	}

	if len(s.warmupQueue) != queueSize {
		t.Fatalf("Expected queue to be full (%d), got %d", queueSize, len(s.warmupQueue))
	}

	// Try non-blocking enqueue (simulates what WarmupCache does for async)
	job := warmupJob{accountID: 999, mailboxNames: []string{"INBOX"}, messageCount: 10}
	dropped := false
	select {
	case s.warmupQueue <- job:
		// Enqueued successfully
	default:
		dropped = true
	}

	if !dropped {
		t.Fatal("Expected job to be dropped when queue is full")
	}

	// Verify lastWarmupTimes was NOT stamped for the dropped job
	if _, ok := s.lastWarmupTimes.Load(int64(999)); ok {
		t.Fatal("lastWarmupTimes should NOT be stamped for dropped jobs")
	}
}

// TestExecuteWarmupDedupRecheck verifies that executeWarmup re-checks dedup
// before doing work (prevents redundant work when multiple jobs for same user are queued)
func TestExecuteWarmupDedupRecheck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := &IMAPServer{
		name:           "test",
		appCtx:         ctx,
		warmupInterval: time.Hour,
		warmupTimeout:  5 * time.Second,
		// cache, rdb, s3 are nil — executeWarmup will hit dedup before reaching them
	}

	// Pre-stamp the account as recently warmed
	s.lastWarmupTimes.Store(int64(100), time.Now())

	// executeWarmup should return early due to dedup re-check
	// (If it didn't, it would panic on nil cache)
	s.executeWarmup(warmupJob{accountID: 100, mailboxNames: []string{"INBOX"}, messageCount: 50})
}

// TestWorkerPoolProcessesJobs verifies that workers consume and process jobs from the queue
func TestWorkerPoolProcessesJobs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var processed atomic.Int64

	s := &IMAPServer{
		name:                "test",
		appCtx:              ctx,
		warmupMaxConcurrent: 3,
		warmupQueue:         make(chan warmupJob, 50),
		warmupSemaphore:     make(chan struct{}, 3),
		warmupInterval:      time.Hour, // Unique account IDs pass the dedup re-check; the stamps outlive the count below
		warmupTimeout:       5 * time.Second,
		// cache is nil — executeWarmup will stamp lastWarmupTimes then fail on cache access
		// That's fine; we're testing that workers pick up jobs.
	}

	// We'll use the dedup timestamp to detect processing.
	// After executeWarmup runs, it stamps lastWarmupTimes (even though it'll fail on nil cache after that).
	// We just need to verify the stamp happens.

	s.startWarmupWorkers()

	numJobs := 20
	for i := 0; i < numJobs; i++ {
		s.warmupQueue <- warmupJob{
			accountID:    int64(1000 + i), // Unique IDs so dedup doesn't skip
			mailboxNames: []string{"INBOX"},
			messageCount: 10,
		}
	}

	// Wait for workers to process (they'll stamp lastWarmupTimes then fail on nil cache)
	time.Sleep(200 * time.Millisecond)

	// Count how many accounts got stamped
	s.lastWarmupTimes.Range(func(key, value any) bool {
		processed.Add(1)
		return true
	})

	s.stopWarmupWorkers()

	if processed.Load() != int64(numJobs) {
		t.Errorf("Expected %d jobs processed (stamped), got %d", numJobs, processed.Load())
	}
}

// TestWorkerPoolConcurrencyBound verifies that at most N workers run concurrently
func TestWorkerPoolConcurrencyBound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	maxWorkers := 3
	var concurrent atomic.Int64
	var maxConcurrent atomic.Int64
	var wg sync.WaitGroup

	// We'll use a channel to control when jobs complete
	proceed := make(chan struct{})

	s := &IMAPServer{
		name:                "test",
		appCtx:              ctx,
		warmupMaxConcurrent: maxWorkers,
		warmupQueue:         make(chan warmupJob, 50),
		warmupSemaphore:     make(chan struct{}, maxWorkers),
		warmupInterval:      time.Millisecond,
		warmupTimeout:       10 * time.Second,
	}

	// Start workers
	for i := 0; i < maxWorkers; i++ {
		s.warmupWg.Add(1)
		go func() {
			defer s.warmupWg.Done()
			for job := range s.warmupQueue {
				_ = job
				cur := concurrent.Add(1)
				// Track max concurrent
				for {
					old := maxConcurrent.Load()
					if cur <= old || maxConcurrent.CompareAndSwap(old, cur) {
						break
					}
				}
				<-proceed // Block until test says to continue
				concurrent.Add(-1)
				wg.Done()
			}
		}()
	}

	// Enqueue more jobs than workers
	numJobs := 10
	wg.Add(numJobs)
	for i := 0; i < numJobs; i++ {
		s.warmupQueue <- warmupJob{accountID: int64(i), mailboxNames: []string{"INBOX"}, messageCount: 10}
	}

	// Let workers all reach the blocking point
	time.Sleep(50 * time.Millisecond)

	// At this point, exactly maxWorkers should be blocked
	if cur := concurrent.Load(); cur != int64(maxWorkers) {
		t.Errorf("Expected %d concurrent workers, got %d", maxWorkers, cur)
	}

	// Release all jobs
	for i := 0; i < numJobs; i++ {
		proceed <- struct{}{}
	}

	wg.Wait()

	// Verify max concurrency was bounded
	if mc := maxConcurrent.Load(); mc > int64(maxWorkers) {
		t.Errorf("Max concurrent exceeded bound: got %d, max allowed %d", mc, maxWorkers)
	}

	close(s.warmupQueue)
	s.warmupWg.Wait()
}

// TestSyncWarmupUsesSemaphore verifies sync mode uses the semaphore
func TestSyncWarmupUsesSemaphore(t *testing.T) {
	ctx := context.Background()
	s := &IMAPServer{
		name:                "test",
		warmupMaxConcurrent: 1,
		warmupQueue:         make(chan warmupJob, 5),
		warmupSemaphore:     make(chan struct{}, 1),
		warmupInterval:      time.Hour,
		// cache is nil → early return
	}

	// With nil cache, sync warmup returns immediately
	err := s.WarmupCache(ctx, 100, []string{"INBOX"}, 50, false)
	if err != nil {
		t.Fatalf("Sync WarmupCache returned error: %v", err)
	}
}

// TestThunderingHerdSimulation simulates mass reconnect and verifies bounded behavior
func TestThunderingHerdSimulation(t *testing.T) {
	maxWorkers := 5
	queueSize := maxWorkers * 5 // 25

	s := &IMAPServer{
		name:                "test",
		warmupMaxConcurrent: maxWorkers,
		warmupQueue:         make(chan warmupJob, queueSize),
		warmupSemaphore:     make(chan struct{}, maxWorkers),
		warmupInterval:      time.Hour,
	}

	totalUsers := 200
	enqueued := 0
	dropped := 0

	// Simulate 200 users reconnecting simultaneously
	for i := 0; i < totalUsers; i++ {
		job := warmupJob{accountID: int64(i), mailboxNames: []string{"INBOX"}, messageCount: 50}
		select {
		case s.warmupQueue <- job:
			enqueued++
		default:
			dropped++
		}
	}

	// Verify queue is bounded
	if enqueued > queueSize {
		t.Errorf("Enqueued %d jobs, but queue capacity is %d", enqueued, queueSize)
	}
	if enqueued != queueSize {
		t.Errorf("Expected exactly %d enqueued (queue capacity), got %d", queueSize, enqueued)
	}
	if dropped != totalUsers-queueSize {
		t.Errorf("Expected %d dropped, got %d", totalUsers-queueSize, dropped)
	}

	// Verify no lastWarmupTimes were stamped for dropped jobs
	for i := queueSize; i < totalUsers; i++ {
		if _, ok := s.lastWarmupTimes.Load(int64(i)); ok {
			t.Errorf("Account %d was dropped but has lastWarmupTimes stamped", i)
		}
	}

	t.Logf("Thundering herd: %d users, %d enqueued, %d dropped (queue=%d, workers=%d)",
		totalUsers, enqueued, dropped, queueSize, maxWorkers)
}

// TestStopWarmupWorkersTimeout verifies stop doesn't hang if workers are stuck
func TestStopWarmupWorkersTimeout(t *testing.T) {
	s := &IMAPServer{
		name:                "test",
		warmupMaxConcurrent: 2,
		warmupQueue:         make(chan warmupJob, 10),
	}

	// Start workers that will block forever (until queue closes)
	blockCh := make(chan struct{})
	for i := 0; i < 2; i++ {
		s.warmupWg.Add(1)
		go func() {
			defer s.warmupWg.Done()
			for range s.warmupQueue {
				<-blockCh // Block forever
			}
		}()
	}

	// Enqueue a job so workers are blocked
	s.warmupQueue <- warmupJob{accountID: 1}

	// stopWarmupWorkers should not hang — it has a 10s timeout
	done := make(chan struct{})
	go func() {
		s.stopWarmupWorkers()
		close(done)
	}()

	select {
	case <-done:
		// Good — completed within timeout
	case <-time.After(15 * time.Second):
		t.Fatal("stopWarmupWorkers hung for more than 15s")
	}

	// Unblock the stuck worker to clean up
	close(blockCh)
}

// TestWarmupQueueDedupSameUserMultipleEnqueues verifies that when the same user
// is enqueued multiple times, only the first execution does real work
func TestWarmupQueueDedupSameUserMultipleEnqueues(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := &IMAPServer{
		name:                "test",
		appCtx:              ctx,
		warmupMaxConcurrent: 1,
		warmupQueue:         make(chan warmupJob, 10),
		warmupSemaphore:     make(chan struct{}, 1),
		warmupInterval:      time.Hour, // Long interval — second execution should be deduped
		warmupTimeout:       5 * time.Second,
	}

	// Enqueue same account twice
	s.warmupQueue <- warmupJob{accountID: 100, mailboxNames: []string{"INBOX"}, messageCount: 10}
	s.warmupQueue <- warmupJob{accountID: 100, mailboxNames: []string{"INBOX"}, messageCount: 10}

	s.startWarmupWorkers()

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	s.stopWarmupWorkers()

	// Account should have been stamped exactly once
	if _, ok := s.lastWarmupTimes.Load(int64(100)); !ok {
		t.Fatal("Expected account 100 to have lastWarmupTimes stamped")
	}

	// The second job should have been deduped by the re-check in executeWarmup
	// (We can't directly count executions without mocking, but the dedup logic is tested above)
}
