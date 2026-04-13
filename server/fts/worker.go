package fts

import (
	"context"
	"sync"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
)

type Worker struct {
	rdb     *resilient.ResilientDatabase
	stopCh  chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
	running bool

	interval  time.Duration
	batchSize int
}

func NewWorker(rdb *resilient.ResilientDatabase) *Worker {
	return &Worker{
		rdb:       rdb,
		stopCh:    make(chan struct{}),
		interval:  30 * time.Second,
		batchSize: 5000,
	}
}

func (w *Worker) Start(ctx context.Context) {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return
	}
	w.running = true
	w.mu.Unlock()

	logger.Info("FTS Background Worker starting...")
	w.wg.Add(1)
	go w.run(ctx)
}

func (w *Worker) Stop() {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return
	}
	w.running = false
	w.mu.Unlock()

	close(w.stopCh)
	w.wg.Wait()
	logger.Info("FTS Background Worker stopped.")
}

func (w *Worker) run(ctx context.Context) {
	defer w.wg.Done()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Run explicitly once on boot to process backlog
	w.processBatch(ctx)

	for {
		select {
		case <-ctx.Done():
			logger.Info("FTS Worker stopped due to context cancellation")
			return
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.processBatch(ctx)
		}
	}
}

func (w *Worker) processBatch(ctx context.Context) {
	// Attempt to process messages in a loop until the batch runs out or we hit limits
	for {
		// Use a local context to ensure each batch runs cleanly
		batchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		processed, err := w.rdb.ProcessFTSBatchWithRetry(batchCtx, w.batchSize)
		cancel()

		if err != nil {
			logger.Error("FTS Worker: failed to process batch, backing off briefly", "err", err)
			time.Sleep(5 * time.Second)
			return
		}

		if processed == 0 {
			// No more messages in the queue
			break
		}

		logger.Info("FTS Worker: generated vectors for messages batch", "count", processed)

		// Keep looping immediately if we processed a full batch,
		// but pause briefly to avoid WAL starvation.
		time.Sleep(1 * time.Second)
	}
}
