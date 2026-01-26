package relayqueue

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server/delivery"
)

// RelayQueue defines the interface for queue operations required by the worker.
// This allows for mocking in tests and decouples the worker from the concrete DiskQueue.
type RelayQueue interface {
	AcquireNext() (*QueuedMessage, []byte, error)
	MarkSuccess(messageID string) error
	MarkFailure(messageID string, errorMsg string) error
	MarkPermanentFailure(messageID string, errorMsg string) error
	Release(messageID string) error
	GetStats() (pending, processing, failed int, err error)
}

// RelayHandler defines the interface for relay handler operations.
// This allows for mocking in tests.
type RelayHandler interface {
	SendToExternalRelay(from, to string, message []byte) error
}

// CircuitBreakerProvider is an optional interface that relay handlers can implement
// to provide circuit breaker state information for proactive recovery checking.
type CircuitBreakerProvider interface {
	GetCircuitBreaker() *circuitbreaker.CircuitBreaker
}

// Worker manages background processing of the relay queue with concurrent message delivery.
//
// The worker processes messages from a disk-based queue and delivers them via a relay handler
// (SMTP or HTTP). It supports:
//   - Concurrent processing of multiple messages (configurable concurrency)
//   - Immediate processing via notification channel
//   - Error reporting via error channel
//   - Graceful shutdown with WaitGroup
//   - Idempotent Start/Stop (safe to call multiple times)
type Worker struct {
	queue        RelayQueue
	relayHandler RelayHandler
	interval     time.Duration
	batchSize    int
	concurrency  int
	notifyCh     chan struct{}
	stopCh       chan struct{}
	errCh        chan<- error
	wg           sync.WaitGroup
	mu           sync.Mutex
	running      bool
}

// NewWorker creates a new relay queue worker.
//
// Parameters:
//   - queue: Queue implementation (typically *DiskQueue)
//   - relayHandler: Handler for delivering messages (SMTP or HTTP)
//   - interval: How often to check for new messages
//   - batchSize: Maximum messages to process per interval
//   - concurrency: Number of messages to process concurrently
//   - errCh: Channel for error reporting (can be nil)
func NewWorker(queue RelayQueue, relayHandler RelayHandler, interval time.Duration, batchSize, concurrency int, errCh chan<- error) *Worker {
	if batchSize <= 0 {
		batchSize = 100 // Default batch size
	}
	if concurrency <= 0 {
		concurrency = 5 // Default concurrency
	}

	return &Worker{
		queue:        queue,
		relayHandler: relayHandler,
		interval:     interval,
		batchSize:    batchSize,
		concurrency:  concurrency,
		notifyCh:     make(chan struct{}, 1),
		stopCh:       make(chan struct{}),
		errCh:        errCh,
	}
}

// Start begins background processing of the relay queue.
// It is safe to call Start multiple times - subsequent calls are no-ops if already running.
//
// Returns an error only if the worker is in an invalid state (currently never happens,
// but kept for consistency with other workers and future extensibility).
func (w *Worker) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return nil
	}
	w.running = true
	w.mu.Unlock()

	w.wg.Add(1)
	go w.run(ctx)

	logger.Info("Relay: worker started")
	return nil
}

// Stop gracefully stops the worker and waits for all goroutines to complete.
// It is safe to call Stop multiple times - subsequent calls are no-ops if already stopped.
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

	logger.Info("Relay: worker stopped")
}

// NotifyQueued signals the worker to process the queue immediately without waiting for the interval.
// This is useful when a new message is enqueued and should be processed ASAP.
// If a notification is already pending, this is a no-op (non-blocking).
func (w *Worker) NotifyQueued() {
	select {
	case w.notifyCh <- struct{}{}:
	default:
		// Don't block if notifyCh already has a signal
	}
}

// run is the main worker loop
func (w *Worker) run(ctx context.Context) {
	defer func() {
		w.mu.Lock()
		w.running = false
		w.mu.Unlock()
		w.wg.Done()
	}()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	logger.Info("Relay: Worker processing", "interval", w.interval, "batch_size", w.batchSize, "concurrency", w.concurrency)

	// Process immediately on start
	w.processQueue(ctx)

	for {
		select {
		case <-ctx.Done():
			logger.Info("Relay: worker stopped due to context cancellation")
			return
		case <-w.stopCh:
			logger.Info("Relay: worker stopped due to stop signal")
			return
		case <-ticker.C:
			logger.Info("Relay: timer tick")
			if err := w.processQueue(ctx); err != nil {
				w.reportError(err)
			}
		case <-w.notifyCh:
			logger.Info("Relay: worker notified")
			_ = w.processQueue(ctx)
		}
	}
}

// getCircuitBreakerState returns the circuit breaker state if the handler provides one
func (w *Worker) getCircuitBreakerState() (hasCircuitBreaker bool, state circuitbreaker.State) {
	if provider, ok := w.relayHandler.(CircuitBreakerProvider); ok {
		if cb := provider.GetCircuitBreaker(); cb != nil {
			return true, cb.State()
		}
	}
	return false, circuitbreaker.StateClosed
}

// processQueue processes a batch of messages from the queue with concurrent delivery.
// It acquires messages one by one up to batch size, then processes them concurrently
// using a semaphore pattern to limit concurrent deliveries.
//
// Circuit Breaker Auto-Recovery:
// If the circuit breaker is OPEN or HALF-OPEN, the worker will attempt to process
// at least one message to trigger recovery logic. This enables proactive recovery
// without waiting for new messages to arrive.
func (w *Worker) processQueue(ctx context.Context) error {
	// Check circuit breaker state for proactive recovery
	hasCircuitBreaker, cbState := w.getCircuitBreakerState()
	if hasCircuitBreaker && cbState != circuitbreaker.StateClosed {
		logger.Info("Relay: Circuit breaker attempting recovery delivery", "state", cbState)
	}

	sem := make(chan struct{}, w.concurrency)
	var wg sync.WaitGroup

	processed := 0
	for processed < w.batchSize {
		// Check for context cancellation early
		select {
		case <-ctx.Done():
			logger.Info("Relay: request aborted")
			wg.Wait() // Wait for in-flight messages to complete
			return nil
		default:
		}

		// Acquire next message
		msg, messageBytes, err := w.queue.AcquireNext()
		if err != nil {
			wg.Wait() // Wait for in-flight messages before returning error
			return fmt.Errorf("failed to acquire message: %w", err)
		}

		if msg == nil {
			// No messages ready for processing, break and wait for next interval
			break
		}

		// Process the message concurrently
		select {
		case <-ctx.Done():
			logger.Info("Relay: request aborted during processing")
			wg.Wait()
			return nil
		case sem <- struct{}{}:
			wg.Add(1)
			go func(msg *QueuedMessage, messageBytes []byte) {
				defer wg.Done()
				defer func() { <-sem }()
				w.processMessage(ctx, msg, messageBytes)
			}(msg, messageBytes)
			processed++
		}
	}

	// Wait for all concurrent deliveries to complete
	wg.Wait()

	// Update metrics and log
	if processed > 0 {
		pending, processing, failed, err := w.queue.GetStats()
		if err == nil {
			metrics.RelayQueueDepth.WithLabelValues("pending").Set(float64(pending))
			metrics.RelayQueueDepth.WithLabelValues("processing").Set(float64(processing))
			metrics.RelayQueueDepth.WithLabelValues("failed").Set(float64(failed))

			logger.Info("Relay: Processed messages", "count", processed,
				"pending", pending, "processing", processing, "failed", failed)
		}
	}

	return nil
}

// processMessage attempts to deliver a single message via the relay handler.
func (w *Worker) processMessage(ctx context.Context, msg *QueuedMessage, messageBytes []byte) {
	// Track message age in queue
	messageAge := time.Since(msg.QueuedAt)
	metrics.RelayQueueAge.WithLabelValues(msg.Type).Observe(messageAge.Seconds())

	logger.Info("Relay: Processing message", "id", msg.ID, "type", msg.Type,
		"from", msg.From, "to", msg.To, "attempt", msg.Attempts+1, "age", messageAge)

	// Check if relay handler is configured
	if w.relayHandler == nil {
		logger.Error("Relay: ERROR - Relay handler not configured, marking as failed")
		if err := w.queue.MarkFailure(msg.ID, "Relay handler not configured"); err != nil {
			logger.Error("Relay: CRITICAL - Failed to mark failure for message", "id", msg.ID, "error", err)
		}
		metrics.RelayDelivery.WithLabelValues(msg.Type, "no_handler").Inc()
		return
	}

	// Check for context cancellation before delivery
	select {
	case <-ctx.Done():
		logger.Info("Relay: Request aborted during delivery", "id", msg.ID)
		return
	default:
	}

	// Attempt delivery
	startTime := time.Now()
	err := w.relayHandler.SendToExternalRelay(msg.From, msg.To, messageBytes)
	duration := time.Since(startTime)

	if err != nil {
		// Check for circuit breaker errors first - these should not increment failure count
		// The circuit breaker is protecting the relay, so we should release the message
		// back to the queue to be retried naturally on the next worker cycle
		if errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) || errors.Is(err, circuitbreaker.ErrTooManyRequests) {
			logger.Warn("Relay: Circuit breaker preventing delivery, releasing back to queue",
				"id", msg.ID, "error", err, "duration", duration)
			metrics.RelayDelivery.WithLabelValues(msg.Type, "circuit_breaker_blocked").Inc()

			// Release back to queue without incrementing attempts
			if releaseErr := w.queue.Release(msg.ID); releaseErr != nil {
				logger.Error("Relay: CRITICAL - Failed to release message back to queue", "id", msg.ID, "error", releaseErr)
			}
			return
		}

		// Classify the error to determine if it's permanent (5xx) or temporary (4xx/network)
		isPermanent := delivery.IsPermanentError(err)

		if isPermanent {
			// Permanent failure (5xx SMTP error) - drop immediately without retry
			logger.Error("Relay: Permanent delivery failure (5xx), dropping message", "id", msg.ID, "error", err, "duration", duration)

			if markErr := w.queue.MarkPermanentFailure(msg.ID, err.Error()); markErr != nil {
				logger.Error("Relay: CRITICAL - Failed to mark permanent failure for message", "id", msg.ID, "error", markErr)
			}

			metrics.RelayDelivery.WithLabelValues(msg.Type, "permanent_failure").Inc()
			metrics.RelayDeliveryDuration.WithLabelValues(msg.Type, "permanent_failure").Observe(duration.Seconds())
		} else {
			// Temporary failure (4xx SMTP error or network error) - retry with backoff
			logger.Error("Relay: Temporary delivery failure (4xx/network), will retry", "id", msg.ID, "error", err, "duration", duration)

			if markErr := w.queue.MarkFailure(msg.ID, err.Error()); markErr != nil {
				logger.Error("Relay: CRITICAL - Failed to mark failure for message", "id", msg.ID, "error", markErr)
			}

			metrics.RelayDelivery.WithLabelValues(msg.Type, "temporary_failure").Inc()
			metrics.RelayDeliveryDuration.WithLabelValues(msg.Type, "temporary_failure").Observe(duration.Seconds())
		}
		return
	}

	// Delivery succeeded
	logger.Info("Relay: Delivered message successfully", "id", msg.ID, "duration", duration)

	if markErr := w.queue.MarkSuccess(msg.ID); markErr != nil {
		logger.Error("Relay: CRITICAL - Failed to mark success for message", "id", msg.ID, "error", markErr)
	}

	metrics.RelayDelivery.WithLabelValues(msg.Type, "success").Inc()
	metrics.RelayDeliveryDuration.WithLabelValues(msg.Type, "success").Observe(duration.Seconds())
}

// reportError sends an error to the error channel if configured, otherwise logs it
func (w *Worker) reportError(err error) {
	if w.errCh != nil {
		select {
		case w.errCh <- err:
		default:
			logger.Error("Relay: Worker error (no listener)", "error", err)
		}
	} else {
		logger.Error("Relay: Worker error", "error", err)
	}
}

// GetStats returns current queue statistics.
func (w *Worker) GetStats() (pending, processing, failed int, err error) {
	return w.queue.GetStats()
}
