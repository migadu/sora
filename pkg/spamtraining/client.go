package spamtraining

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/metrics"
)

// TrainingType represents whether a message is spam or ham
type TrainingType string

const (
	// TrainingTypeSpam indicates the message is spam (moved TO Junk)
	TrainingTypeSpam TrainingType = "spam"
	// TrainingTypeHam indicates the message is ham/not spam (moved FROM Junk)
	TrainingTypeHam TrainingType = "ham"
)

// TrainingRequest represents the payload sent to the spam training endpoint
type TrainingRequest struct {
	// Type of training: "spam" or "ham"
	Type TrainingType `json:"type"`
	// Message content (without attachments)
	Message string `json:"message"`
	// Email address of the user performing the training
	User string `json:"user"`
	// Source mailbox name
	SourceMailbox string `json:"source_mailbox,omitempty"`
	// Destination mailbox name
	DestMailbox string `json:"dest_mailbox,omitempty"`
	// Timestamp of the training action
	Timestamp time.Time `json:"timestamp"`
}

// Job is one moved message to train on.
type Job struct {
	Type          TrainingType
	User          string
	SourceMailbox string
	DestMailbox   string
	// Size is the message size stored with the message. Enqueue refuses a job over
	// max_message_size, so its body is never fetched.
	Size int64
	// Open returns the message. A worker calls it and reads at most
	// max_message_size bytes from it.
	Open func(ctx context.Context) (io.ReadCloser, error)

	queuedAt time.Time
}

var (
	// ErrMessageTooLarge means the message is over max_message_size.
	ErrMessageTooLarge = errors.New("message exceeds spam training max_message_size")
	// ErrQueueFull means every worker is busy and the queue is full.
	ErrQueueFull = errors.New("spam training queue is full")
	// ErrClosed means the client has been closed.
	ErrClosed = errors.New("spam training client is closed")
)

// jobTimeout bounds one job: fetching the body and submitting it.
const jobTimeout = 60 * time.Second

// Client handles spam training submissions to remote endpoint. A fixed pool of
// workers serves a bounded queue, so however many messages are moved, at most one
// body per worker, each no larger than max_message_size, is held at a time.
type Client struct {
	config         *config.SpamTrainingConfig
	httpClient     *http.Client
	circuitBreaker *circuitbreaker.CircuitBreaker

	maxMessageSize int64
	jobs           chan Job
	ctx            context.Context // cancelled by Close; ends the workers and their jobs
	cancel         context.CancelFunc
	wg             sync.WaitGroup
}

// NewClient creates a new spam training client
func NewClient(cfg *config.SpamTrainingConfig) (*Client, error) {
	if cfg == nil || !cfg.IsConfigured() {
		return nil, fmt.Errorf("spam training not configured")
	}

	timeout, err := cfg.GetTimeout()
	if err != nil {
		return nil, fmt.Errorf("invalid timeout: %w", err)
	}

	maxMessageSize, err := cfg.GetMaxMessageSize()
	if err != nil {
		return nil, fmt.Errorf("invalid max_message_size: %w", err)
	}
	if maxMessageSize <= 0 {
		return nil, fmt.Errorf("invalid max_message_size %q: must be positive", cfg.MaxMessageSize)
	}

	httpClient := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// Get circuit breaker settings
	cbTimeout, err := cfg.CircuitBreaker.GetTimeout()
	if err != nil {
		return nil, fmt.Errorf("invalid circuit breaker timeout: %w", err)
	}

	// Configure circuit breaker using Sora's implementation
	cbSettings := circuitbreaker.Settings{
		Name:        "spam-training",
		MaxRequests: uint32(cfg.CircuitBreaker.GetMaxRequests()),
		Interval:    0, // Don't clear counts (use Timeout for recovery)
		Timeout:     cbTimeout,
		ReadyToTrip: func(counts circuitbreaker.Counts) bool {
			threshold := cfg.CircuitBreaker.GetThreshold()
			return counts.ConsecutiveFailures >= uint32(threshold)
		},
		OnStateChange: func(name string, from circuitbreaker.State, to circuitbreaker.State) {
			logger.Info("Spam training circuit breaker state change",
				"from", from.String(),
				"to", to.String())
		},
	}

	cb := circuitbreaker.NewCircuitBreaker(cbSettings)

	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		config:         cfg,
		httpClient:     httpClient,
		circuitBreaker: cb,
		maxMessageSize: maxMessageSize,
		jobs:           make(chan Job, cfg.GetQueueSize()),
		ctx:            ctx,
		cancel:         cancel,
	}
	for range cfg.GetWorkers() {
		c.wg.Add(1)
		go c.worker()
	}
	return c, nil
}

// Close stops the workers. Queued jobs are abandoned and jobs in progress cancelled.
func (c *Client) Close() {
	c.cancel()
	c.wg.Wait()
}

// Enqueue hands a job to the workers without blocking. It returns
// ErrMessageTooLarge for a job over max_message_size and ErrQueueFull when the
// queue is full; such a job is not run.
func (c *Client) Enqueue(job Job) error {
	if job.Size > c.maxMessageSize {
		metrics.SpamTrainingMessagesTotal.WithLabelValues("too_large").Inc()
		return ErrMessageTooLarge
	}
	if c.ctx.Err() != nil {
		metrics.SpamTrainingMessagesTotal.WithLabelValues("dropped").Inc()
		return ErrClosed
	}
	job.queuedAt = time.Now()
	select {
	case c.jobs <- job:
		return nil
	default:
		metrics.SpamTrainingMessagesTotal.WithLabelValues("dropped").Inc()
		return ErrQueueFull
	}
}

func (c *Client) worker() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		case job := <-c.jobs:
			if c.ctx.Err() != nil {
				return // closed while this job was picked
			}
			c.run(job)
		}
	}
}

func (c *Client) run(job Job) {
	defer func() {
		if r := recover(); r != nil {
			metrics.SpamTrainingMessagesTotal.WithLabelValues("failed").Inc()
			logger.Error("Spam training job panicked", "type", job.Type, "user", job.User, "panic", r)
		}
	}()
	ctx, cancel := context.WithTimeout(c.ctx, jobTimeout)
	defer cancel()

	err := c.train(ctx, job)
	switch {
	case err == nil:
		metrics.SpamTrainingMessagesTotal.WithLabelValues("submitted").Inc()
		logger.Debug("Spam training submitted", "type", job.Type, "user", job.User,
			"source", job.SourceMailbox, "dest", job.DestMailbox)
	case errors.Is(err, ErrMessageTooLarge):
		metrics.SpamTrainingMessagesTotal.WithLabelValues("too_large").Inc()
		logger.Debug("Spam training skipped: message body larger than its stored size and max_message_size",
			"type", job.Type, "user", job.User, "stored_size", job.Size, "max_message_size", c.maxMessageSize)
	default:
		metrics.SpamTrainingMessagesTotal.WithLabelValues("failed").Inc()
		logger.Warn("Spam training submission failed", "type", job.Type, "user", job.User, "error", err)
	}
}

// train fetches the job's message, strips its attachments and submits it.
func (c *Client) train(ctx context.Context, job Job) error {
	// An open breaker refuses the submission, so do not download a body that
	// cannot be sent while the endpoint is down.
	if c.circuitBreaker.State() == circuitbreaker.StateOpen {
		return circuitbreaker.ErrCircuitBreakerOpen
	}

	body, err := job.Open(ctx)
	if err != nil {
		return fmt.Errorf("fetching message: %w", err)
	}
	if body == nil {
		return errors.New("fetching message: no body")
	}
	// The stored size is not trusted to bound the read.
	message, err := io.ReadAll(io.LimitReader(body, c.maxMessageSize+1))
	body.Close()
	if err != nil {
		return fmt.Errorf("reading message: %w", err)
	}
	if int64(len(message)) > c.maxMessageSize {
		return ErrMessageTooLarge
	}

	stripped, err := StripAttachments(message)
	if err != nil {
		logger.Warn("Spam training: failed to strip attachments, submitting the whole message",
			"type", job.Type, "user", job.User, "error", err)
		stripped = message
	}

	return c.SubmitTraining(ctx, &TrainingRequest{
		Type:          job.Type,
		Message:       string(stripped),
		User:          job.User,
		SourceMailbox: job.SourceMailbox,
		DestMailbox:   job.DestMailbox,
		Timestamp:     job.queuedAt,
	})
}

// SubmitTraining submits a message for spam training
func (c *Client) SubmitTraining(ctx context.Context, req *TrainingRequest) error {
	if req == nil {
		return fmt.Errorf("training request is nil")
	}

	// Execute through circuit breaker
	_, err := c.circuitBreaker.Execute(func() (any, error) {
		return nil, c.submitHTTP(ctx, req)
	})

	return err
}

// submitHTTP performs the actual HTTP request to the training endpoint
func (c *Client) submitHTTP(ctx context.Context, req *TrainingRequest) error {
	// Marshal request to JSON
	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal training request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.config.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	if c.config.AuthToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.config.AuthToken)
	}

	// Send request
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for error details
	body, _ := io.ReadAll(resp.Body)

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("training endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetCircuitBreakerState returns the current circuit breaker state
func (c *Client) GetCircuitBreakerState() circuitbreaker.State {
	return c.circuitBreaker.State()
}
