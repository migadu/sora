package spamtraining

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/circuitbreaker"
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

// Client handles spam training submissions to remote endpoint
type Client struct {
	config         *config.SpamTrainingConfig
	httpClient     *http.Client
	circuitBreaker *circuitbreaker.CircuitBreaker
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

	httpClient := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
		// Never follow a redirect: a followed 301/302/303 turns the POST into a
		// body-less GET whose 2xx would count as accepted, and a 307/308 replays
		// the message and the bearer token to the Location. The 3xx reaches the
		// status check in submitHTTP as a failure.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
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

	return &Client{
		config:         cfg,
		httpClient:     httpClient,
		circuitBreaker: cb,
	}, nil
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

// SubmitTrainingAsync submits training in background (non-blocking)
func (c *Client) SubmitTrainingAsync(ctx context.Context, req *TrainingRequest) {
	go func() {
		// Use a background context to avoid cancellation when original context expires
		bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := c.SubmitTraining(bgCtx, req); err != nil {
			logger.Warn("Spam training submission failed",
				"type", req.Type,
				"user", req.User,
				"error", err)
		} else {
			logger.Debug("Spam training submitted",
				"type", req.Type,
				"user", req.User,
				"source", req.SourceMailbox,
				"dest", req.DestMailbox)
		}
	}()
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
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fmt.Errorf("training endpoint returned redirect status %d to %q; redirects are not followed, so [spam_training] endpoint must be the final URL",
			resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("training endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetCircuitBreakerState returns the current circuit breaker state
func (c *Client) GetCircuitBreakerState() circuitbreaker.State {
	return c.circuitBreaker.State()
}
