package config

import (
	"time"

	"github.com/migadu/sora/helpers"
)

// SpamTrainingConfig defines configuration for spam filter training
// When users move messages to/from Junk folder, the message (without attachments)
// is submitted to a remote endpoint for spam filter training.
type SpamTrainingConfig struct {
	// Enable spam training submission
	Enabled bool `toml:"enabled"`

	// HTTP endpoint to submit spam/ham training data
	// Example: "https://spam-filter.example.com/train"
	Endpoint string `toml:"endpoint"`

	// Authentication token for the training endpoint (Bearer token)
	AuthToken string `toml:"auth_token"`

	// Timeout for HTTP requests to the training endpoint
	Timeout string `toml:"timeout"`

	// Maximum message size to submit, attachments included, as stored with the
	// message. Larger messages are skipped before their body is fetched.
	// Default: "10mb"
	MaxMessageSize string `toml:"max_message_size"`

	// Skip training if message has attachments larger than this size
	// Set to "0" to always strip attachments and train regardless of size
	// Default: "0" (always strip and train)
	MaxAttachmentSize string `toml:"max_attachment_size"`

	// Async mode: submit training requests in background (don't block MOVE)
	// Default: true
	Async bool `toml:"async"`

	// Number of workers that fetch and submit training messages, process-wide.
	// Default: 4
	Workers int `toml:"workers"`

	// Messages waiting for a worker. A message moved while the queue is full is
	// not submitted. Default: 1000
	QueueSize int `toml:"queue_size"`

	// Circuit breaker configuration for training endpoint
	CircuitBreaker SpamTrainingCircuitBreakerConfig `toml:"circuit_breaker"`
}

// SpamTrainingCircuitBreakerConfig holds circuit breaker settings for spam training
type SpamTrainingCircuitBreakerConfig struct {
	// Number of consecutive failures before opening circuit
	// Default: 5
	Threshold int `toml:"threshold"`

	// Recovery test interval when circuit is open
	// Default: "30s"
	Timeout string `toml:"timeout"`

	// Max requests allowed in half-open state
	// Default: 3
	MaxRequests int `toml:"max_requests"`
}

// IsConfigured returns true if spam training is enabled and configured
func (s *SpamTrainingConfig) IsConfigured() bool {
	return s.Enabled && s.Endpoint != ""
}

// GetTimeout parses and returns the HTTP timeout duration
func (s *SpamTrainingConfig) GetTimeout() (time.Duration, error) {
	if s.Timeout == "" {
		return 10 * time.Second, nil // Default: 10 seconds
	}
	return helpers.ParseDuration(s.Timeout)
}

// GetMaxMessageSize parses and returns the maximum message size
func (s *SpamTrainingConfig) GetMaxMessageSize() (int64, error) {
	if s.MaxMessageSize == "" {
		return 10 * 1024 * 1024, nil // Default: 10MB
	}
	return helpers.ParseSize(s.MaxMessageSize)
}

// GetWorkers returns the number of training workers
func (s *SpamTrainingConfig) GetWorkers() int {
	if s.Workers <= 0 {
		return 4
	}
	return s.Workers
}

// GetQueueSize returns how many messages may wait for a training worker
func (s *SpamTrainingConfig) GetQueueSize() int {
	if s.QueueSize <= 0 {
		return 1000
	}
	return s.QueueSize
}

// GetMaxAttachmentSize parses and returns the maximum attachment size
func (s *SpamTrainingConfig) GetMaxAttachmentSize() (int64, error) {
	if s.MaxAttachmentSize == "" {
		return 0, nil // Default: always strip attachments
	}
	return helpers.ParseSize(s.MaxAttachmentSize)
}

// GetCircuitBreakerThreshold returns the circuit breaker failure threshold
func (c *SpamTrainingCircuitBreakerConfig) GetThreshold() int {
	if c.Threshold <= 0 {
		return 5 // Default: open after 5 consecutive failures
	}
	return c.Threshold
}

// GetCircuitBreakerTimeout returns the circuit breaker timeout
func (c *SpamTrainingCircuitBreakerConfig) GetTimeout() (time.Duration, error) {
	if c.Timeout == "" {
		return 30 * time.Second, nil // Default: 30s
	}
	return helpers.ParseDuration(c.Timeout)
}

// GetCircuitBreakerMaxRequests returns max requests in half-open state
func (c *SpamTrainingCircuitBreakerConfig) GetMaxRequests() int {
	if c.MaxRequests <= 0 {
		return 3 // Default: allow 3 requests in half-open
	}
	return c.MaxRequests
}
