package config

import (
	"time"

	"github.com/migadu/sora/helpers"
)

// RelayConfig defines the configuration for external message relay (for Sieve redirect/vacation)
type RelayConfig struct {
	// Type of relay: "smtp" or "http"
	Type string `toml:"type"`

	// SMTP relay configuration
	SMTPHost        string `toml:"smtp_host"`          // SMTP server address (e.g., "smtp.example.com:587")
	SMTPTLS         bool   `toml:"smtp_tls"`           // Use TLS for SMTP connection (default: true if not specified)
	SMTPTLSVerify   bool   `toml:"smtp_tls_verify"`    // Verify TLS certificates (default: true)
	SMTPUseStartTLS bool   `toml:"smtp_use_starttls"`  // Use STARTTLS instead of direct TLS (default: false)
	SMTPTLSCertFile string `toml:"smtp_tls_cert_file"` // Client certificate for mTLS (optional)
	SMTPTLSKeyFile  string `toml:"smtp_tls_key_file"`  // Client key for mTLS (optional)

	// HTTP API relay configuration
	HTTPURL   string `toml:"http_url"`   // HTTP API endpoint (e.g., "https://api.example.com/v1/mail/deliver")
	AuthToken string `toml:"auth_token"` // Bearer token for HTTP Authorization header

	// Queue configuration (nested under [relay.queue] in TOML)
	Queue RelayQueueConfig `toml:"queue"`
}

// RelayQueueConfig holds relay queue configuration for disk-based retry queue
type RelayQueueConfig struct {
	Path                      string   `toml:"path"`                         // Base path for queue storage (e.g., "/var/spool/sora/relay")
	WorkerInterval            string   `toml:"worker_interval"`              // How often worker processes queue (e.g., "1m")
	BatchSize                 int      `toml:"batch_size"`                   // Number of messages to process per worker cycle
	Concurrency               int      `toml:"concurrency"`                  // Number of concurrent messages to process (default: 5)
	MaxAttempts               int      `toml:"max_attempts"`                 // Maximum delivery attempts before moving to failed
	RetryBackoff              []string `toml:"retry_backoff"`                // Backoff durations between retries (e.g., ["1m", "5m", "15m", "1h", "6h", "24h"])
	CircuitBreakerThreshold   int      `toml:"circuit_breaker_threshold"`    // Consecutive failures before opening circuit (default: 5)
	CircuitBreakerTimeout     string   `toml:"circuit_breaker_timeout"`      // Recovery test interval (default: "30s")
	CircuitBreakerMaxRequests int      `toml:"circuit_breaker_max_requests"` // Max requests in half-open state (default: 3)
}

// IsConfigured returns true if the relay is configured
func (r *RelayConfig) IsConfigured() bool {
	return r.Type != ""
}

// IsSMTP returns true if this is an SMTP relay
func (r *RelayConfig) IsSMTP() bool {
	return r.Type == "smtp"
}

// IsHTTP returns true if this is an HTTP API relay
func (r *RelayConfig) IsHTTP() bool {
	return r.Type == "http"
}

// IsQueueEnabled returns true if relay is configured (queue is always enabled when relay is configured)
func (r *RelayConfig) IsQueueEnabled() bool {
	return r.IsConfigured()
}

// GetQueuePath returns the queue path with default if not set
func (r *RelayConfig) GetQueuePath() string {
	if r.Queue.Path != "" {
		return r.Queue.Path
	}
	return "/var/spool/sora/relay" // Default path
}

// GetWorkerInterval parses the worker interval duration
func (q *RelayQueueConfig) GetWorkerInterval() (time.Duration, error) {
	if q.WorkerInterval == "" {
		return 1 * time.Minute, nil // Default 1 minute
	}
	return helpers.ParseDuration(q.WorkerInterval)
}

// GetRetryBackoff parses the retry backoff durations
func (q *RelayQueueConfig) GetRetryBackoff() ([]time.Duration, error) {
	if len(q.RetryBackoff) == 0 {
		// Default exponential backoff
		return []time.Duration{
			1 * time.Minute,
			5 * time.Minute,
			15 * time.Minute,
			1 * time.Hour,
			6 * time.Hour,
			24 * time.Hour,
		}, nil
	}

	// Parse configured backoff durations
	backoff := make([]time.Duration, 0, len(q.RetryBackoff))
	for _, b := range q.RetryBackoff {
		d, err := helpers.ParseDuration(b)
		if err != nil {
			return nil, err
		}
		backoff = append(backoff, d)
	}
	return backoff, nil
}

// GetCircuitBreakerThreshold returns the circuit breaker failure threshold with default
func (q *RelayQueueConfig) GetCircuitBreakerThreshold() int {
	if q.CircuitBreakerThreshold <= 0 {
		return 5 // Default: open after 5 consecutive failures
	}
	return q.CircuitBreakerThreshold
}

// GetCircuitBreakerTimeout returns the circuit breaker timeout with default
func (q *RelayQueueConfig) GetCircuitBreakerTimeout() (time.Duration, error) {
	if q.CircuitBreakerTimeout == "" {
		return 30 * time.Second, nil // Default: 30s
	}
	return helpers.ParseDuration(q.CircuitBreakerTimeout)
}

// GetCircuitBreakerMaxRequests returns the max requests in half-open state with default
func (q *RelayQueueConfig) GetCircuitBreakerMaxRequests() int {
	if q.CircuitBreakerMaxRequests <= 0 {
		return 3 // Default: allow 3 requests in half-open
	}
	return q.CircuitBreakerMaxRequests
}
