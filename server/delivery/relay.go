package delivery

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/metrics"
)

// RelayError wraps an error with information about whether it's permanent or temporary.
// Permanent errors (5xx SMTP codes) should not be retried.
// Temporary errors (4xx SMTP codes, network errors) can be retried.
type RelayError struct {
	Err       error
	Permanent bool // true for 5xx errors, false for 4xx/network errors
}

func (e *RelayError) Error() string {
	if e.Permanent {
		return fmt.Sprintf("permanent failure: %v", e.Err)
	}
	return fmt.Sprintf("temporary failure: %v", e.Err)
}

func (e *RelayError) Unwrap() error {
	return e.Err
}

// IsPermanentError checks if an error is a permanent failure (5xx SMTP error).
// Returns true for 5xx errors, false for 4xx errors and network/connection errors.
func IsPermanentError(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's already wrapped as RelayError
	var relayErr *RelayError
	if errors.As(err, &relayErr) {
		return relayErr.Permanent
	}

	// Check for SMTP error
	var smtpErr *smtp.SMTPError
	if errors.As(err, &smtpErr) {
		// 5xx = permanent, 4xx = temporary (use Temporary() which returns true for 4xx)
		return !smtpErr.Temporary()
	}

	// Network errors, connection errors, etc. are temporary
	return false
}

// RelayHandler interface defines the contract for external relay operations.
type RelayHandler interface {
	SendToExternalRelay(from string, to string, messageBytes []byte) error
}

// SMTPRelayHandler implements SMTP relay with configurable TLS and circuit breaker.
type SMTPRelayHandler struct {
	SMTPHost       string
	UseTLS         bool   // Use TLS (default: true)
	TLSVerify      bool   // Verify TLS certificates (default: true)
	UseStartTLS    bool   // Use STARTTLS instead of direct TLS
	TLSCertFile    string // Client certificate for mTLS (optional)
	TLSKeyFile     string // Client key for mTLS (optional)
	MetricsLabel   string
	Logger         Logger
	CircuitBreaker *circuitbreaker.CircuitBreaker // Circuit breaker for resilience
}

// GetCircuitBreaker returns the circuit breaker for health monitoring
func (r *SMTPRelayHandler) GetCircuitBreaker() *circuitbreaker.CircuitBreaker {
	return r.CircuitBreaker
}

// SendToExternalRelay sends a message to the external SMTP relay with circuit breaker protection.
func (r *SMTPRelayHandler) SendToExternalRelay(from string, to string, messageBytes []byte) error {
	if r.SMTPHost == "" {
		return fmt.Errorf("SMTP relay host not configured")
	}

	// Wrap delivery in circuit breaker if available
	if r.CircuitBreaker != nil {
		_, err := r.CircuitBreaker.Execute(func() (any, error) {
			return nil, r.sendToSMTPRelay(from, to, messageBytes)
		})
		// Check if circuit breaker is open
		if errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) {
			logger.Warn("SMTP Relay: Circuit breaker is OPEN - skipping delivery", "host", r.SMTPHost)
			metrics.LMTPExternalRelay.WithLabelValues("circuit_breaker_open").Inc()
			return fmt.Errorf("SMTP relay circuit breaker is open: %w", err)
		}
		return err
	}

	// No circuit breaker, send directly
	return r.sendToSMTPRelay(from, to, messageBytes)
}

// sendToSMTPRelay performs the actual SMTP relay operation
func (r *SMTPRelayHandler) sendToSMTPRelay(from string, to string, messageBytes []byte) error {
	var c *smtp.Client
	var err error

	// Build TLS config
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		Renegotiation:      tls.RenegotiateNever,
		InsecureSkipVerify: !r.TLSVerify,
	}

	// Load client certificate if provided (for mTLS)
	if r.TLSCertFile != "" && r.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(r.TLSCertFile, r.TLSKeyFile)
		if err != nil {
			metrics.LMTPExternalRelay.WithLabelValues("failure").Inc()
			// Certificate loading errors are configuration errors (permanent)
			return &RelayError{Err: fmt.Errorf("failed to load client certificate: %w", err), Permanent: true}
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Connect based on TLS configuration
	if !r.UseTLS {
		// Plain connection (not recommended)
		c, err = smtp.Dial(r.SMTPHost)
		if err != nil {
			metrics.LMTPExternalRelay.WithLabelValues("failure").Inc()
			// Connection errors are temporary (network issue, server down)
			return &RelayError{Err: fmt.Errorf("failed to connect to SMTP relay: %w", err), Permanent: false}
		}
	} else if r.UseStartTLS {
		// Connect with STARTTLS (automatically upgrades to TLS)
		c, err = smtp.DialStartTLS(r.SMTPHost, tlsConfig)
		if err != nil {
			metrics.LMTPExternalRelay.WithLabelValues("failure").Inc()
			// Connection errors are temporary (network issue, server down)
			return &RelayError{Err: fmt.Errorf("failed to connect to SMTP relay with STARTTLS: %w", err), Permanent: false}
		}
	} else {
		// Direct TLS connection
		c, err = smtp.DialTLS(r.SMTPHost, tlsConfig)
		if err != nil {
			metrics.LMTPExternalRelay.WithLabelValues("failure").Inc()
			// Connection errors are temporary (network issue, server down)
			return &RelayError{Err: fmt.Errorf("failed to connect to SMTP relay with TLS: %w", err), Permanent: false}
		}
	}
	defer c.Close()

	// Defer the failure metric increment to avoid multiple calls.
	var relayErr error
	defer func() {
		if relayErr != nil {
			metrics.LMTPExternalRelay.WithLabelValues("failure").Inc()
		}
	}()

	if relayErr = c.Mail(from, nil); relayErr != nil {
		// Classify SMTP error (5xx = permanent, 4xx = temporary)
		return &RelayError{Err: fmt.Errorf("failed to set sender: %w", relayErr), Permanent: IsPermanentError(relayErr)}
	}
	if relayErr = c.Rcpt(to, nil); relayErr != nil {
		// Classify SMTP error (5xx = permanent, 4xx = temporary)
		return &RelayError{Err: fmt.Errorf("failed to set recipient: %w", relayErr), Permanent: IsPermanentError(relayErr)}
	}

	wc, relayErr := c.Data()
	if relayErr != nil {
		// Classify SMTP error (5xx = permanent, 4xx = temporary)
		return &RelayError{Err: fmt.Errorf("failed to start data: %w", relayErr), Permanent: IsPermanentError(relayErr)}
	}
	if _, relayErr = wc.Write(messageBytes); relayErr != nil {
		// Attempt to close the data writer even if write fails, to send the final dot.
		_ = wc.Close()
		// Write errors are typically I/O errors (temporary)
		return &RelayError{Err: fmt.Errorf("failed to write message: %w", relayErr), Permanent: false}
	}
	if relayErr = wc.Close(); relayErr != nil {
		// Classify SMTP error (5xx = permanent, 4xx = temporary)
		return &RelayError{Err: fmt.Errorf("failed to close data writer: %w", relayErr), Permanent: IsPermanentError(relayErr)}
	}

	if relayErr = c.Quit(); relayErr != nil {
		// Quit errors don't affect message delivery (already accepted), treat as non-fatal
		// Just log it but don't return error
		logger.Warn("SMTP Relay: Failed to send QUIT", "error", relayErr)
	}

	metrics.LMTPExternalRelay.WithLabelValues("success").Inc()
	return nil
}

// HTTPRelayHandler implements HTTP API relay with Bearer token authentication and circuit breaker.
type HTTPRelayHandler struct {
	HTTPURL        string
	AuthToken      string // Bearer token for Authorization header
	MetricsLabel   string
	Logger         Logger
	CircuitBreaker *circuitbreaker.CircuitBreaker // Circuit breaker for resilience
}

// GetCircuitBreaker returns the circuit breaker for health monitoring
func (r *HTTPRelayHandler) GetCircuitBreaker() *circuitbreaker.CircuitBreaker {
	return r.CircuitBreaker
}

// HTTPRelayRequest represents the HTTP API relay request payload
type HTTPRelayRequest struct {
	From       string   `json:"from"`
	Recipients []string `json:"recipients"`
	Message    string   `json:"message"` // RFC822 message as string
}

// SendToExternalRelay sends a message to the external HTTP API with circuit breaker protection.
func (r *HTTPRelayHandler) SendToExternalRelay(from string, to string, messageBytes []byte) error {
	if r.HTTPURL == "" {
		return fmt.Errorf("HTTP relay URL not configured")
	}

	// Wrap delivery in circuit breaker if available
	if r.CircuitBreaker != nil {
		_, err := r.CircuitBreaker.Execute(func() (any, error) {
			return nil, r.sendToHTTPRelay(from, to, messageBytes)
		})
		// Check if circuit breaker is open
		if errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) {
			logger.Warn("HTTP Relay: Circuit breaker is OPEN - skipping delivery", "url", r.HTTPURL)
			metrics.LMTPExternalRelay.WithLabelValues("circuit_breaker_open").Inc()
			return fmt.Errorf("HTTP relay circuit breaker is open: %w", err)
		}
		return err
	}

	// No circuit breaker, send directly
	return r.sendToHTTPRelay(from, to, messageBytes)
}

// sendToHTTPRelay performs the actual HTTP relay operation
func (r *HTTPRelayHandler) sendToHTTPRelay(from string, to string, messageBytes []byte) error {
	// Create request payload
	payload := HTTPRelayRequest{
		From:       from,
		Recipients: []string{to},
		Message:    string(messageBytes),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		metrics.LMTPExternalRelay.WithLabelValues("failure").Inc()
		// Marshal errors are programming errors (permanent)
		return &RelayError{Err: fmt.Errorf("failed to marshal relay request: %w", err), Permanent: true}
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", r.HTTPURL, bytes.NewBuffer(jsonData))
	if err != nil {
		metrics.LMTPExternalRelay.WithLabelValues("failure").Inc()
		// Invalid URL is a configuration error (permanent)
		return &RelayError{Err: fmt.Errorf("failed to create HTTP request: %w", err), Permanent: true}
	}

	req.Header.Set("Content-Type", "application/json")
	if r.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+r.AuthToken)
	}

	// Send request with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		metrics.LMTPExternalRelay.WithLabelValues("failure").Inc()
		// Network/connection errors are temporary
		return &RelayError{Err: fmt.Errorf("failed to send HTTP relay request: %w", err), Permanent: false}
	}
	defer resp.Body.Close()

	// Check response status
	// HTTP 5xx = server error (temporary, server may recover)
	// HTTP 4xx = client error (permanent, e.g., bad auth, invalid request)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		metrics.LMTPExternalRelay.WithLabelValues("failure").Inc()
		permanent := resp.StatusCode >= 400 && resp.StatusCode < 500 // 4xx = permanent
		return &RelayError{
			Err:       fmt.Errorf("HTTP relay returned error status: %d", resp.StatusCode),
			Permanent: permanent,
		}
	}

	metrics.LMTPExternalRelay.WithLabelValues("success").Inc()
	return nil
}

// CircuitBreakerConfig holds circuit breaker configuration
type CircuitBreakerConfig struct {
	Threshold   int           // Consecutive failures before opening (default: 5)
	Timeout     time.Duration // Recovery test interval (default: 30s)
	MaxRequests int           // Max requests in half-open state (default: 3)
}

// NewRelayHandlerFromConfig creates the appropriate relay handler based on configuration with circuit breaker
func NewRelayHandlerFromConfig(relayType, smtpHost, httpURL, httpToken, metricsLabel string, useTLS, tlsVerify, useStartTLS bool, tlsCertFile, tlsKeyFile string, logger Logger, cbConfig CircuitBreakerConfig) RelayHandler {
	// Apply defaults if not set
	if cbConfig.Threshold <= 0 {
		cbConfig.Threshold = 5
	}
	if cbConfig.Timeout <= 0 {
		cbConfig.Timeout = 30 * time.Second
	}
	if cbConfig.MaxRequests <= 0 {
		cbConfig.MaxRequests = 3
	}

	switch relayType {
	case "smtp":
		// Create circuit breaker for SMTP relay
		cb := circuitbreaker.NewCircuitBreaker(circuitbreaker.Settings{
			Name:        "smtp_relay",
			MaxRequests: uint32(cbConfig.MaxRequests),
			Interval:    10 * time.Second,
			Timeout:     cbConfig.Timeout,
			ReadyToTrip: func(counts circuitbreaker.Counts) bool {
				return counts.ConsecutiveFailures >= uint32(cbConfig.Threshold)
			},
			OnStateChange: func(name string, from circuitbreaker.State, to circuitbreaker.State) {
				if logger != nil {
					logger.Log(fmt.Sprintf("[SMTP Relay] Circuit breaker '%s' changed from %s to %s", name, from, to))
				}
			},
			IsSuccessful: func(err error) bool {
				return err == nil
			},
		})

		return &SMTPRelayHandler{
			SMTPHost:       smtpHost,
			UseTLS:         useTLS,
			TLSVerify:      tlsVerify,
			UseStartTLS:    useStartTLS,
			TLSCertFile:    tlsCertFile,
			TLSKeyFile:     tlsKeyFile,
			MetricsLabel:   metricsLabel,
			Logger:         logger,
			CircuitBreaker: cb,
		}
	case "http":
		// Create circuit breaker for HTTP relay
		cb := circuitbreaker.NewCircuitBreaker(circuitbreaker.Settings{
			Name:        "http_relay",
			MaxRequests: uint32(cbConfig.MaxRequests),
			Interval:    10 * time.Second,
			Timeout:     cbConfig.Timeout,
			ReadyToTrip: func(counts circuitbreaker.Counts) bool {
				return counts.ConsecutiveFailures >= uint32(cbConfig.Threshold)
			},
			OnStateChange: func(name string, from circuitbreaker.State, to circuitbreaker.State) {
				if logger != nil {
					logger.Log(fmt.Sprintf("[HTTP Relay] Circuit breaker '%s' changed from %s to %s", name, from, to))
				}
			},
			IsSuccessful: func(err error) bool {
				return err == nil
			},
		})

		return &HTTPRelayHandler{
			HTTPURL:        httpURL,
			AuthToken:      httpToken,
			MetricsLabel:   metricsLabel,
			Logger:         logger,
			CircuitBreaker: cb,
		}
	default:
		return nil
	}
}
