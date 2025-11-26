package proxy

import (
	"fmt"
	"github.com/migadu/sora/logger"

	"github.com/migadu/sora/config"
)

// InitializeRemoteLookup creates an HTTP remotelookup client from configuration
func InitializeRemoteLookup(protocol string, cfg *config.RemoteLookupConfig) (UserRoutingLookup, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	if cfg.URL == "" {
		return nil, fmt.Errorf("remotelookup.url is required when remotelookup is enabled")
	}

	// Get HTTP timeout
	timeout, err := cfg.GetTimeout()
	if err != nil {
		return nil, fmt.Errorf("invalid remotelookup timeout: %w", err)
	}

	// Get remote TLS verification setting
	remoteTLSVerify := true
	if cfg.RemoteTLSVerify != nil {
		remoteTLSVerify = *cfg.RemoteTLSVerify
	}

	// Parse remote port (can be int or string)
	remotePort := 0
	if cfg.RemotePort != nil {
		switch v := cfg.RemotePort.(type) {
		case int:
			remotePort = v
		case int64:
			remotePort = int(v)
		case string:
			// Try to parse string as int
			if v != "" {
				parsed, err := fmt.Sscanf(v, "%d", &remotePort)
				if err != nil || parsed != 1 {
					logger.Debug("RemoteLookup: Warning - failed to parse remote_port, using default", "value", v)
					remotePort = 0
				}
			}
		default:
			logger.Debug("RemoteLookup: Warning - remote_port has unexpected type, using default", "type", fmt.Sprintf("%T", v))
		}
	}

	hasAuth := cfg.AuthToken != ""
	logger.Debug("RemoteLookup: Initializing HTTP remotelookup (NO caching)", "url", cfg.URL, "timeout", timeout, "remote_port", remotePort, "auth_enabled", hasAuth)

	// Parse circuit breaker settings
	var cbSettings *CircuitBreakerSettings
	if cfg.CircuitBreaker != nil {
		cbTimeout, err := cfg.CircuitBreaker.GetTimeout()
		if err != nil {
			return nil, fmt.Errorf("invalid circuit_breaker.timeout: %w", err)
		}
		cbInterval, err := cfg.CircuitBreaker.GetInterval()
		if err != nil {
			return nil, fmt.Errorf("invalid circuit_breaker.interval: %w", err)
		}

		cbSettings = &CircuitBreakerSettings{
			MaxRequests:  cfg.CircuitBreaker.GetMaxRequests(),
			Interval:     cbInterval,
			Timeout:      cbTimeout,
			FailureRatio: cfg.CircuitBreaker.GetFailureRatio(),
			MinRequests:  cfg.CircuitBreaker.GetMinRequests(),
		}
	}
	// If nil, NewHTTPRemoteLookupClient will use defaults

	// Parse transport settings
	var transportSettings *TransportSettings
	if cfg.Transport != nil {
		idleConnTimeout, err := cfg.Transport.GetIdleConnTimeout()
		if err != nil {
			return nil, fmt.Errorf("invalid transport.idle_conn_timeout: %w", err)
		}
		dialTimeout, err := cfg.Transport.GetDialTimeout()
		if err != nil {
			return nil, fmt.Errorf("invalid transport.dial_timeout: %w", err)
		}
		tlsHandshakeTimeout, err := cfg.Transport.GetTLSHandshakeTimeout()
		if err != nil {
			return nil, fmt.Errorf("invalid transport.tls_handshake_timeout: %w", err)
		}
		expectContinueTimeout, err := cfg.Transport.GetExpectContinueTimeout()
		if err != nil {
			return nil, fmt.Errorf("invalid transport.expect_continue_timeout: %w", err)
		}
		keepAlive, err := cfg.Transport.GetKeepAlive()
		if err != nil {
			return nil, fmt.Errorf("invalid transport.keep_alive: %w", err)
		}

		transportSettings = &TransportSettings{
			MaxIdleConns:          cfg.Transport.GetMaxIdleConns(),
			MaxIdleConnsPerHost:   cfg.Transport.GetMaxIdleConnsPerHost(),
			MaxConnsPerHost:       cfg.Transport.GetMaxConnsPerHost(),
			IdleConnTimeout:       idleConnTimeout,
			DialTimeout:           dialTimeout,
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ExpectContinueTimeout: expectContinueTimeout,
			KeepAlive:             keepAlive,
		}
	}
	// If nil, NewHTTPRemoteLookupClient will use defaults

	client := NewHTTPRemoteLookupClient(
		cfg.URL,
		timeout,
		cfg.AuthToken,
		remotePort,
		cfg.RemoteTLS,
		cfg.RemoteTLSUseStartTLS,
		remoteTLSVerify,
		cfg.RemoteUseProxyProtocol,
		cfg.RemoteUseIDCommand,
		cfg.RemoteUseXCLIENT,
		cbSettings,
		transportSettings,
	)

	return client, nil
}
