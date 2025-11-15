package proxy

import (
	"fmt"
	"github.com/migadu/sora/logger"

	"github.com/migadu/sora/config"
)

// InitializePrelookup creates an HTTP prelookup client from configuration
func InitializePrelookup(protocol string, cfg *config.PreLookupConfig) (UserRoutingLookup, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	if cfg.URL == "" {
		return nil, fmt.Errorf("prelookup.url is required when prelookup is enabled")
	}

	// Get HTTP timeout
	timeout, err := cfg.GetTimeout()
	if err != nil {
		return nil, fmt.Errorf("invalid prelookup timeout: %w", err)
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
					logger.Debug("Prelookup: Warning - failed to parse remote_port, using default", "value", v)
					remotePort = 0
				}
			}
		default:
			logger.Debug("Prelookup: Warning - remote_port has unexpected type, using default", "type", fmt.Sprintf("%T", v))
		}
	}

	// Initialize cache if enabled
	var cache *prelookupCache
	cacheEnabled := false
	if cfg.Cache != nil && cfg.Cache.Enabled {
		cacheEnabled = true
		positiveTTL, err := cfg.Cache.GetPositiveTTL()
		if err != nil {
			return nil, fmt.Errorf("invalid cache.positive_ttl: %w", err)
		}

		negativeTTL, err := cfg.Cache.GetNegativeTTL()
		if err != nil {
			return nil, fmt.Errorf("invalid cache.negative_ttl: %w", err)
		}

		cleanupInterval, err := cfg.Cache.GetCleanupInterval()
		if err != nil {
			return nil, fmt.Errorf("invalid cache.cleanup_interval: %w", err)
		}

		maxSize := cfg.Cache.MaxSize
		if maxSize <= 0 {
			maxSize = 10000 // Default
		}

		cache = newPrelookupCache(protocol, positiveTTL, negativeTTL, maxSize, cleanupInterval)
	}

	hasAuth := cfg.AuthToken != ""
	logger.Debug("Prelookup: Initializing HTTP prelookup", "url", cfg.URL, "timeout", timeout, "remote_port", remotePort, "cache_enabled", cacheEnabled, "auth_enabled", hasAuth)

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
	// If nil, NewHTTPPreLookupClient will use defaults

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
	// If nil, NewHTTPPreLookupClient will use defaults

	client := NewHTTPPreLookupClient(
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
		cache,
		cbSettings,
		transportSettings,
	)

	return client, nil
}
