package proxy

import (
	"fmt"
	"log"

	"github.com/migadu/sora/config"
)

// InitializePrelookup creates an HTTP prelookup client from configuration
func InitializePrelookup(cfg *config.PreLookupConfig) (UserRoutingLookup, error) {
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
					log.Printf("[Prelookup] Warning: failed to parse remote_port %q as integer, using default", v)
					remotePort = 0
				}
			}
		default:
			log.Printf("[Prelookup] Warning: remote_port has unexpected type %T, using default", v)
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

		cache = newPrelookupCache(positiveTTL, negativeTTL, maxSize, cleanupInterval)
	}

	log.Printf("[Prelookup] Initializing HTTP prelookup: url=%s, timeout=%s, remote_port=%d, cache_enabled=%v",
		cfg.URL, timeout, remotePort, cacheEnabled)

	client := NewHTTPPreLookupClient(
		cfg.URL,
		timeout,
		remotePort,
		cfg.RemoteTLS,
		cfg.RemoteTLSUseStartTLS,
		remoteTLSVerify,
		cfg.RemoteUseProxyProtocol,
		cfg.RemoteUseIDCommand,
		cfg.RemoteUseXCLIENT,
		cache,
	)

	return client, nil
}
