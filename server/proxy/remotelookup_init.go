package proxy

import (
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
)

// validateRemoteLookupURL requires https:// for non-loopback hosts. A plaintext
// remote-lookup endpoint exposes the user's password and the returned password hash
// to an on-path attacker, who can also forge the backend-routing response.
func validateRemoteLookupURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid remotelookup.url: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil // http:// allowed only to loopback (dev/test)
	}
	return fmt.Errorf("remotelookup.url must use https:// for non-loopback hosts (got scheme %q); plaintext exposes credentials and password hashes", u.Scheme)
}

// standardBackendPorts are the ports the backends listen on by default (as in
// config.toml.example). The User API has none: a port-less address there takes the
// port of the URL scheme, as a port-less remote_addrs entry does.
var standardBackendPorts = map[string]int{
	"imap":        143,
	"pop3":        110,
	"managesieve": 4190,
	"lmtp":        24,
}

// implicitTLSBackendPorts are the registered implicit TLS ports (RFC 8314 §3.1 "pop3s"
// 995, §3.2 "imaps" 993), used when the lookup's backend leg is remote_tls without
// STARTTLS. ManageSieve and LMTP have no such port and keep their standard one.
var implicitTLSBackendPorts = map[string]int{
	"imap": 993,
	"pop3": 995,
}

// InitializeRemoteLookup creates an HTTP remotelookup client from configuration.
// serverRemotePort is the proxy's own remote_port (0 when unset).
func InitializeRemoteLookup(protocol string, cfg *config.RemoteLookupConfig, serverRemotePort int) (UserRoutingLookup, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	if cfg.URL == "" {
		return nil, fmt.Errorf("remotelookup.url is required when remotelookup is enabled")
	}
	if err := validateRemoteLookupURL(cfg.URL); err != nil {
		return nil, err
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
				var err error
				remotePort, err = strconv.Atoi(v)
				if err != nil {
					logger.Debug("RemoteLookup: Warning - failed to parse remote_port, using default", "value", v)
					remotePort = 0
				}
			}
		default:
			logger.Debug("RemoteLookup: Warning - remote_port has unexpected type, using default", "type", fmt.Sprintf("%T", v))
		}
	}
	// A lookup answer naming a server without a port is dialed at the lookup's own
	// remote_port, else at the proxy's remote_port (what its port-less pool and
	// remote_addrs backends get), else at the protocol's standard port for the backend
	// leg this lookup configures (implicit TLS or not).
	if remotePort == 0 {
		remotePort = serverRemotePort
	}
	if remotePort == 0 && cfg.RemoteTLS && !cfg.RemoteTLSUseStartTLS {
		remotePort = implicitTLSBackendPorts[protocol]
	}
	if remotePort == 0 {
		remotePort = standardBackendPorts[protocol]
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
		cfg.RemoteUseUTF8,
		cbSettings,
		transportSettings,
	)

	return client, nil
}
