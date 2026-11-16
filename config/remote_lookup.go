package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Validate checks what a proxy needs from an enabled [server.remote_lookup] to build its
// lookup client: the URL, the durations and remote_port. Nothing here needs the network,
// so ServerConfig.Validate (start-up, SIGHUP reload and sora-admin config validate) runs
// it, and so does proxy.InitializeRemoteLookup: the file is refused by the same checks
// wherever it is read.
func (c *RemoteLookupConfig) Validate() error {
	if c.URL == "" {
		return fmt.Errorf("remote_lookup.url is required when remote_lookup is enabled")
	}
	if err := validateRemoteLookupURL(c.URL); err != nil {
		return err
	}
	if _, err := c.GetTimeout(); err != nil {
		return fmt.Errorf("invalid remote_lookup.timeout: %w", err)
	}
	if _, err := c.GetRemotePort(); err != nil {
		return fmt.Errorf("invalid remote_lookup.remote_port: %w", err)
	}
	if cb := c.CircuitBreaker; cb != nil {
		if _, err := cb.GetTimeout(); err != nil {
			return fmt.Errorf("invalid remote_lookup.circuit_breaker.timeout: %w", err)
		}
		if _, err := cb.GetInterval(); err != nil {
			return fmt.Errorf("invalid remote_lookup.circuit_breaker.interval: %w", err)
		}
	}
	if tr := c.Transport; tr != nil {
		for _, d := range []struct {
			key   string
			parse func() (time.Duration, error)
		}{
			{"idle_conn_timeout", tr.GetIdleConnTimeout},
			{"dial_timeout", tr.GetDialTimeout},
			{"tls_handshake_timeout", tr.GetTLSHandshakeTimeout},
			{"expect_continue_timeout", tr.GetExpectContinueTimeout},
			{"keep_alive", tr.GetKeepAlive},
		} {
			if _, err := d.parse(); err != nil {
				return fmt.Errorf("invalid remote_lookup.transport.%s: %w", d.key, err)
			}
		}
	}
	return nil
}

// validateRemoteLookupURL checks that the template yields a request URL for every
// lookup, and requires https:// for non-loopback hosts. A plaintext remote-lookup
// endpoint exposes the user's password and the returned password hash to an on-path
// attacker, who can also forge the backend-routing response.
//
// The template itself parsing is not enough: the client substitutes $email and $ip
// with url.QueryEscape, so in the host they become %40 or %3A, which net/url refuses,
// and every lookup would fail before a request is sent. Placeholders therefore belong
// in the path and query. There the substituted values always parse: QueryEscape
// leaves only unreserved characters, '+' and %XX escapes, none of which can end a
// component or is refused outside the host.
func validateRemoteLookupURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid remote_lookup.url: %w", MaskURLError(err))
	}
	if u.Hostname() == "" {
		return fmt.Errorf("invalid remote_lookup.url: no host")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid remote_lookup.url: scheme must be http or https (got %q)", u.Scheme)
	}
	for _, placeholder := range []string{"$email", "$ip"} {
		if strings.Contains(u.Host, placeholder) {
			return fmt.Errorf("invalid remote_lookup.url: %s is allowed only in the path and query, not in the host %q", placeholder, u.Host)
		}
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil // http:// allowed only to loopback (dev/test)
	}
	return fmt.Errorf("remote_lookup.url must use https:// for non-loopback hosts (got scheme %q); plaintext exposes credentials and password hashes", u.Scheme)
}

// RemoteLookupRequestURL builds a lookup request URL from the configured template by
// interpolating its placeholders:
//   - $email: user email (MasterAddress - includes master token but not +detail)
//   - $ip: client IP address; empty when the caller has none, never the literal placeholder
func RemoteLookupRequestURL(template, email, clientIP string, routeOnly bool) string {
	requestURL := strings.ReplaceAll(template, "$email", url.QueryEscape(email))
	requestURL = strings.ReplaceAll(requestURL, "$ip", url.QueryEscape(clientIP))

	// Add route_only parameter if requested (for master username authentication)
	if routeOnly {
		// A fragment is not sent to the server, so append to the query before it.
		request, fragment, hasFragment := strings.Cut(requestURL, "#")
		// Check if URL already has query parameters
		if strings.Contains(request, "?") {
			request += "&route_only=true"
		} else {
			request += "?route_only=true"
		}
		requestURL = request
		if hasFragment {
			requestURL += "#" + fragment
		}
	}
	return requestURL
}
