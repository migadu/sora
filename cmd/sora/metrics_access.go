package main

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"

	"github.com/migadu/sora/helpers"
)

// metricsAccessGuard wraps the Prometheus handler with the access controls
// configured on a metrics listener:
//
//   - allowed_hosts: IP/CIDR allow-list, matched against the real socket peer
//     (r.RemoteAddr). X-Forwarded-For and friends are deliberately ignored -
//     they are attacker-controlled, and the metrics listener does not parse
//     PROXY protocol, so the peer address is always the connecting host.
//   - api_key: bearer token, compared in constant time.
//
// Both are optional and enforced independently, host first: with both set a
// request must come from an allowed host AND carry the token. With neither set
// the endpoint is served unauthenticated, as it always has been - failing
// closed here would take every existing scrape down on upgrade. That case is
// warned about at startup instead (see the "metrics" arm in main).
//
// Sora's metrics carry per-domain and optionally per-user activity, plus a
// detailed picture of internal state, so treat the endpoint as sensitive on any
// network that is not fully trusted.
func metricsAccessGuard(allowedHosts []string, apiKey string, next http.Handler) http.Handler {
	if len(allowedHosts) == 0 && apiKey == "" {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(allowedHosts) > 0 {
			if !helpers.IPInNetworks(net.ParseIP(metricsClientIP(r)), allowedHosts) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}

		if apiKey != "" {
			token, ok := bearerToken(r.Header.Get("Authorization"))
			if !ok {
				w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if subtle.ConstantTimeCompare([]byte(token), []byte(apiKey)) != 1 {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// metricsClientIP returns the peer IP of the request, without the port.
func metricsClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr may already be a bare IP (httptest, unix sockets).
		return r.RemoteAddr
	}
	return host
}

// bearerToken extracts the credentials from an "Authorization: Bearer <token>"
// header. The scheme is case-insensitive per RFC 7235.
func bearerToken(header string) (string, bool) {
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	return token, true
}
