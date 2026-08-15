package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// okHandler stands in for the Prometheus handler and records whether the guard
// let the request through - a guard that returns 200 without reaching this has
// not actually protected anything.
func okHandler(reached *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("sora_up 1\n"))
	})
}

func TestMetricsAccessGuard(t *testing.T) {
	const apiKey = "s3cr3t-scrape-key"

	tests := []struct {
		name         string
		allowedHosts []string
		apiKey       string
		remoteAddr   string
		authHeader   string
		wantStatus   int
	}{
		{
			// Pre-existing behaviour: nothing configured, endpoint stays open.
			// Upgrading must not break an unconfigured scrape.
			name:       "no controls configured serves metrics",
			remoteAddr: "203.0.113.9:51000",
			wantStatus: http.StatusOK,
		},
		{
			name:         "allowed host matches CIDR",
			allowedHosts: []string{"10.0.0.0/8"},
			remoteAddr:   "10.4.2.1:51000",
			wantStatus:   http.StatusOK,
		},
		{
			name:         "allowed host matches bare IP",
			allowedHosts: []string{"192.0.2.10"},
			remoteAddr:   "192.0.2.10:51000",
			wantStatus:   http.StatusOK,
		},
		{
			name:         "host outside allow-list is refused",
			allowedHosts: []string{"10.0.0.0/8"},
			remoteAddr:   "203.0.113.9:51000",
			wantStatus:   http.StatusForbidden,
		},
		{
			name:         "IPv6 allow-list matches by value",
			allowedHosts: []string{"2001:db8::/32"},
			remoteAddr:   "[2001:db8::1]:51000",
			wantStatus:   http.StatusOK,
		},
		{
			name:         "IPv6 outside allow-list is refused",
			allowedHosts: []string{"2001:db8::/32"},
			remoteAddr:   "[2001:db9::1]:51000",
			wantStatus:   http.StatusForbidden,
		},
		{
			name:       "missing token is unauthorized",
			apiKey:     apiKey,
			remoteAddr: "10.4.2.1:51000",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "non-bearer scheme is unauthorized",
			apiKey:     apiKey,
			remoteAddr: "10.4.2.1:51000",
			authHeader: "Basic " + apiKey,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong token is refused",
			apiKey:     apiKey,
			remoteAddr: "10.4.2.1:51000",
			authHeader: "Bearer wrong-key",
			wantStatus: http.StatusForbidden,
		},
		{
			// A prefix of the real key must not pass: the comparison is over the
			// whole value, not a prefix match.
			name:       "token prefix is refused",
			apiKey:     apiKey,
			remoteAddr: "10.4.2.1:51000",
			authHeader: "Bearer " + apiKey[:len(apiKey)-1],
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "correct token is accepted",
			apiKey:     apiKey,
			remoteAddr: "10.4.2.1:51000",
			authHeader: "Bearer " + apiKey,
			wantStatus: http.StatusOK,
		},
		{
			name:       "bearer scheme is case-insensitive",
			apiKey:     apiKey,
			remoteAddr: "10.4.2.1:51000",
			authHeader: "bearer " + apiKey,
			wantStatus: http.StatusOK,
		},
		{
			// Both controls are enforced, not either-or.
			name:         "allowed host still needs the token",
			allowedHosts: []string{"10.0.0.0/8"},
			apiKey:       apiKey,
			remoteAddr:   "10.4.2.1:51000",
			wantStatus:   http.StatusUnauthorized,
		},
		{
			name:         "valid token from a disallowed host is refused",
			allowedHosts: []string{"10.0.0.0/8"},
			apiKey:       apiKey,
			remoteAddr:   "203.0.113.9:51000",
			authHeader:   "Bearer " + apiKey,
			wantStatus:   http.StatusForbidden,
		},
		{
			name:         "both controls satisfied",
			allowedHosts: []string{"10.0.0.0/8"},
			apiKey:       apiKey,
			remoteAddr:   "10.4.2.1:51000",
			authHeader:   "Bearer " + apiKey,
			wantStatus:   http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reached bool
			guard := metricsAccessGuard(tt.allowedHosts, tt.apiKey, okHandler(&reached))

			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rec := httptest.NewRecorder()
			guard.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if want := tt.wantStatus == http.StatusOK; reached != want {
				t.Errorf("handler reached = %v, want %v", reached, want)
			}
		})
	}
}

// TestMetricsAccessGuard_IgnoresForwardedHeaders pins that the allow-list reads
// the socket peer only. The metrics listener does not parse PROXY protocol, so
// an X-Forwarded-For an attacker sets must not talk its way past allowed_hosts.
func TestMetricsAccessGuard_IgnoresForwardedHeaders(t *testing.T) {
	var reached bool
	guard := metricsAccessGuard([]string{"10.0.0.0/8"}, "", okHandler(&reached))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "203.0.113.9:51000"
	req.Header.Set("X-Forwarded-For", "10.0.0.5")
	req.Header.Set("X-Real-IP", "10.0.0.5")

	rec := httptest.NewRecorder()
	guard.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d - forwarded headers must not be trusted", rec.Code, http.StatusForbidden)
	}
	if reached {
		t.Error("handler must not be reached for a spoofed forwarded address")
	}
}

func TestBearerToken(t *testing.T) {
	tests := []struct {
		header    string
		wantToken string
		wantOK    bool
	}{
		{"Bearer abc123", "abc123", true},
		{"bearer abc123", "abc123", true},
		{"BEARER abc123", "abc123", true},
		{"Bearer   abc123  ", "abc123", true},
		{"", "", false},
		{"abc123", "", false},
		{"Basic abc123", "", false},
		{"Bearer", "", false},
		{"Bearer ", "", false},
	}

	for _, tt := range tests {
		token, ok := bearerToken(tt.header)
		if ok != tt.wantOK || token != tt.wantToken {
			t.Errorf("bearerToken(%q) = (%q, %v), want (%q, %v)", tt.header, token, ok, tt.wantToken, tt.wantOK)
		}
	}
}
