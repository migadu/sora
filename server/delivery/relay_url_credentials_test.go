package delivery

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/circuitbreaker"
)

// closedRelayAddr returns a loopback address nothing listens on.
func closedRelayAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// TestHTTPRelayErrorsHideURLCredentials: http_url may carry the relay's credentials
// in its userinfo or query, and a failed send's error is logged by the relay queue.
// net/http quotes the URL in its errors with the user name and the query, and a URL
// that does not parse is quoted whole, its reason a piece of it (#806).
func TestHTTPRelayErrorsHideURLCredentials(t *testing.T) {
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// An http-to-https redirect repeats the request URL, query included.
		location := "https://fixture-user:fixture-password@relay.example.invalid" + r.URL.RequestURI()
		if r.URL.Path == "/malformed" {
			location = "https://fixture-user:fixture/password@relay.example.invalid/send?api_key=fixture-query-secret"
		}
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer redirect.Close()
	redirectHost := strings.TrimPrefix(redirect.URL, "http://")

	for _, tc := range []struct{ name, url string }{
		{"connection refused", "http://fixture-user:fixture-password@" + closedRelayAddr(t) + "/send?api_key=fixture-query-secret"},
		{"unparsable", "https://fixture-user:fixture/password@relay.example.invalid/send"},
		{"redirect", "http://fixture-user:fixture-password@" + redirectHost + "/send?api_key=fixture-query-secret"},
		{"malformed redirect", redirect.URL + "/malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &HTTPRelayHandler{HTTPURL: tc.url}
			err := h.SendToExternalRelay("a@example.com", "b@example.com", []byte("Subject: x\r\n\r\nbody"))
			if err == nil {
				t.Fatal("send succeeded, want an error")
			}
			if strings.Contains(err.Error(), "fixture") {
				t.Errorf("error quotes the relay's credentials: %v", err)
			}
		})
	}
}

// TestHTTPRelayCircuitBreakerLogHidesURLCredentials: the warning for a delivery the
// open breaker refuses names http_url as the config dump shows it (#806).
func TestHTTPRelayCircuitBreakerLogHidesURLCredentials(t *testing.T) {
	logs := captureLogger(t)
	httpURL := "http://fixture-user:fixture-password@" + closedRelayAddr(t) + "/send?api_key=fixture-query-secret"
	h := NewRelayHandlerFromConfig("http", "", httpURL, "", "test", false, false, false, "", "", "", nil,
		CircuitBreakerConfig{Threshold: 1, Timeout: time.Minute, MaxRequests: 1})
	_ = h.SendToExternalRelay("a@example.com", "b@example.com", []byte("Subject: x\r\n\r\nbody"))
	err := h.SendToExternalRelay("a@example.com", "b@example.com", []byte("Subject: x\r\n\r\nbody"))
	if !errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) {
		t.Fatalf("second send = %v, want the open breaker's refusal", err)
	}
	logged := logs.String()
	if !strings.Contains(logged, "Circuit breaker is OPEN") {
		t.Fatalf("no circuit breaker warning logged:\n%s", logged)
	}
	if strings.Contains(logged, "fixture") {
		t.Errorf("log quotes the relay's credentials:\n%s", logged)
	}
}
