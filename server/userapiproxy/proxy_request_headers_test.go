package userapiproxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server/proxy"
)

func newUserAPITestConnManager(t *testing.T, addr string) *proxy.ConnectionManager {
	t.Helper()
	cm, err := proxy.NewConnectionManager([]string{addr}, 80, false, false, false, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}
	return cm
}

// TestProxyRequestForwardsOriginalHost verifies that X-Forwarded-Host carries
// the client's original Host. Regression test for the User API proxy review
// (2026-07-03): the code used r.Header.Get("Host"), but the request Host lives
// in r.Host, never in r.Header — so X-Forwarded-Host was always empty.
func TestProxyRequestForwardsOriginalHost(t *testing.T) {
	var gotForwardedHost, gotRealIP string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotForwardedHost = r.Header.Get("X-Forwarded-Host")
		gotRealIP = r.Header.Get("X-Real-IP")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}
	backendAddr := backendURL.Host

	s := &Server{
		name:        "test",
		connManager: newUserAPITestConnManager(t, backendAddr),
		transport:   &http.Transport{},
	}

	r := httptest.NewRequest(http.MethodGet, "http://original.example.com/user/mailboxes", nil)
	if r.Host != "original.example.com" {
		t.Fatalf("test setup: expected request host original.example.com, got %q", r.Host)
	}
	w := httptest.NewRecorder()

	s.proxyRequest(w, r, backendAddr)

	if w.Code != http.StatusOK {
		t.Fatalf("backend not reached: status %d, body %q", w.Code, w.Body.String())
	}
	if gotForwardedHost != "original.example.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q (was always empty before the fix)", gotForwardedHost, "original.example.com")
	}
	// httptest.NewRequest sets RemoteAddr to 192.0.2.1:1234
	if !strings.HasPrefix(gotRealIP, "192.0.2.1") {
		t.Errorf("X-Real-IP = %q, want client IP 192.0.2.1", gotRealIP)
	}
}
