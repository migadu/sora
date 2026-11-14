package userapiproxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestProxyRequestBareIPv6Backend: a backend address without a port (a lookup "server"
// or a remote_addrs entry, with no remote_port configured) takes the URL scheme's port.
// A bare IPv6 literal has to be bracketed in the URL for that; unbracketed, url.Parse
// rejected "http://2001:db8::21" and every request for the user failed with a 500.
func TestProxyRequestBareIPv6Backend(t *testing.T) {
	var gotHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}

	var dialed string
	s := &Server{
		name:        "test",
		connManager: newUserAPITestConnManager(t, backendURL.Host),
		transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = addr
			var d net.Dialer
			return d.DialContext(ctx, network, backendURL.Host)
		}},
	}

	w := httptest.NewRecorder()
	s.proxyRequest(w, httptest.NewRequest(http.MethodGet, "http://original.example.com/user/mailboxes", nil), backendRoute{addr: "2001:db8::21"})

	if w.Code != http.StatusOK {
		t.Fatalf("backend not reached: status %d, body %q", w.Code, w.Body.String())
	}
	if dialed != "[2001:db8::21]:80" {
		t.Errorf("dialed %q, want %q", dialed, "[2001:db8::21]:80")
	}
	if gotHost != "[2001:db8::21]" {
		t.Errorf("backend Host = %q, want %q", gotHost, "[2001:db8::21]")
	}
}
