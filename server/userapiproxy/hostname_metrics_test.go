package userapiproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/proxy"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The proxy's connection metrics carry the node's hostname like every other server's,
// so series from different nodes can be told apart without the scrape target. They
// were always labelled hostname="" (#299).
func TestUserAPIProxy_ConnectionMetricsCarryTheNodeHostname(t *testing.T) {
	name := t.Name()
	s, err := New(context.Background(), &resilient.ResilientDatabase{}, ServerOptions{
		Name:        name,
		Addr:        "127.0.0.1:0",
		RemoteAddrs: []string{"127.0.0.1:1"},
		JWTSecret:   strings.Repeat("x", 32),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.cancel() })
	// The maintenance list is not loaded, so the request is refused right after it is
	// counted, without reaching a backend.
	s.connManager.SetMaintenance(proxy.NewMaintenance())

	rec := httptest.NewRecorder()
	s.setupHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/user/mailboxes", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", rec.Code)
	}

	want := config.ResolveMailHostname()
	if got := testutil.ToFloat64(metrics.ConnectionsTotal.WithLabelValues("userapi_proxy", name, want)); got != 1 {
		t.Errorf("sora_connections_total{hostname=%q} = %v, want 1", want, got)
	}
	if got := testutil.ToFloat64(metrics.ConnectionsTotal.WithLabelValues("userapi_proxy", name, "")); got != 0 {
		t.Errorf("sora_connections_total{hostname=\"\"} = %v, want 0", got)
	}
}
