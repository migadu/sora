package userapiproxy

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/server/proxy"
)

// fakeRoutingLookup implements proxy.UserRoutingLookup and records whether the
// lookup context carried a deadline.
type fakeRoutingLookup struct {
	sawDeadline bool
	backend     string
}

func (f *fakeRoutingLookup) LookupUserRoute(ctx context.Context, email, password string) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return f.LookupUserRouteWithOptions(ctx, email, password, true)
}

func (f *fakeRoutingLookup) LookupUserRouteWithOptions(ctx context.Context, email, password string, routeOnly bool) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	_, f.sawDeadline = ctx.Deadline()
	return &proxy.UserRoutingInfo{ServerAddress: f.backend, AccountID: 42}, proxy.AuthSuccess, nil
}

func (f *fakeRoutingLookup) LookupUserRouteWithClientIP(ctx context.Context, email, password, clientIP string, routeOnly bool) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return f.LookupUserRouteWithOptions(ctx, email, password, routeOnly)
}

func (f *fakeRoutingLookup) Close() error { return nil }

// TestGetBackendForUserBoundsRemoteLookup verifies that the remotelookup call
// runs under a context with a deadline. Regression test for the User API proxy
// review (2026-07-03): getBackendForUser used context.Background() with no
// timeout, so a hung remotelookup service blocked the request handler
// indefinitely (modulo the HTTP client's own internal timeout).
func TestGetBackendForUserBoundsRemoteLookup(t *testing.T) {
	const backendAddr = "10.0.0.5:8081"
	fake := &fakeRoutingLookup{backend: backendAddr}

	cm, err := proxy.NewConnectionManager([]string{backendAddr}, 8081, false, false, false, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}

	s := &Server{
		name:          "test",
		connManager:   cm,
		routingLookup: fake,
	}

	got, err := s.getBackendForUser(context.Background(), "user@example.com", 42)
	if err != nil {
		t.Fatalf("getBackendForUser failed: %v", err)
	}
	if got != backendAddr {
		t.Fatalf("getBackendForUser returned %q, want %q", got, backendAddr)
	}
	if !fake.sawDeadline {
		t.Fatal("remotelookup context had no deadline (a hung lookup service would block the request handler)")
	}
}
