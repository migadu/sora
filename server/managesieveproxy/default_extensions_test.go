package managesieveproxy

import (
	"context"
	"slices"
	"testing"

	"github.com/migadu/sora/server/managesieve"
)

// Unconfigured, the proxy advertises what an unconfigured backend accepts, which
// leaves out editheader.
func TestManageSieveProxyDefaultExtensions(t *testing.T) {
	srv, err := New(context.Background(), nil, "test.example.com", ServerOptions{
		Name:        "test-proxy",
		Addr:        ":14191",
		RemoteAddrs: []string{"backend1.example.com:4190"},
		RemotePort:  4190,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	if !slices.Equal(srv.supportedExtensions, managesieve.DefaultEnabledExtensions) {
		t.Errorf("default extensions = %v, want %v", srv.supportedExtensions, managesieve.DefaultEnabledExtensions)
	}
	if slices.Contains(srv.supportedExtensions, "editheader") {
		t.Error("editheader is advertised by default")
	}
}
