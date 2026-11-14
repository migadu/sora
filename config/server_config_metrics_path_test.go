package config

import (
	"net/http"
	"testing"
)

func TestServerConfigMetricsPathDefaults(t *testing.T) {
	server := ServerConfig{Type: "metrics", Name: "metrics", Addr: "127.0.0.1:9090"}
	if got := server.MetricsPath(); got != "/metrics" {
		t.Fatalf("MetricsPath() = %q, want %q", got, "/metrics")
	}

	server.Path = "/custom"
	if got := server.MetricsPath(); got != "/custom" {
		t.Fatalf("MetricsPath() = %q, want %q", got, "/custom")
	}
}

func TestServerConfigMetricsPathRegistersOnServeMux(t *testing.T) {
	server := ServerConfig{Type: "metrics", Name: "metrics", Addr: "127.0.0.1:9090"}

	// Registering an empty pattern panics, which is how a metrics block
	// without a path used to take the process down at startup.
	mux := http.NewServeMux()
	mux.Handle(server.MetricsPath(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
}

func TestServerConfigValidateMetricsPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "unset", path: ""},
		{name: "absolute", path: "/metrics"},
		{name: "relative", path: "metrics", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := ServerConfig{
				Type: "metrics",
				Name: "metrics",
				Addr: "127.0.0.1:9090",
				Path: tt.path,
			}
			err := server.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("Validate() = nil, want an error for path %q", tt.path)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil for path %q", err, tt.path)
			}
		})
	}
}
