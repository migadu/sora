package main

import (
	"testing"

	"github.com/migadu/sora/config"
)

// The Admin API's uploader endpoints count an upload as failed once it reaches the
// configured [uploader] max_attempts, the point where the uploader gives up (#288).
func TestBuildAdminAPIServerOptions_ThreadsUploadMaxAttempts(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cfg.Uploader.MaxAttempts = 37
	deps := &serverDependencies{config: cfg}

	options := buildAdminAPIServerOptions(deps, config.ServerConfig{Name: "admin-api", Addr: ":8080"})

	if options.UploadMaxAttempts != 37 {
		t.Fatalf("UploadMaxAttempts = %d, want the configured [uploader] max_attempts 37", options.UploadMaxAttempts)
	}
}
