package config

import (
	"strings"
	"testing"
)

func TestUserAPILoginCacheIsUnusedWithoutDurationFallbackWarnings(t *testing.T) {
	cfg := NewDefaultConfig()
	cfg.DynamicServers = []ServerConfig{{
		Type: "http_user_api", Name: "user-no-login-cache", Addr: "127.0.0.1:8081", JWTSecret: "test-secret-for-warning-only",
		LookupCache: &LookupCacheConfig{Enabled: true, PositiveTTL: "bad", NegativeTTL: "bad", CleanupInterval: "bad", PositiveRevalidationWindow: "bad"},
	}}
	var ignored int
	for _, warning := range cfg.Warnings() {
		if !strings.Contains(warning, "user-no-login-cache") {
			continue
		}
		if strings.Contains(warning, "'lookup_cache'") {
			ignored++
		}
		if strings.Contains(warning, "lookup_cache.") {
			t.Fatalf("unused login cache must not claim duration fallback: %s", warning)
		}
	}
	if ignored != 1 {
		t.Fatalf("got %d whole-table warnings, want exactly one", ignored)
	}
}
