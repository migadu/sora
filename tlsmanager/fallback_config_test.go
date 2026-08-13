package tlsmanager

import (
	"path/filepath"
	"testing"

	"github.com/migadu/sora/config"
)

// TestFallbackActiveWhenOnlyFallbackDirConfigured pins the operator-visible semantic:
// naming a fallback_dir puts the local certificate mirror in front of S3. An S3-only
// cache here means every TLS handshake pays an S3 GET and an S3 outage can trigger
// Let's Encrypt orders for certificates that already exist.
func TestFallbackActiveWhenOnlyFallbackDirConfigured(t *testing.T) {
	_, endpoint := newStubS3(t)
	dir := filepath.Join(t.TempDir(), "certs")

	m, _ := newTestLetsEncryptManager(t, endpoint, func(le *config.TLSLetsEncryptConfig) {
		// enable_fallback deliberately left unset, as an absent TOML key decodes it.
		le.FallbackDir = dir
	})

	fc := extractFallbackCache(m.autocertMgr.Cache)
	if fc == nil {
		t.Fatalf("fallback_dir configured but the cache chain is %T with no FallbackCache in it", m.autocertMgr.Cache)
	}
	if got := fc.GetFallbackDir(); got != dir {
		t.Errorf("fallback dir = %q, want %q", got, dir)
	}
}

func boolPtr(b bool) *bool { return &b }

func TestResolveFallbackDir(t *testing.T) {
	tests := []struct {
		name  string
		leCfg config.TLSLetsEncryptConfig
		want  string
	}{
		{"configured dir", config.TLSLetsEncryptConfig{FallbackDir: "/srv/sora/certs"}, "/srv/sora/certs"},
		{"configured dir with enable_fallback", config.TLSLetsEncryptConfig{EnableFallback: boolPtr(true), FallbackDir: "/srv/sora/certs"}, "/srv/sora/certs"},
		{"nothing configured", config.TLSLetsEncryptConfig{}, DefaultFallbackDir},
		{"enable_fallback only", config.TLSLetsEncryptConfig{EnableFallback: boolPtr(true)}, DefaultFallbackDir},
		{"explicitly disabled", config.TLSLetsEncryptConfig{EnableFallback: boolPtr(false)}, ""},
		{"explicitly disabled with dir", config.TLSLetsEncryptConfig{EnableFallback: boolPtr(false), FallbackDir: "/srv/sora/certs"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveFallbackDir(&tt.leCfg); got != tt.want {
				t.Errorf("resolveFallbackDir() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestFallbackActiveWhenEnableFallbackAndDirConfigured covers the configuration that
// already worked, so the fix does not trade one inversion for another.
func TestFallbackActiveWhenEnableFallbackAndDirConfigured(t *testing.T) {
	_, endpoint := newStubS3(t)
	dir := filepath.Join(t.TempDir(), "certs")

	m, _ := newTestLetsEncryptManager(t, endpoint, func(le *config.TLSLetsEncryptConfig) {
		le.EnableFallback = boolPtr(true)
		le.FallbackDir = dir
	})

	fc := extractFallbackCache(m.autocertMgr.Cache)
	if fc == nil {
		t.Fatalf("enable_fallback with fallback_dir but the cache chain is %T with no FallbackCache in it", m.autocertMgr.Cache)
	}
	if got := fc.GetFallbackDir(); got != dir {
		t.Errorf("fallback dir = %q, want %q", got, dir)
	}
}
