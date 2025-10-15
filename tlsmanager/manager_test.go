package tlsmanager

import (
	"testing"

	"github.com/migadu/sora/config"
)

func TestNewTLSManagerFileProvider(t *testing.T) {
	// Test that file provider validation works
	cfg := config.TLSConfig{
		Enabled:  true,
		Provider: "file",
		CertFile: "",
		KeyFile:  "",
	}

	_, err := New(cfg, nil) // nil cluster manager
	if err == nil {
		t.Fatal("expected error for missing cert_file and key_file, got nil")
	}

	// Check error message
	expectedMsg := "cert_file and key_file are required for provider='file'"
	if err.Error() != "failed to initialize file provider: "+expectedMsg {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewTLSManagerDisabled(t *testing.T) {
	cfg := config.TLSConfig{
		Enabled: false,
	}

	_, err := New(cfg, nil)
	if err == nil {
		t.Fatal("expected error when TLS is disabled, got nil")
	}

	expectedMsg := "TLS is not enabled in configuration"
	if err.Error() != expectedMsg {
		t.Errorf("expected error '%s', got '%v'", expectedMsg, err)
	}
}

func TestNewTLSManagerUnknownProvider(t *testing.T) {
	cfg := config.TLSConfig{
		Enabled:  true,
		Provider: "unknown",
	}

	_, err := New(cfg, nil)
	if err == nil {
		t.Fatal("expected error for unknown provider, got nil")
	}

	expectedMsg := "unknown TLS provider: unknown (must be 'file' or 'letsencrypt')"
	if err.Error() != expectedMsg {
		t.Errorf("expected error '%s', got '%v'", expectedMsg, err)
	}
}

func TestNewTLSManagerLetsEncryptMissingConfig(t *testing.T) {
	cfg := config.TLSConfig{
		Enabled:     true,
		Provider:    "letsencrypt",
		LetsEncrypt: nil,
	}

	_, err := New(cfg, nil)
	if err == nil {
		t.Fatal("expected error for missing letsencrypt config, got nil")
	}

	expectedMsg := "letsencrypt configuration is required for provider='letsencrypt'"
	if err.Error() != "failed to initialize Let's Encrypt provider: "+expectedMsg {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewTLSManagerLetsEncryptMissingEmail(t *testing.T) {
	cfg := config.TLSConfig{
		Enabled:  true,
		Provider: "letsencrypt",
		LetsEncrypt: &config.TLSLetsEncryptConfig{
			Email:   "",
			Domains: []string{"example.com"},
		},
	}

	_, err := New(cfg, nil)
	if err == nil {
		t.Fatal("expected error for missing email, got nil")
	}

	expectedMsg := "letsencrypt.email is required"
	if err.Error() != "failed to initialize Let's Encrypt provider: "+expectedMsg {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewTLSManagerLetsEncryptMissingDomains(t *testing.T) {
	cfg := config.TLSConfig{
		Enabled:  true,
		Provider: "letsencrypt",
		LetsEncrypt: &config.TLSLetsEncryptConfig{
			Email:   "test@example.com",
			Domains: []string{},
		},
	}

	_, err := New(cfg, nil)
	if err == nil {
		t.Fatal("expected error for missing domains, got nil")
	}

	expectedMsg := "letsencrypt.domains is required and must not be empty"
	if err.Error() != "failed to initialize Let's Encrypt provider: "+expectedMsg {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewTLSManagerLetsEncryptInvalidStorageProvider(t *testing.T) {
	cfg := config.TLSConfig{
		Enabled:  true,
		Provider: "letsencrypt",
		LetsEncrypt: &config.TLSLetsEncryptConfig{
			Email:           "test@example.com",
			Domains:         []string{"example.com"},
			StorageProvider: "redis", // Not supported yet
		},
	}

	_, err := New(cfg, nil)
	if err == nil {
		t.Fatal("expected error for unsupported storage provider, got nil")
	}

	expectedMsg := "only storage_provider='s3' is currently supported for Let's Encrypt"
	if err.Error() != "failed to initialize Let's Encrypt provider: "+expectedMsg {
		t.Errorf("unexpected error message: %v", err)
	}
}
