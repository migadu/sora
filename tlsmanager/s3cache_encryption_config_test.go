package tlsmanager

import (
	"context"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/migadu/sora/config"
)

// The encryption the cache asks for has to be reachable from config: stores differ on
// which server-side encryption they implement, and a deployment pointed at one that
// rejects the header cannot edit Go to get its certificates written.

func ptr(s string) *string { return &s }

func decodeS3Config(t *testing.T, body string) config.TLSLetsEncryptS3Config {
	t.Helper()

	var cfg config.TLSLetsEncryptS3Config
	if _, err := toml.Decode(body, &cfg); err != nil {
		t.Fatalf("toml.Decode: %v", err)
	}
	return cfg
}

// TestEncryptionOptionsFromConfig covers the translation from configuration to cache
// options, including the distinction an absent key has to keep from an explicit "".
func TestEncryptionOptionsFromConfig(t *testing.T) {
	tests := []struct {
		name          string
		cfg           config.TLSLetsEncryptS3Config
		wantAlgorithm string
		wantKMSKeyID  string
	}{
		{
			name:          "absent key keeps the default",
			cfg:           config.TLSLetsEncryptS3Config{},
			wantAlgorithm: "AES256",
		},
		{
			name:          "explicit empty value sends no header",
			cfg:           config.TLSLetsEncryptS3Config{ServerSideEncryption: ptr("")},
			wantAlgorithm: "",
		},
		{
			name:          "explicit AES256",
			cfg:           config.TLSLetsEncryptS3Config{ServerSideEncryption: ptr("AES256")},
			wantAlgorithm: "AES256",
		},
		{
			name: "kms with a key id",
			cfg: config.TLSLetsEncryptS3Config{
				ServerSideEncryption:         ptr("aws:kms"),
				ServerSideEncryptionKMSKeyID: "arn:aws:kms:eu-west-1:1:key/abc",
			},
			wantAlgorithm: "aws:kms",
			wantKMSKeyID:  "arn:aws:kms:eu-west-1:1:key/abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, endpoint := newEncryptionRecorder(t)

			cfg := tt.cfg
			cfg.Bucket = "certs"
			cfg.Endpoint = endpoint
			cfg.DisableTLS = true
			cfg.AccessKey = "test"
			cfg.SecretKey = "test"

			cache, err := NewS3Cache(cfg, encryptionOptions(cfg)...)
			if err != nil {
				t.Fatalf("NewS3Cache: %v", err)
			}
			if err := cache.Put(context.Background(), "mail.example.com", []byte("-----BEGIN PRIVATE KEY-----")); err != nil {
				t.Fatalf("Put: %v", err)
			}

			algorithm, kmsKeyID := rec.lastPut(t)
			if algorithm != tt.wantAlgorithm {
				t.Errorf("PUT server-side encryption = %q, want %q", algorithm, tt.wantAlgorithm)
			}
			if kmsKeyID != tt.wantKMSKeyID {
				t.Errorf("PUT KMS key id = %q, want %q", kmsKeyID, tt.wantKMSKeyID)
			}
		})
	}
}

// TestEncryptionConfigRejectsStrayKMSKeyID keeps a KMS key id configured without an
// algorithm from being silently ignored: the deployment believes its own key protects
// the certificates while the store is in fact managing them.
func TestEncryptionConfigRejectsStrayKMSKeyID(t *testing.T) {
	_, endpoint := newEncryptionRecorder(t)

	cfg := config.TLSLetsEncryptS3Config{
		Bucket:                       "certs",
		Endpoint:                     endpoint,
		DisableTLS:                   true,
		AccessKey:                    "test",
		SecretKey:                    "test",
		ServerSideEncryptionKMSKeyID: "arn:aws:kms:eu-west-1:1:key/abc",
	}

	if _, err := NewS3Cache(cfg, encryptionOptions(cfg)...); err == nil {
		t.Fatal("NewS3Cache with a KMS key id and no algorithm: err = nil, want a configuration error")
	}
}

// TestEncryptionConfigParsesFromTOML covers the TOML keys themselves, so a rename of
// either one is caught here rather than by a deployment whose setting stopped applying.
func TestEncryptionConfigParsesFromTOML(t *testing.T) {
	t.Run("explicit empty value survives decoding", func(t *testing.T) {
		cfg := decodeS3Config(t, `
bucket = "certs"
server_side_encryption = ""
`)
		if cfg.ServerSideEncryption == nil {
			t.Fatal("server_side_encryption = \"\" decoded to nil: an explicit opt-out is indistinguishable from an absent key")
		}
		if *cfg.ServerSideEncryption != "" {
			t.Errorf("server_side_encryption = %q, want %q", *cfg.ServerSideEncryption, "")
		}
	})

	t.Run("absent key stays nil", func(t *testing.T) {
		cfg := decodeS3Config(t, `bucket = "certs"`)
		if cfg.ServerSideEncryption != nil {
			t.Errorf("absent server_side_encryption decoded to %q, want nil", *cfg.ServerSideEncryption)
		}
	})

	t.Run("kms key id", func(t *testing.T) {
		cfg := decodeS3Config(t, `
bucket = "certs"
server_side_encryption = "aws:kms"
server_side_encryption_kms_key_id = "arn:aws:kms:eu-west-1:1:key/abc"
`)
		if cfg.ServerSideEncryption == nil || *cfg.ServerSideEncryption != "aws:kms" {
			t.Errorf("server_side_encryption = %v, want %q", cfg.ServerSideEncryption, "aws:kms")
		}
		if cfg.ServerSideEncryptionKMSKeyID != "arn:aws:kms:eu-west-1:1:key/abc" {
			t.Errorf("server_side_encryption_kms_key_id = %q, want the configured key", cfg.ServerSideEncryptionKMSKeyID)
		}
	})
}
