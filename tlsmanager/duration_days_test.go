package tlsmanager

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
)

// [tls.letsencrypt] renew_before and sync_interval take the syntax of every
// other duration key, whole days included. They were parsed with
// time.ParseDuration, so "45d" stopped the TLS manager and with it startup (#417).
func TestLetsEncryptDurationsAcceptDays(t *testing.T) {
	logs := &syncBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { logger.Swap(prev) })

	_, endpoint := newStubS3(t)
	m, _ := newTestLetsEncryptManager(t, endpoint, func(le *config.TLSLetsEncryptConfig) {
		le.RenewBefore = "45d"
		le.SyncInterval = "1d"
		le.EnableFallback = boolPtr(false)
	})

	if got, want := m.autocertMgr.RenewBefore, 45*24*time.Hour; got != want {
		t.Errorf("renew_before = %v, want %v", got, want)
	}
	if !strings.Contains(logs.String(), `msg="Starting certificate sync worker" interval=24h0m0s`) {
		t.Errorf("sync_interval = \"1d\" did not start the sync worker every 24h; log:\n%s", logs.String())
	}
}

// An unparsable value still stops startup, naming the key.
func TestLetsEncryptInvalidDurationsRejected(t *testing.T) {
	_, endpoint := newStubS3(t)
	for key, set := range map[string]func(*config.TLSLetsEncryptConfig){
		"renew_before":  func(le *config.TLSLetsEncryptConfig) { le.RenewBefore = "30 days" },
		"sync_interval": func(le *config.TLSLetsEncryptConfig) { le.SyncInterval = "5 min" },
	} {
		le := &config.TLSLetsEncryptConfig{
			Email:           "tls-test@example.com",
			Domains:         []string{"mail.example.com"},
			StorageProvider: "s3",
			SyncInterval:    "0",
			EnableFallback:  boolPtr(false),
			S3: config.TLSLetsEncryptS3Config{
				Bucket: "certs", Endpoint: endpoint, DisableTLS: true, AccessKey: "test", SecretKey: "test",
			},
		}
		set(le)
		_, directoryURL := newStubACME(t)
		productionDirectory := acmeDirectoryURL
		acmeDirectoryURL = directoryURL
		m, err := newManager(config.TLSConfig{Enabled: true, Provider: "letsencrypt", LetsEncrypt: le}, nil)
		acmeDirectoryURL = productionDirectory
		if err == nil {
			m.Shutdown()
			t.Errorf("invalid %s accepted", key)
			continue
		}
		if !strings.Contains(err.Error(), key) {
			t.Errorf("invalid %s: error %q does not name the key", key, err)
		}
	}
}
