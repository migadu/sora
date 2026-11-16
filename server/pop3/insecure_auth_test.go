package pop3

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
)

// A listener without TLS always allows cleartext logins, whatever insecure_auth says
// (the backend-behind-a-proxy deployment). New does not warn about it: cmd/sora reports
// cleartext authentication on a publicly reachable address for every login listener
// alike and stays quiet on private backends, and the IMAP and ManageSieve servers do not
// warn either. cmd/sora passes InsecureAuth already forced on without TLS, so a warning
// keyed on the raw option could only ever fire for a direct caller (#1676).
func TestNewWithoutTLSAllowsCleartextAuthWithoutWarning(t *testing.T) {
	for _, insecureAuth := range []bool{false, true} {
		var logs bytes.Buffer
		prev := logger.Swap(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))

		ctx, cancel := context.WithCancel(context.Background())
		srv, err := New(ctx, "pop3-plain", "localhost", "127.0.0.1:0", nil, nil, nil, nil, POP3ServerOptions{
			InsecureAuth: insecureAuth,
			Config:       &config.Config{},
		})
		cancel()
		logger.Swap(prev)
		if err != nil {
			t.Fatalf("insecure_auth=%v: New: %v", insecureAuth, err)
		}

		if !srv.insecureAuth {
			t.Errorf("insecure_auth=%v without TLS: cleartext authentication not allowed", insecureAuth)
		}
		if strings.Contains(logs.String(), "level=WARN") {
			t.Errorf("insecure_auth=%v without TLS: New logged a warning:\n%s", insecureAuth, logs.String())
		}
	}
}
