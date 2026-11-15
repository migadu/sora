package proxy

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/logger"
)

// TestHTTPRemoteLookupDoesNotLogPasswordHash: no part of the password_hash a lookup
// answers reaches the log, at any level, whether the password matches, does not, or
// the hash cannot be checked. It used to be logged at DEBUG ("hash_prefix", its first
// 30 characters), and a lookup service that answers a password in that field would
// have the password logged.
func TestHTTPRemoteLookupDoesNotLogPasswordHash(t *testing.T) {
	logs := &syncBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { logger.Swap(prev) })

	for _, hash := range []string{
		"$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", // bcrypt of "password"
		"Secret-2026", // a password in the hash field
	} {
		lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"address": "user@example.com", "password_hash": hash, "server": "backend:143"})
		}))
		client := NewHTTPRemoteLookupClient(lookup.URL+"/lookup?email=$email", 5*time.Second, "", 143,
			false, false, false, false, false, false, false, nil, nil)
		for _, password := range []string{"password", "Secret-2026", "wrong"} {
			_, _, _ = client.LookupUserRoute(context.Background(), "user@example.com", password)
		}
		lookup.Close()

		piece := strings.TrimPrefix(hash, "$2a$10$")[:8]
		if strings.Contains(logs.String(), piece) {
			t.Errorf("lookup answering password_hash %q logged %q from it:\n%s", hash, piece, logs.String())
		}
	}
}
