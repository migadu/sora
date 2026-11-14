package userapiproxy

import (
	"context"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
)

// lookup_local_users adds the database as a second source for users the lookup does
// not know; it must not turn a lookup that cannot be built into running without one.
// TestPools_InvalidLookupCannotEnableLocalFallback covers the named-pool proxy.
func TestNew_InvalidRemoteLookupFailsWithLookupLocalUsers(t *testing.T) {
	for name, lookup := range map[string]*config.RemoteLookupConfig{
		"plaintext_url":   {Enabled: true, LookupLocalUsers: true, URL: "http://lookup.example.com/lookup?email=$email"},
		"invalid_timeout": {Enabled: true, LookupLocalUsers: true, URL: "http://127.0.0.1:1/lookup?email=$email", Timeout: "5"},
	} {
		t.Run(name, func(t *testing.T) {
			s, err := New(context.Background(), &resilient.ResilientDatabase{}, ServerOptions{
				Name: "test", Addr: "127.0.0.1:0", JWTSecret: "test-secret-key-at-least-32-bytes!!",
				RemoteAddrs:  []string{"127.0.0.1:8081"},
				RemoteLookup: lookup,
			})
			if err == nil {
				s.cancel()
				t.Fatal("User API proxy started without its remote lookup")
			}
		})
	}
}
