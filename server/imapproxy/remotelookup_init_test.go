package imapproxy

import (
	"context"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
)

// lookup_local_users adds the database as a second source for users the lookup does
// not know; it must not turn a lookup that cannot be built into running without one.
func TestNew_InvalidRemoteLookupFailsWithLookupLocalUsers(t *testing.T) {
	for name, lookup := range map[string]*config.RemoteLookupConfig{
		"plaintext_url":   {Enabled: true, LookupLocalUsers: true, URL: "http://lookup.example.com/lookup?email=$email"},
		"invalid_timeout": {Enabled: true, LookupLocalUsers: true, URL: "http://127.0.0.1:1/lookup?email=$email", Timeout: "5"},
	} {
		t.Run(name, func(t *testing.T) {
			srv, err := New(context.Background(), &resilient.ResilientDatabase{}, "localhost", ServerOptions{
				Name: "test", Addr: "127.0.0.1:0", RemoteAddrs: []string{"127.0.0.1:1"},
				RemoteLookup: lookup,
			})
			if err == nil {
				srv.Stop()
				t.Fatal("IMAP proxy started without its remote lookup")
			}
		})
	}
}
