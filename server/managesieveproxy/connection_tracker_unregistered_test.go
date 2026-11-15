package managesieveproxy

import (
	"context"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// TestMSBackendFailureAfterLoginKeepsLiveSessionSlot: the proxy accepts the client's
// credentials before it reaches the backend, and registers the session with the
// connection tracker only once the backend has accepted the proxy's login. A session
// whose backend leg fails never held a slot, so its end must not release one: that
// would free the slot of the account's live session from the same client IP, letting
// the account exceed max_connections_per_user / max_connections_per_user_per_ip by
// one session per such failure (#796).
func TestMSBackendFailureAfterLoginKeepsLiveSessionSlot(t *testing.T) {
	for _, tc := range []struct {
		name    string
		backend func(t *testing.T) string
	}{
		{"backend down", deadSieveBackendAddr},
		{"backend refuses the proxy login", refusingSieveBackend},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			tracker := server.NewConnectionTracker("ManageSieve", "", "", "instance-1", nil, 0, 0, 1000, false)
			defer tracker.Stop()

			lookup := httptest.NewServer(acceptingSieveLookup(t))
			defer lookup.Close()

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := ln.Addr().String()
			ln.Close()
			srv, err := New(ctx, &resilient.ResilientDatabase{}, "localhost", ServerOptions{
				Name:               "unregistered",
				Addr:               addr,
				RemoteAddrs:        []string{tc.backend(t)},
				ConnectTimeout:     2 * time.Second,
				InsecureAuth:       true,
				MasterSASLUsername: "proxy-master",
				MasterSASLPassword: "proxy-master-secret",
				RemoteLookup:       &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", Timeout: "5s"},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			srv.SetConnectionTracker(tracker)
			go func() { _ = srv.Start() }()
			defer srv.Stop()

			// The account's live session from the same client IP on this listener.
			accountID := proxy.DeriveAccountIDFromEmail(sieveTestUser)
			if err := tracker.RegisterConnection(ctx, accountID, sieveTestUser, "ManageSieve", "127.0.0.1:40000"); err != nil {
				t.Fatalf("register the live session: %v", err)
			}

			// authenticateViaSieveProxy disconnects once it has the reply.
			const want = `NO (TRYLATER) "Backend server temporarily unavailable"`
			if got := authenticateViaSieveProxy(t, addr); got != want {
				t.Fatalf("AUTHENTICATE with a failing backend: %q, want %q", got, want)
			}

			// Wait for the failed session to end, close() included.
			if !srv.sessions.Drain(5 * time.Second) {
				t.Fatal("the failed session did not end")
			}

			if got := tracker.GetLocalConnectionCount(accountID); got != 1 {
				t.Errorf("connection count = %d after a session whose backend leg failed ended, want 1 (the live session's slot)", got)
			}
		})
	}
}
