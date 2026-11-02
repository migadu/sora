//go:build integration

package imap_test

import (
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	soraimap "github.com/migadu/sora/server/imap"
)

// eventuallyDrainSessions waits until a server reports want (open, started).
func eventuallyDrainSessions(t *testing.T, sessions func() (int64, int64), wantOpen, wantStarted int64, when string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		open, started := sessions()
		if open == wantOpen && started == wantStarted {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: drain sessions = %d open, %d started; want %d open, %d started", when, open, started, wantOpen, wantStarted)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The node reports IMAP sessions that have logged in as drain sessions (an authenticated
// session can APPEND), which backend maintenance waits on: a connection counts once it
// logs in, and stops counting as open when it ends. Started never goes back.
func TestIMAP_DrainSessionsCountLoggedInSessions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	s, ok := server.Server.(*soraimap.IMAPServer)
	if !ok {
		t.Fatalf("server is %T, want *imap.IMAPServer", server.Server)
	}

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if err := c.WaitGreeting(); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	eventuallyDrainSessions(t, s.DrainSessions, 0, 0, "connected, not logged in")

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}
	eventuallyDrainSessions(t, s.DrainSessions, 1, 1, "logged in")

	if err := c.Logout().Wait(); err != nil {
		t.Fatalf("logout: %v", err)
	}
	eventuallyDrainSessions(t, s.DrainSessions, 0, 1, "after logout")
}
