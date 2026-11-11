//go:build integration

package imap_test

import (
	"errors"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	soraimap "github.com/migadu/sora/server/imap"
)

// eventuallyOpenDrainSessions waits until a server reports want open drain sessions.
func eventuallyOpenDrainSessions(t *testing.T, sessions func() int64, want int64, when string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		open := sessions()
		if open == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d drain sessions open, want %d", when, open, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The node reports IMAP sessions that have logged in as drain sessions (an authenticated
// session can APPEND), which backend maintenance waits on: a connection counts once it
// logs in, and stops counting when it ends.
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
	eventuallyOpenDrainSessions(t, s.DrainSessions, 0, "connected, not logged in")

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}
	eventuallyOpenDrainSessions(t, s.DrainSessions, 1, "logged in")

	if err := c.Logout().Wait(); err != nil {
		t.Fatalf("logout: %v", err)
	}
	eventuallyOpenDrainSessions(t, s.DrainSessions, 0, "after logout")
}

// A backend refusing new sessions (in maintenance, past refuse_after) turns every login
// away with a temporary failure, NO [UNAVAILABLE], and does not count it, whichever way the
// client logs in: LOGIN, AUTHENTICATE PLAIN, the master username forms of both, and master
// SASL (how the proxies log in). A session logged in before carries on.
func TestIMAP_MaintenanceRefusesNewLogins(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := setupIMAPServerWithMasterAuth(t)
	s := server.Server.(*soraimap.IMAPServer)
	logins := []struct {
		name  string
		login func(c *imapclient.Client) error
	}{
		{"LOGIN", func(c *imapclient.Client) error { return c.Login(account.Email, account.Password).Wait() }},
		{"LOGIN as master", func(c *imapclient.Client) error {
			return c.Login(account.Email+"@"+masterUsername, masterPassword).Wait()
		}},
		{"AUTHENTICATE PLAIN", func(c *imapclient.Client) error {
			return c.Authenticate(sasl.NewPlainClient("", account.Email, account.Password))
		}},
		{"AUTHENTICATE PLAIN as master", func(c *imapclient.Client) error {
			return c.Authenticate(sasl.NewPlainClient("", account.Email+"@"+masterUsername, masterPassword))
		}},
		{"AUTHENTICATE PLAIN, master SASL", func(c *imapclient.Client) error {
			return c.Authenticate(&plainSASLClient{identity: account.Email, username: masterSASLUsername, password: masterSASLPassword})
		}},
	}
	dial := func() *imapclient.Client {
		t.Helper()
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}

	before := dial()
	if err := before.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login before maintenance: %v", err)
	}
	eventuallyOpenDrainSessions(t, s.DrainSessions, 1, "logged in before maintenance")

	server.MaintenanceGate.SetRefusing(true)
	for _, l := range logins {
		err := l.login(dial())
		var imapErr *imap.Error
		if !errors.As(err, &imapErr) || imapErr.Code != imap.ResponseCodeUnavailable {
			t.Errorf("%s while refusing: %v, want NO [UNAVAILABLE]", l.name, err)
		}
	}
	eventuallyOpenDrainSessions(t, s.DrainSessions, 1, "after the refused logins")
	if _, err := before.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("session logged in before maintenance: %v", err)
	}

	server.MaintenanceGate.SetRefusing(false)
	for _, l := range logins {
		if err := l.login(dial()); err != nil {
			t.Errorf("%s once accepting again: %v", l.name, err)
		}
	}
	eventuallyOpenDrainSessions(t, s.DrainSessions, int64(1+len(logins)), "after accepting again")
}
