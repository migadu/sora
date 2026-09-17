//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/adminapi"
	serverImap "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/storage"
)

// An IMAP backend with its lookup cache on (the default) and the Admin API in the
// same process, sharing the backend's connection tracker the way cmd/sora wires
// them. A login the cache holds is served from memory, so these tests always sign
// in once before the change they make, and then expect the change to hold at once.
type accountLoginsStack struct {
	api      *HTTPAPITestServer
	imapAddr string
}

func setupAccountLoginsStack(t *testing.T) *accountLoginsStack {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	imapAddr := common.GetRandomAddress(t)
	imapSrv, err := serverImap.New(context.Background(), "imap-logins", "localhost", imapAddr,
		&storage.S3Storage{}, rdb, nil, nil,
		serverImap.IMAPServerOptions{InsecureAuth: true})
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}
	tracker := serverPkg.NewConnectionTracker("IMAP", "imap-logins", "localhost", "localhost-imap-logins", nil, 0, 0, 0, true)
	imapSrv.SetConnTracker(tracker)
	go func() {
		if err := imapSrv.Serve(imapAddr); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("IMAP server stopped: %v", err)
		}
	}()
	t.Cleanup(func() {
		tracker.Stop()
		imapSrv.Close()
	})

	api := startAdminAPI(t, rdb, map[string]*serverPkg.ConnectionTracker{"IMAP-imap-logins": tracker})
	t.Cleanup(api.Close)
	time.Sleep(100 * time.Millisecond)

	return &accountLoginsStack{api: api, imapAddr: imapAddr}
}

func startAdminAPI(t *testing.T, rdb *resilient.ResilientDatabase, trackers map[string]*serverPkg.ConnectionTracker) *HTTPAPITestServer {
	t.Helper()

	options := adminapi.ServerOptions{
		Addr:               common.GetRandomAddress(t),
		APIKey:             testAPIKey,
		AllowedHosts:       []string{},
		ConnectionTrackers: trackers,
	}
	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	go adminapi.Start(ctx, rdb, options, errChan)
	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-errChan:
		cancel()
		t.Fatalf("Failed to start HTTP API server: %v", err)
	default:
	}
	return &HTTPAPITestServer{URL: "http://" + options.Addr, rdb: rdb, cleanup: cancel}
}

// login signs in over a new connection and returns it, or the refusal.
func (s *accountLoginsStack) login(t *testing.T, email, password string) (*imapclient.Client, error) {
	t.Helper()
	c, err := imapclient.DialInsecure(s.imapAddr, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := c.Login(email, password).Wait(); err != nil {
		c.Close()
		return nil, err
	}
	t.Cleanup(func() { c.Close() })
	return c, nil
}

func (s *accountLoginsStack) mustLogin(t *testing.T, email, password string) *imapclient.Client {
	t.Helper()
	c, err := s.login(t, email, password)
	if err != nil {
		t.Fatalf("login %s: %v", email, err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("select as %s: %v", email, err)
	}
	return c
}

func (s *accountLoginsStack) request(t *testing.T, method, endpoint string, body any, wantStatus int) {
	t.Helper()
	resp, respBody := s.api.makeRequest(t, method, endpoint, body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("%s %s: %d %s", method, endpoint, resp.StatusCode, string(respBody))
	}
}

func (s *accountLoginsStack) createAccount(t *testing.T, tag, password string) string {
	t.Helper()
	email := fmt.Sprintf("logins-%s-%d@example.com", tag, time.Now().UnixNano())
	s.request(t, "POST", "/admin/accounts", map[string]string{"email": email, "password": password}, http.StatusCreated)
	return email
}

// waitClosed polls until the connection stops serving commands.
func waitClosed(t *testing.T, c *imapclient.Client, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := c.Select("INBOX", nil).Wait(); err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: the connection is still being served", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestAdminAPI_DeleteAccount_EndsSessionsAndLogins(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	s := setupAccountLoginsStack(t)

	const password = "deleted-account-pass-1"
	email := s.createAccount(t, "delete", password)
	open := s.mustLogin(t, email, password)

	s.request(t, "DELETE", "/admin/accounts/"+email, nil, http.StatusOK)

	if _, err := s.login(t, email, password); err == nil {
		t.Error("a deleted account can still sign in")
	}
	waitClosed(t, open, "a deleted account's open session")
}

func TestAdminAPI_UpdatePassword_OldPasswordStopsAtOnce(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	s := setupAccountLoginsStack(t)

	const oldPassword, newPassword = "old-password-123", "new-password-456"
	email := s.createAccount(t, "password", oldPassword)
	open := s.mustLogin(t, email, oldPassword)

	s.request(t, "PUT", "/admin/accounts/"+email, map[string]string{"password": newPassword}, http.StatusOK)

	if _, err := s.login(t, email, oldPassword); err == nil {
		t.Error("the replaced password still signs in")
	}
	s.mustLogin(t, email, newPassword)

	// A password change is not a sign-out: the session already open carries on.
	if _, err := open.Select("INBOX", nil).Wait(); err != nil {
		t.Errorf("the open session ended with the password change: %v", err)
	}
}

func TestAdminAPI_DeleteCredential_AddressStopsSigningIn(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	s := setupAccountLoginsStack(t)

	const password = "primary-password-1"
	const aliasPassword = "alias-password-2"
	email := s.createAccount(t, "credential", password)
	alias := "alias-" + email
	s.request(t, "POST", "/admin/accounts/"+email+"/credentials",
		map[string]string{"email": alias, "password": aliasPassword}, http.StatusCreated)
	s.mustLogin(t, alias, aliasPassword)

	s.request(t, "DELETE", "/admin/credentials/"+alias, nil, http.StatusOK)

	if _, err := s.login(t, alias, aliasPassword); err == nil {
		t.Error("a deleted credential can still sign in")
	}
	s.mustLogin(t, email, password)
}
