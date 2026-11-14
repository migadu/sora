package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

type recordedAdminLookupCache struct {
	mu       sync.Mutex
	accounts []int64
}

func (c *recordedAdminLookupCache) InvalidateUser(serverName, username string) {}

func (c *recordedAdminLookupCache) InvalidateAccount(accountID int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accounts = append(c.accounts, accountID)
}

func (c *recordedAdminLookupCache) forgot(accountID int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Contains(c.accounts, accountID)
}

func (c *recordedAdminLookupCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accounts = nil
}

func serveAdminRequest(t *testing.T, h http.Handler, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var payload string
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		payload = string(b)
	}
	req := httptest.NewRequest(method, target, strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+rwKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	var panicked any
	func() {
		defer func() { panicked = recover() }()
		h.ServeHTTP(rec, req)
	}()
	if panicked != nil {
		t.Errorf("%s %s panicked instead of answering cleanly: %v", method, target, panicked)
		return nil
	}
	return rec
}

func assertBadAddressResponse(t *testing.T, method, target string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec == nil {
		return
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("%s %s: status %d, want 400; body=%s", method, target, rec.Code, rec.Body.String())
		return
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Errorf("%s %s: body %q is not JSON: %v", method, target, rec.Body.String(), err)
		return
	}
	if resp["error"] == "" {
		t.Errorf("%s %s: empty error field in %q", method, target, rec.Body.String())
	}
}

func TestAdminAPIAddressValidationWithoutDatabase(t *testing.T) {
	const trackerKey = "IMAP-node-1-imap-proxy"
	tracker := server.NewConnectionTracker("IMAP", "imap-proxy", "host", "node-1-imap-proxy", nil, 0, 0, 0, true)
	t.Cleanup(tracker.Stop)

	s, err := New(nil, ServerOptions{
		Name:   "addr-unit",
		APIKey: rwKey,
		ConnectionTrackers: func() map[string]*server.ConnectionTracker {
			return map[string]*server.ConnectionTracker{trackerKey: tracker}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := s.setupRoutes()

	noTrackers, err := New(nil, ServerOptions{Name: "addr-no-trackers", APIKey: rwKey})
	if err != nil {
		t.Fatalf("New(noTrackers): %v", err)
	}
	hNoTrackers := noTrackers.setupRoutes()

	t.Run("unparsable and NUL addresses answer 400 before touching database", func(t *testing.T) {
		badSegments := []struct {
			name    string
			segment string
			raw     string
		}{
			{"missing at", "not-an-address", "not-an-address"},
			{"nul byte in local part", "a%00b@example.com", "a\x00b@example.com"},
			{"whitespace in address", "a%20b@example.com", "a b@example.com"},
			{"invalid utf8 in path", "%ff@example.com", ""},
			{"invalid domain", "user@bad_domain", "user@bad_domain"},
		}
		for _, bad := range badSegments {
			t.Run(bad.name, func(t *testing.T) {
				cases := []struct {
					method, path string
					body         any
				}{
					{http.MethodPost, "/admin/accounts/" + bad.segment + "/credentials", AddCredentialRequest{Email: "alias@example.com", Password: "pw-123456"}},
					{http.MethodGet, "/admin/credentials/" + bad.segment, nil},
					{http.MethodGet, "/admin/accounts/" + bad.segment + "/messages/deleted", nil},
					{http.MethodPost, "/admin/accounts/" + bad.segment + "/messages/restore", map[string]string{"mailbox": "INBOX"}},
					{http.MethodGet, "/admin/connections/user/" + bad.segment, nil},
				}
				if bad.raw != "" {
					cases = append(cases, struct {
						method, path string
						body         any
					}{http.MethodPost, "/admin/connections/kick", KickConnectionsRequest{UserEmail: bad.raw}})
				}
				for _, tc := range cases {
					rec := serveAdminRequest(t, h, tc.method, tc.path, tc.body)
					assertBadAddressResponse(t, tc.method, tc.path, rec)
				}
				recNoTrackers := serveAdminRequest(t, hNoTrackers, http.MethodGet, "/admin/connections/user/"+bad.segment, nil)
				assertBadAddressResponse(t, http.MethodGet, "/admin/connections/user/"+bad.segment+" (no trackers)", recNoTrackers)
			})
		}
	})

	t.Run("user connections and kick fold IDN domains without database", func(t *testing.T) {
		const (
			unicodeEmail = "anna@münchen.de"
			asciiEmail   = "anna@xn--mnchen-3ya.de"
		)
		derivedASCII := proxy.DeriveAccountIDFromEmail(asciiEmail)
		if err := tracker.RegisterConnection(context.Background(), derivedASCII, asciiEmail, "IMAP", "192.0.2.10:50000"); err != nil {
			t.Fatalf("RegisterConnection: %v", err)
		}
		kicked := tracker.RegisterSession(derivedASCII)
		t.Cleanup(func() {
			tracker.UnregisterSession(derivedASCII, kicked)
			_ = tracker.UnregisterConnection(context.Background(), derivedASCII, "IMAP", "192.0.2.10:50000")
		})

		escaped := url.PathEscape(unicodeEmail)
		rec := serveAdminRequest(t, h, http.MethodGet, "/admin/connections/user/"+escaped, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /admin/connections/user/%s: %d %s", escaped, rec.Code, rec.Body.String())
		}
		var got struct {
			Email       string           `json:"email"`
			Count       int              `json:"count"`
			Connections []ConnectionInfo `json:"connections"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode user connections: %v", err)
		}
		if got.Email != unicodeEmail {
			t.Errorf("email = %q, want %q", got.Email, unicodeEmail)
		}
		if got.Count != 1 || len(got.Connections) != 1 || got.Connections[0].Email != asciiEmail {
			t.Fatalf("connections for %s = %+v, want 1 entry for %s", unicodeEmail, got, asciiEmail)
		}

		kickRec := serveAdminRequest(t, h, http.MethodPost, "/admin/connections/kick", KickConnectionsRequest{UserEmail: unicodeEmail})
		if kickRec.Code != http.StatusOK {
			t.Fatalf("POST /admin/connections/kick (%s): %d %s", unicodeEmail, kickRec.Code, kickRec.Body.String())
		}
		select {
		case <-kicked:
		case <-time.After(2 * time.Second):
			t.Errorf("session under %s (ID %d) stayed open after kick of %s", asciiEmail, derivedASCII, unicodeEmail)
		}
	})
}

func setupAdminAPITestDatabase(t *testing.T) *resilient.ResilientDatabase {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping database test in short mode")
	}
	conn, err := net.DialTimeout("tcp", "localhost:5432", time.Second)
	if err != nil {
		t.Skipf("PostgreSQL unavailable on localhost:5432: %v", err)
	}
	_ = conn.Close()

	dbName := os.Getenv("SORA_TEST_DB_NAME")
	if dbName == "" {
		dbName = "sora_test_db"
	}
	cfg := &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{
			Hosts: []string{"localhost"},
			Port:  "5432",
			User:  "postgres",
			Name:  dbName,
		},
	}
	rdb, err := resilient.NewResilientDatabase(context.Background(), cfg, false, true)
	if err != nil {
		t.Fatalf("NewResilientDatabase(%s): %v", dbName, err)
	}
	t.Cleanup(rdb.Close)
	return rdb
}

func TestAdminAPIAddressValidationAndIDNWithDatabase(t *testing.T) {
	rdb := setupAdminAPITestDatabase(t)

	const trackerKey = "IMAP-node-1-imap-proxy"
	tracker := server.NewConnectionTracker("IMAP", "imap-proxy", "host", "node-1-imap-proxy", nil, 0, 0, 0, true)
	t.Cleanup(tracker.Stop)
	logins := &recordedAdminLookupCache{}
	tracker.SetLookupCache(logins)

	s, err := New(rdb, ServerOptions{
		Name:   "addr-db",
		APIKey: rwKey,
		ConnectionTrackers: func() map[string]*server.ConnectionTracker {
			return map[string]*server.ConnectionTracker{trackerKey: tracker}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := s.setupRoutes()

	t.Run("unparsable and NUL addresses answer 400 with live database", func(t *testing.T) {
		for _, bad := range []struct {
			name, segment, raw string
		}{
			{"missing at", "not-an-address", "not-an-address"},
			{"nul byte", "a%00b@example.com", "a\x00b@example.com"},
		} {
			t.Run(bad.name, func(t *testing.T) {
				cases := []struct {
					method, path string
					body         any
				}{
					{http.MethodPost, "/admin/accounts/" + bad.segment + "/credentials", AddCredentialRequest{Email: "alias@example.com", Password: "pw-123456"}},
					{http.MethodGet, "/admin/credentials/" + bad.segment, nil},
					{http.MethodGet, "/admin/accounts/" + bad.segment + "/messages/deleted", nil},
					{http.MethodPost, "/admin/accounts/" + bad.segment + "/messages/restore", map[string]string{"mailbox": "INBOX"}},
					{http.MethodGet, "/admin/connections/user/" + bad.segment, nil},
					{http.MethodPost, "/admin/connections/kick", KickConnectionsRequest{UserEmail: bad.raw}},
					{http.MethodDelete, "/admin/accounts/" + bad.segment, nil},
					{http.MethodDelete, "/admin/credentials/" + bad.segment, nil},
				}
				for _, tc := range cases {
					rec := serveAdminRequest(t, h, tc.method, tc.path, tc.body)
					assertBadAddressResponse(t, tc.method, tc.path, rec)
				}
			})
		}
	})

	t.Run("IDN punycode normalization across credential, message, connection, and revocation routes", func(t *testing.T) {
		stamp := time.Now().UnixNano()
		primaryUnicode := fmt.Sprintf("anna-%d@münchen.de", stamp)
		primaryASCII := fmt.Sprintf("anna-%d@xn--mnchen-3ya.de", stamp)
		aliasUnicode := fmt.Sprintf("alias-%d@bücher.de", stamp)
		aliasASCII := fmt.Sprintf("alias-%d@xn--bcher-kva.de", stamp)

		createRec := serveAdminRequest(t, h, http.MethodPost, "/admin/accounts", CreateAccountRequest{
			Email:    primaryUnicode,
			Password: "pw-primary-123456",
		})
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create account %s: %d %s", primaryUnicode, createRec.Code, createRec.Body.String())
		}
		var created struct {
			AccountID int64 `json:"account_id"`
		}
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create response: %v", err)
		}

		// POST /admin/accounts/{email}/credentials with U-label path {email}
		addCredPath := "/admin/accounts/" + url.PathEscape(primaryUnicode) + "/credentials"
		addRec := serveAdminRequest(t, h, http.MethodPost, addCredPath, AddCredentialRequest{
			Email:    aliasUnicode,
			Password: "pw-alias-123456",
		})
		if addRec.Code != http.StatusCreated {
			t.Fatalf("POST %s: %d %s", addCredPath, addRec.Code, addRec.Body.String())
		}

		// GET /admin/credentials/{email} with U-label path {email}
		for _, pair := range []struct{ unicode, ascii string }{
			{primaryUnicode, primaryASCII},
			{aliasUnicode, aliasASCII},
		} {
			credPath := "/admin/credentials/" + url.PathEscape(pair.unicode)
			credRec := serveAdminRequest(t, h, http.MethodGet, credPath, nil)
			if credRec.Code != http.StatusOK {
				t.Fatalf("GET %s: %d %s", credPath, credRec.Code, credRec.Body.String())
			}
			var details db.CredentialDetails
			if err := json.Unmarshal(credRec.Body.Bytes(), &details); err != nil {
				t.Fatalf("decode credential details: %v", err)
			}
			if details.Address != pair.ascii {
				t.Errorf("GET %s: address = %q, want %q", credPath, details.Address, pair.ascii)
			}
		}

		// GET /admin/accounts/{email}/messages/deleted and POST .../messages/restore with U-label
		delMsgPath := "/admin/accounts/" + url.PathEscape(primaryUnicode) + "/messages/deleted"
		if rec := serveAdminRequest(t, h, http.MethodGet, delMsgPath, nil); rec.Code != http.StatusOK {
			t.Errorf("GET %s: %d %s, want 200", delMsgPath, rec.Code, rec.Body.String())
		}
		restoreMsgPath := "/admin/accounts/" + url.PathEscape(primaryUnicode) + "/messages/restore"
		if rec := serveAdminRequest(t, h, http.MethodPost, restoreMsgPath, map[string]string{"mailbox": "INBOX"}); rec.Code != http.StatusOK {
			t.Errorf("POST %s: %d %s, want 200", restoreMsgPath, rec.Code, rec.Body.String())
		}

		// Register a backend session (keyed by database accountID) and a remote-lookup proxy
		// session (keyed by DeriveAccountIDFromEmail(aliasASCII)) and query/kick by U-label.
		registerPair := func() (<-chan struct{}, <-chan struct{}, func()) {
			aliasDerived := proxy.DeriveAccountIDFromEmail(aliasASCII)
			if err := tracker.RegisterConnection(context.Background(), created.AccountID, primaryASCII, "IMAP", "192.0.2.20:50001"); err != nil {
				t.Fatalf("RegisterConnection(db): %v", err)
			}
			if err := tracker.RegisterConnection(context.Background(), aliasDerived, aliasASCII, "IMAP", "192.0.2.21:50002"); err != nil {
				t.Fatalf("RegisterConnection(derived): %v", err)
			}
			dbSession := tracker.RegisterSession(created.AccountID)
			rlSession := tracker.RegisterSession(aliasDerived)
			cleanup := func() {
				tracker.UnregisterSession(created.AccountID, dbSession)
				tracker.UnregisterSession(aliasDerived, rlSession)
				_ = tracker.UnregisterConnection(context.Background(), created.AccountID, "IMAP", "192.0.2.20:50001")
				_ = tracker.UnregisterConnection(context.Background(), aliasDerived, "IMAP", "192.0.2.21:50002")
			}
			return dbSession, rlSession, cleanup
		}

		dbSession, rlSession, cleanup := registerPair()
		defer cleanup()

		connPath := "/admin/connections/user/" + url.PathEscape(primaryUnicode)
		connRec := serveAdminRequest(t, h, http.MethodGet, connPath, nil)
		if connRec.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", connPath, connRec.Code, connRec.Body.String())
		}
		var connBody struct {
			Count int `json:"count"`
		}
		if err := json.Unmarshal(connRec.Body.Bytes(), &connBody); err != nil {
			t.Fatalf("decode user connections: %v", err)
		}
		if connBody.Count != 2 {
			t.Errorf("GET %s listed %d entries, want 2 (backend + remote-lookup alias): %s", connPath, connBody.Count, connRec.Body.String())
		}

		// POST /admin/connections/kick with U-label kicks both DB account ID and derived alias ID.
		kickRec := serveAdminRequest(t, h, http.MethodPost, "/admin/connections/kick", KickConnectionsRequest{UserEmail: primaryUnicode})
		if kickRec.Code != http.StatusOK {
			t.Fatalf("POST /admin/connections/kick (%s): %d %s", primaryUnicode, kickRec.Code, kickRec.Body.String())
		}
		for name, ch := range map[string]<-chan struct{}{"backend": dbSession, "remote-lookup": rlSession} {
			select {
			case <-ch:
			case <-time.After(2 * time.Second):
				t.Errorf("%s session stayed open after kick of %s", name, primaryUnicode)
			}
		}
		cleanup()

		// PUT /admin/accounts/{email} with U-label forgets cached logins under DB account ID and derived IDs.
		logins.reset()
		putPath := "/admin/accounts/" + url.PathEscape(primaryUnicode)
		if rec := serveAdminRequest(t, h, http.MethodPut, putPath, UpdateAccountRequest{Password: "pw-updated-123456"}); rec.Code != http.StatusOK {
			t.Fatalf("PUT %s: %d %s", putPath, rec.Code, rec.Body.String())
		}
		for _, wantID := range []int64{created.AccountID, proxy.DeriveAccountIDFromEmail(primaryASCII), proxy.DeriveAccountIDFromEmail(aliasASCII)} {
			if !logins.forgot(wantID) {
				t.Errorf("PUT %s did not drop cached logins for ID %d", putPath, wantID)
			}
		}

		// DELETE /admin/credentials/{email} with U-label forgets cached logins under DB account ID and derived ID.
		logins.reset()
		delCredPath := "/admin/credentials/" + url.PathEscape(aliasUnicode)
		if rec := serveAdminRequest(t, h, http.MethodDelete, delCredPath, nil); rec.Code != http.StatusOK {
			t.Fatalf("DELETE %s: %d %s", delCredPath, rec.Code, rec.Body.String())
		}
		for _, wantID := range []int64{created.AccountID, proxy.DeriveAccountIDFromEmail(aliasASCII)} {
			if !logins.forgot(wantID) {
				t.Errorf("DELETE %s did not drop cached logins for ID %d", delCredPath, wantID)
			}
		}

		// DELETE /admin/accounts/{email} with U-label ends sessions under DB account ID and derived primary ID.
		primaryDerived := proxy.DeriveAccountIDFromEmail(primaryASCII)
		if err := tracker.RegisterConnection(context.Background(), created.AccountID, primaryASCII, "IMAP", "192.0.2.22:50003"); err != nil {
			t.Fatalf("RegisterConnection: %v", err)
		}
		if err := tracker.RegisterConnection(context.Background(), primaryDerived, primaryASCII, "IMAP", "192.0.2.23:50004"); err != nil {
			t.Fatalf("RegisterConnection: %v", err)
		}
		dbDelSession := tracker.RegisterSession(created.AccountID)
		rlDelSession := tracker.RegisterSession(primaryDerived)
		defer func() {
			tracker.UnregisterSession(created.AccountID, dbDelSession)
			tracker.UnregisterSession(primaryDerived, rlDelSession)
			_ = tracker.UnregisterConnection(context.Background(), created.AccountID, "IMAP", "192.0.2.22:50003")
			_ = tracker.UnregisterConnection(context.Background(), primaryDerived, "IMAP", "192.0.2.23:50004")
		}()

		delAcctPath := "/admin/accounts/" + url.PathEscape(primaryUnicode)
		if rec := serveAdminRequest(t, h, http.MethodDelete, delAcctPath, nil); rec.Code != http.StatusOK {
			t.Fatalf("DELETE %s: %d %s", delAcctPath, rec.Code, rec.Body.String())
		}
		for name, ch := range map[string]<-chan struct{}{"backend": dbDelSession, "remote-lookup": rlDelSession} {
			select {
			case <-ch:
			case <-time.After(2 * time.Second):
				t.Errorf("%s session stayed open after DELETE %s", name, delAcctPath)
			}
		}
	})
}
