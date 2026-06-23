//go:build integration

package userapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/userapi"
)

// TestUserAPI_SharedMailbox_RequiresReadRight is a regression test for the H2
// finding: the User API exposed a shared mailbox's message metadata (list/search/
// counts) to a grantee holding only the 'l' (lookup) ACL right, where IMAP correctly
// requires 'r' (read). The fix gates list/search/counts on the read right.
//
// It drives the real attack path: a same-domain user is granted only 'l' on another
// account's shared mailbox, then calls the User API and must NOT see the contents.
func TestUserAPI_SharedMailbox_RequiresReadRight(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapServer, owner := common.SetupIMAPServer(t)
	defer imapServer.Close()
	rdb := imapServer.ResilientDB
	ctx := context.Background()

	// Second account in the SAME domain (the grantee/attacker).
	domain := strings.Split(owner.Email, "@")[1]
	granteeEmail := fmt.Sprintf("grantee-%d@%s", common.GetTimestamp(), domain)
	const granteePassword = "grantee-pass-123"
	if _, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email:     granteeEmail,
		Password:  granteePassword,
		HashType:  "bcrypt",
		IsPrimary: true,
	}); err != nil {
		t.Fatalf("create grantee: %v", err)
	}

	// Owner creates a shared mailbox (the "Shared/" prefix marks it is_shared) and
	// appends a message whose subject must never reach a lookup-only grantee.
	sharedMailbox := fmt.Sprintf("Shared/H2-%d", common.GetTimestamp())
	const secretSubject = "H2-secret-subject"

	c1, err := imapclient.DialInsecure(imapServer.Address, nil)
	if err != nil {
		t.Fatalf("dial IMAP: %v", err)
	}
	if err := c1.Login(owner.Email, owner.Password).Wait(); err != nil {
		t.Fatalf("owner login: %v", err)
	}
	defer func() { _ = c1.Logout() }()
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	msg := "From: owner@" + domain + "\r\nTo: owner@" + domain +
		"\r\nSubject: " + secretSubject + "\r\n\r\nconfidential body\r\n"
	ap := c1.Append(sharedMailbox, int64(len(msg)), nil)
	if _, err := ap.Write([]byte(msg)); err != nil {
		t.Fatalf("append write: %v", err)
	}
	if err := ap.Close(); err != nil {
		t.Fatalf("append close: %v", err)
	}
	if _, err := ap.Wait(); err != nil {
		t.Fatalf("append: %v", err)
	}

	ownerID, err := rdb.GetAccountIDByAddressWithRetry(ctx, owner.Email)
	if err != nil {
		t.Fatalf("owner id: %v", err)
	}

	// Stand up the User API against the same database.
	ts := newUserAPITestServer(t, rdb)
	client := ts.Client()

	token := h2Login(t, ts, client, granteeEmail, granteePassword)

	listPath := "/user/mailboxes/" + sharedMailbox + "/messages"
	searchPath := "/user/mailboxes/" + sharedMailbox + "/search?q=" + secretSubject

	// === Phase 1: grantee has only 'l' (lookup) — contents MUST be hidden. ===
	if err := rdb.GrantMailboxAccessByIdentifierWithRetry(ctx, ownerID, granteeEmail, sharedMailbox, "l"); err != nil {
		t.Fatalf("grant 'l': %v", err)
	}

	if code, body := h2Get(t, ts, client, token, listPath); code != http.StatusNotFound {
		t.Errorf("list with only 'l': expected 404, got %d (body: %s)", code, body)
	} else if strings.Contains(body, secretSubject) {
		t.Errorf("LEAK: list exposed message subject to lookup-only grantee")
	}

	if code, body := h2Get(t, ts, client, token, searchPath); code != http.StatusNotFound {
		t.Errorf("search with only 'l': expected 404, got %d (body: %s)", code, body)
	} else if strings.Contains(body, secretSubject) {
		t.Errorf("LEAK: search exposed message subject to lookup-only grantee")
	}

	// The mailbox is visible in the listing (that's what 'l' grants), but its counts
	// must be hidden (shown as 0) rather than leaking the real message count.
	if total, found := h2MailboxTotal(t, ts, client, token, sharedMailbox); !found {
		t.Errorf("shared mailbox should be visible in listing with 'l' right")
	} else if total != 0 {
		t.Errorf("LEAK: lookup-only grantee saw message count %d (expected hidden 0)", total)
	}

	// === Phase 2: grant 'r' — the grantee may now read (fix must not over-block). ===
	if err := rdb.GrantMailboxAccessByIdentifierWithRetry(ctx, ownerID, granteeEmail, sharedMailbox, "lr"); err != nil {
		t.Fatalf("grant 'lr': %v", err)
	}
	if code, body := h2Get(t, ts, client, token, listPath); code != http.StatusOK {
		t.Errorf("list with 'lr': expected 200, got %d (body: %s)", code, body)
	} else if !strings.Contains(body, secretSubject) {
		t.Errorf("reader with 'r' should see message subject %q, body: %s", secretSubject, body)
	}
	if total, found := h2MailboxTotal(t, ts, client, token, sharedMailbox); !found || total != 1 {
		t.Errorf("reader with 'r' should see the real count (1); found=%v total=%d", found, total)
	}
}

func h2Login(t *testing.T, ts *httptest.Server, client *http.Client, email, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	resp, err := client.Post(ts.URL+"/user/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("login failed: %d (%s)", resp.StatusCode, b)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	tok, _ := out["token"].(string)
	if tok == "" {
		t.Fatal("no token in login response")
	}
	return tok
}

func h2Get(t *testing.T, ts *httptest.Server, client *http.Client, token, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequest("GET", ts.URL+path, nil)
	if err != nil {
		t.Fatalf("build GET %s: %v", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// h2MailboxTotal fetches /user/mailboxes and returns the total count reported for
// the named mailbox (and whether it was present in the listing at all).
func h2MailboxTotal(t *testing.T, ts *httptest.Server, client *http.Client, token, name string) (int, bool) {
	t.Helper()
	code, body := h2Get(t, ts, client, token, "/user/mailboxes")
	if code != http.StatusOK {
		t.Fatalf("list mailboxes: expected 200, got %d (%s)", code, body)
	}
	var out struct {
		Mailboxes []struct {
			Name  string `json:"name"`
			Total int    `json:"total"`
		} `json:"mailboxes"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode mailboxes: %v (body: %s)", err, body)
	}
	for _, mb := range out.Mailboxes {
		if mb.Name == name {
			return mb.Total, true
		}
	}
	return 0, false
}

// newUserAPITestServer stands up a User API HTTP server backed by rdb.
func newUserAPITestServer(t *testing.T, rdb *resilient.ResilientDatabase) *httptest.Server {
	t.Helper()
	apiSrv, err := userapi.New(rdb, userapi.ServerOptions{
		Name:           "test-userapi",
		Addr:           "127.0.0.1:0",
		JWTSecret:      "test-secret-key-for-testing-only",
		TokenDuration:  time.Hour,
		TokenIssuer:    "test-issuer",
		AllowedOrigins: []string{"*"},
		TLS:            false,
	})
	if err != nil {
		t.Fatalf("userapi.New: %v", err)
	}
	ts := httptest.NewServer(apiSrv.SetupRoutes())
	t.Cleanup(func() { ts.Close() })
	return ts
}

// TestUserAPI_MessageRead_TimestampScan is a regression test for B1: the User API
// message read endpoints (list, search, get-by-id) returned HTTP 500 on any
// non-empty mailbox because sent_date/internal_date (timestamptz) were scanned into
// string struct fields. This verifies all three endpoints now return the message
// with properly populated timestamps.
func TestUserAPI_MessageRead_TimestampScan(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapServer, owner := common.SetupIMAPServer(t)
	defer imapServer.Close()
	rdb := imapServer.ResilientDB

	const subject = "B1-timestamp-scan"

	// Owner appends a message to their own INBOX.
	c1, err := imapclient.DialInsecure(imapServer.Address, nil)
	if err != nil {
		t.Fatalf("dial IMAP: %v", err)
	}
	if err := c1.Login(owner.Email, owner.Password).Wait(); err != nil {
		t.Fatalf("owner login: %v", err)
	}
	defer func() { _ = c1.Logout() }()

	msg := "From: a@example.com\r\nTo: b@example.com\r\nSubject: " + subject +
		"\r\nDate: Mon, 02 Jan 2006 15:04:05 -0700\r\n\r\nbody\r\n"
	ap := c1.Append("INBOX", int64(len(msg)), nil)
	if _, err := ap.Write([]byte(msg)); err != nil {
		t.Fatalf("append write: %v", err)
	}
	if err := ap.Close(); err != nil {
		t.Fatalf("append close: %v", err)
	}
	if _, err := ap.Wait(); err != nil {
		t.Fatalf("append: %v", err)
	}

	ts := newUserAPITestServer(t, rdb)
	client := ts.Client()
	token := h2Login(t, ts, client, owner.Email, owner.Password)

	// 1) List endpoint — the path that exposed B1. Must return the message with
	//    non-zero timestamps (proves the timestamptz -> time.Time scan works).
	code, body := h2Get(t, ts, client, token, "/user/mailboxes/INBOX/messages")
	if code != http.StatusOK {
		t.Fatalf("list INBOX: expected 200, got %d (body: %s)", code, body)
	}
	var listResp struct {
		Messages []struct {
			ID           int64     `json:"id"`
			Subject      string    `json:"subject"`
			Date         time.Time `json:"date"`
			InternalDate time.Time `json:"internal_date"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(body), &listResp); err != nil {
		t.Fatalf("decode list: %v (body: %s)", err, body)
	}
	var msgID int64
	var found bool
	for _, m := range listResp.Messages {
		if m.Subject == subject {
			found = true
			msgID = m.ID
			if m.Date.IsZero() {
				t.Errorf("date not populated (timestamptz scan regressed)")
			}
			if m.InternalDate.IsZero() {
				t.Errorf("internal_date not populated (timestamptz scan regressed)")
			}
		}
	}
	if !found {
		t.Fatalf("appended message not returned by list endpoint; body: %s", body)
	}

	// 2) Search endpoint — same scan path.
	if code, body := h2Get(t, ts, client, token, "/user/mailboxes/INBOX/search?q="+subject); code != http.StatusOK || !strings.Contains(body, subject) {
		t.Errorf("search INBOX: expected 200 with subject, got %d (body: %s)", code, body)
	}

	// 3) Get-by-id endpoint — same scan path.
	if code, body := h2Get(t, ts, client, token, fmt.Sprintf("/user/messages/%d", msgID)); code != http.StatusOK || !strings.Contains(body, subject) {
		t.Errorf("get message by id: expected 200 with subject, got %d (body: %s)", code, body)
	}
}
