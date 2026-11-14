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
	"slices"
	"strings"
	"testing"

	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// apiDo sends an authenticated User API request with an optional JSON body.
func apiDo(t *testing.T, ts *httptest.Server, client *http.Client, token, method, path string, body any) (int, string) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal %s %s body: %v", method, path, err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, ts.URL+path, reader)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// imapAppend appends msg to mailbox as the given user.
func imapAppend(t *testing.T, addr, email, password, mailbox, msg string, create bool) {
	t.Helper()
	c, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatalf("dial IMAP: %v", err)
	}
	defer func() { _ = c.Logout() }()
	if err := c.Login(email, password).Wait(); err != nil {
		t.Fatalf("IMAP login: %v", err)
	}
	if create {
		if err := c.Create(mailbox, nil).Wait(); err != nil {
			t.Fatalf("create %s: %v", mailbox, err)
		}
	}
	ap := c.Append(mailbox, int64(len(msg)), nil)
	if _, err := ap.Write([]byte(msg)); err != nil {
		t.Fatalf("append write: %v", err)
	}
	if err := ap.Close(); err != nil {
		t.Fatalf("append close: %v", err)
	}
	if _, err := ap.Wait(); err != nil {
		t.Fatalf("append: %v", err)
	}
}

type apiMessage struct {
	ID      int64    `json:"id"`
	Subject string   `json:"subject"`
	From    string   `json:"from"`
	To      []string `json:"to"`
	Cc      []string `json:"cc"`
	Bcc     []string `json:"bcc"`
	Flags   []string `json:"flags"`
}

// findMessage decodes a list or search response and returns the message with subject.
func findMessage(t *testing.T, body, subject string) apiMessage {
	t.Helper()
	var out struct {
		Messages []apiMessage `json:"messages"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode messages: %v (body: %s)", err, body)
	}
	for _, m := range out.Messages {
		if m.Subject == subject {
			return m
		}
	}
	t.Fatalf("message %q not in response: %s", subject, body)
	return apiMessage{}
}

// A grantee who can list a shared mailbox's messages can open them, and change their
// flags and delete them as far as the mailbox ACL allows (RFC 4314 §4: \Seen needs
// "s", \Deleted "t", other flags "w"), as over IMAP. The messages belong to the
// owner's account, so a by-ID lookup scoped to the token's account found none.
func TestUserAPI_SharedMailbox_MessageByIDFollowsACL(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapServer, owner := common.SetupIMAPServer(t)
	defer imapServer.Close()
	rdb := imapServer.ResilientDB
	ctx := context.Background()

	domain := strings.Split(owner.Email, "@")[1]
	granteeEmail := fmt.Sprintf("grantee-msg-%d@%s", common.GetTimestamp(), domain)
	const granteePassword = "grantee-pass-123"
	if _, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email: granteeEmail, Password: granteePassword, HashType: "bcrypt", IsPrimary: true,
	}); err != nil {
		t.Fatalf("create grantee: %v", err)
	}
	ownerID, err := rdb.GetAccountIDByAddressWithRetry(ctx, owner.Email)
	if err != nil {
		t.Fatalf("owner id: %v", err)
	}

	shared := fmt.Sprintf("Shared/Msg-%d", common.GetTimestamp())
	const subject = "shared-message-by-id"
	imapAppend(t, imapServer.Address, owner.Email, owner.Password, shared,
		"From: owner@"+domain+"\r\nTo: team@"+domain+"\r\nSubject: "+subject+"\r\n\r\nbody\r\n", true)

	ts := newUserAPITestServer(t, rdb)
	client := ts.Client()
	token := h2Login(t, ts, client, granteeEmail, granteePassword)
	grant := func(rights string) {
		t.Helper()
		if err := rdb.GrantMailboxAccessByIdentifierWithRetry(ctx, ownerID, granteeEmail, shared, rights); err != nil {
			t.Fatalf("grant %q: %v", rights, err)
		}
	}

	grant("lr")
	code, body := h2Get(t, ts, client, token, "/user/mailboxes/"+shared+"/messages")
	if code != http.StatusOK {
		t.Fatalf("list shared mailbox with 'lr': %d (%s)", code, body)
	}
	msgPath := fmt.Sprintf("/user/messages/%d", findMessage(t, body, subject).ID)
	flagsOf := func() []string {
		t.Helper()
		code, body := h2Get(t, ts, client, token, msgPath)
		if code != http.StatusOK {
			t.Fatalf("GET %s: %d (%s)", msgPath, code, body)
		}
		var m apiMessage
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("decode message: %v (%s)", err, body)
		}
		return m.Flags
	}

	t.Run("read right opens the message", func(t *testing.T) {
		if code, body := h2Get(t, ts, client, token, msgPath); code != http.StatusOK || !strings.Contains(body, subject) {
			t.Errorf("GET %s with 'lr': %d (%s), want 200 with the message", msgPath, code, body)
		}
	})

	t.Run("flags need their rights", func(t *testing.T) {
		if code, body := apiDo(t, ts, client, token, "PATCH", msgPath, map[string]any{"add_flags": []string{`\Flagged`}}); code != http.StatusForbidden {
			t.Errorf("PATCH \\Flagged with 'lr': %d (%s), want 403", code, body)
		}
		if code, body := apiDo(t, ts, client, token, "DELETE", msgPath, nil); code != http.StatusForbidden {
			t.Errorf("DELETE with 'lr': %d (%s), want 403", code, body)
		}

		grant("lrw")
		// RFC 4314 §4: STORE SHOULD NOT fail if at least one flag may be modified;
		// the others are left alone.
		if code, body := apiDo(t, ts, client, token, "PATCH", msgPath, map[string]any{"add_flags": []string{`\Seen`, `\Flagged`}}); code != http.StatusOK {
			t.Errorf("PATCH \\Seen \\Flagged with 'lrw': %d (%s), want 200", code, body)
		}
		if flags := flagsOf(); !slices.Contains(flags, `\Flagged`) || slices.Contains(flags, `\Seen`) {
			t.Errorf("flags after PATCH with 'lrw' = %v, want \\Flagged set and \\Seen not (no 's' right)", flags)
		}
		if code, body := apiDo(t, ts, client, token, "DELETE", msgPath, nil); code != http.StatusForbidden {
			t.Errorf("DELETE with 'lrw': %d (%s), want 403 (no 't' right)", code, body)
		}

		grant("lrwt")
		if code, body := apiDo(t, ts, client, token, "DELETE", msgPath, nil); code != http.StatusOK {
			t.Errorf("DELETE with 'lrwt': %d (%s), want 200", code, body)
		}
		if flags := flagsOf(); !slices.Contains(flags, `\Deleted`) {
			t.Errorf("flags after DELETE = %v, want \\Deleted", flags)
		}
	})

	t.Run("lookup right does not open the message", func(t *testing.T) {
		grant("l")
		if code, body := h2Get(t, ts, client, token, msgPath); code != http.StatusNotFound || strings.Contains(body, subject) {
			t.Errorf("GET %s with only 'l': %d (%s), want 404", msgPath, code, body)
		}
		if code, body := apiDo(t, ts, client, token, "PATCH", msgPath, map[string]any{"add_flags": []string{`\Answered`}}); code != http.StatusNotFound {
			t.Errorf("PATCH with only 'l': %d (%s), want 404", code, body)
		}
	})
}

// The message list, the search results and the single message carry the message's
// recipients, the same fields in all three. recipients_json is stored as a list of
// {type, email, name}, as IMAP FETCH ENVELOPE reads it.
func TestUserAPI_RecipientsSameInListSearchAndGet(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapServer, owner := common.SetupIMAPServer(t)
	defer imapServer.Close()

	const subject = "recipients-everywhere"
	imapAppend(t, imapServer.Address, owner.Email, owner.Password, "INBOX",
		"From: a@example.com\r\nTo: b@example.com\r\nCc: c@example.com, d@example.com\r\nBcc: e@example.com\r\nSubject: "+subject+"\r\n\r\nbody\r\n", false)

	ts := newUserAPITestServer(t, imapServer.ResilientDB)
	client := ts.Client()
	token := h2Login(t, ts, client, owner.Email, owner.Password)

	code, body := h2Get(t, ts, client, token, "/user/mailboxes/INBOX/messages")
	if code != http.StatusOK {
		t.Fatalf("list: %d (%s)", code, body)
	}
	listed := findMessage(t, body, subject)
	if listed.From != "a@example.com" || !slices.Equal(listed.To, []string{"b@example.com"}) ||
		!slices.Equal(listed.Cc, []string{"c@example.com", "d@example.com"}) || !slices.Equal(listed.Bcc, []string{"e@example.com"}) {
		t.Fatalf("list recipients from=%q to=%v cc=%v bcc=%v, want a@, [b@], [c@ d@], [e@] (example.com)",
			listed.From, listed.To, listed.Cc, listed.Bcc)
	}

	code, body = h2Get(t, ts, client, token, "/user/mailboxes/INBOX/search?q="+subject)
	if code != http.StatusOK {
		t.Fatalf("search: %d (%s)", code, body)
	}
	found := findMessage(t, body, subject)

	code, body = h2Get(t, ts, client, token, fmt.Sprintf("/user/messages/%d", listed.ID))
	if code != http.StatusOK {
		t.Fatalf("get: %d (%s)", code, body)
	}
	var got apiMessage
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode get: %v (%s)", err, body)
	}

	for name, m := range map[string]apiMessage{"search": found, "get": got} {
		if m.From != listed.From || !slices.Equal(m.To, listed.To) || !slices.Equal(m.Cc, listed.Cc) || !slices.Equal(m.Bcc, listed.Bcc) {
			t.Errorf("%s recipients from=%q to=%v cc=%v bcc=%v, list has from=%q to=%v cc=%v bcc=%v",
				name, m.From, m.To, m.Cc, m.Bcc, listed.From, listed.To, listed.Cc, listed.Bcc)
		}
	}
}
