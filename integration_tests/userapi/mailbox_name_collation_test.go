//go:build integration

package userapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/server/userapi"
)

func fetchMailboxMap(t *testing.T, tc *TestContext, query string) map[string]userapi.MailboxInfo {
	t.Helper()
	path := "/user/mailboxes"
	if query != "" {
		path += "?" + query
	}
	resp := tc.makeRequest(t, http.MethodGet, path, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("GET %s: status %d, want 200 (body: %s)", path, resp.StatusCode, string(body))
	}
	var payload struct {
		Mailboxes []userapi.MailboxInfo `json:"mailboxes"`
	}
	parseJSON(t, resp, &payload)
	byName := make(map[string]userapi.MailboxInfo, len(payload.Mailboxes))
	for _, mb := range payload.Mailboxes {
		byName[mb.Name] = mb
	}
	return byName
}

func TestUserAPIMailboxCollationIdentity(t *testing.T) {
	tc := setupTestServer(t)
	tc.JWTToken = tc.loginFor(t, tc.TestUser.Email, tc.TestUser.Password)
	ctx := context.Background()
	accountID := tc.accountID(t)

	doStatus := func(t *testing.T, method, path string, body any) (int, string) {
		t.Helper()
		resp := tc.makeRequest(t, method, path, body)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(raw)
	}

	var iDotMatchesInbox bool
	if err := tc.RDB.GetOperationalDatabase().WritePool.QueryRow(
		ctx, "SELECT LOWER($1) = LOWER($2)", "\u0130NBOX", "INBOX",
	).Scan(&iDotMatchesInbox); err != nil {
		t.Fatalf("check PostgreSQL LOWER() behavior for U+0130: %v", err)
	}

	if !iDotMatchesInbox {
		t.Run("ICU distinct U+0130 mailbox subscription and deletion", func(t *testing.T) {
			const lookalikeInbox = "\u0130NBOX" // U+0130 + NBOX
			escaped := url.PathEscape(lookalikeInbox)

			if code, body := doStatus(t, http.MethodPost, "/user/mailboxes", map[string]string{"name": lookalikeInbox}); code != http.StatusCreated {
				t.Fatalf("POST /user/mailboxes %q: status %d, want 201 (body: %s)", lookalikeInbox, code, body)
			}

			all := fetchMailboxMap(t, tc, "")
			if inbox, ok := all["INBOX"]; !ok || !inbox.Subscribed {
				t.Fatalf("GET /user/mailboxes INBOX = %+v (present=%v), want present and subscribed=true", inbox, ok)
			}
			if mb, ok := all[lookalikeInbox]; !ok {
				t.Fatalf("GET /user/mailboxes missing %q", lookalikeInbox)
			} else if mb.Subscribed {
				t.Errorf("GET /user/mailboxes reported unsubscribed %q as subscribed=true (matched INBOX via Go strings.ToLower)", lookalikeInbox)
			}

			subOnly := fetchMailboxMap(t, tc, "subscribed=true")
			if _, ok := subOnly["INBOX"]; !ok {
				t.Errorf("GET /user/mailboxes?subscribed=true missing INBOX")
			}
			if _, ok := subOnly[lookalikeInbox]; ok {
				t.Errorf("GET /user/mailboxes?subscribed=true included unsubscribed %q", lookalikeInbox)
			}

			if code, body := doStatus(t, http.MethodPost, "/user/mailboxes/"+escaped+"/subscribe", nil); code != http.StatusOK {
				t.Fatalf("POST subscribe %q: status %d, want 200 (body: %s)", lookalikeInbox, code, body)
			}
			if _, ok := fetchMailboxMap(t, tc, "subscribed=true")[lookalikeInbox]; !ok {
				t.Errorf("GET /user/mailboxes?subscribed=true missing %q after subscribe", lookalikeInbox)
			}

			if code, body := doStatus(t, http.MethodPost, "/user/mailboxes/"+escaped+"/unsubscribe", nil); code != http.StatusOK {
				t.Fatalf("POST unsubscribe %q: status %d, want 200 (body: %s)", lookalikeInbox, code, body)
			}
			if mb, ok := fetchMailboxMap(t, tc, "")[lookalikeInbox]; !ok || mb.Subscribed {
				t.Errorf("GET /user/mailboxes after unsubscribe %q = %+v (present=%v), want present and subscribed=false", lookalikeInbox, mb, ok)
			}
			if _, ok := fetchMailboxMap(t, tc, "subscribed=true")[lookalikeInbox]; ok {
				t.Errorf("GET /user/mailboxes?subscribed=true still includes %q after unsubscribe", lookalikeInbox)
			}

			if code, body := doStatus(t, http.MethodDelete, "/user/mailboxes/"+escaped, nil); code != http.StatusOK {
				t.Fatalf("DELETE %q: status %d, want 200 (body: %s)", lookalikeInbox, code, body)
			}
			afterDel := fetchMailboxMap(t, tc, "")
			if _, ok := afterDel[lookalikeInbox]; ok {
				t.Errorf("GET /user/mailboxes still lists %q after DELETE", lookalikeInbox)
			}
			if inbox, ok := afterDel["INBOX"]; !ok || !inbox.Subscribed {
				t.Errorf("INBOX after deleting %q = %+v (present=%v), want present and subscribed=true", lookalikeInbox, inbox, ok)
			}
		})

		t.Run("ICU distinct U+0130 non-default mailbox does not inherit ASCII subscription", func(t *testing.T) {
			const upperIDot = "\u0130tems"
			if err := tc.RDB.SubscribeWithRetry(ctx, accountID, "items"); err != nil {
				t.Fatalf("SubscribeWithRetry(\"items\"): %v", err)
			}
			if code, body := doStatus(t, http.MethodPost, "/user/mailboxes", map[string]string{"name": upperIDot}); code != http.StatusCreated {
				t.Fatalf("POST /user/mailboxes %q: status %d, want 201 (body: %s)", upperIDot, code, body)
			}

			all := fetchMailboxMap(t, tc, "")
			if mb, ok := all[upperIDot]; !ok {
				t.Fatalf("GET /user/mailboxes missing %q", upperIDot)
			} else if mb.Subscribed {
				t.Errorf("GET /user/mailboxes reported unsubscribed %q as subscribed=true because \"items\" is subscribed", upperIDot)
			}
			if _, ok := fetchMailboxMap(t, tc, "subscribed=true")[upperIDot]; ok {
				t.Errorf("GET /user/mailboxes?subscribed=true included unsubscribed %q", upperIDot)
			}
		})
	} else {
		t.Run("libc U+0130 alias for INBOX cannot delete INBOX", func(t *testing.T) {
			escaped := url.PathEscape("\u0130NBOX")
			code, body := doStatus(t, http.MethodDelete, "/user/mailboxes/"+escaped, nil)
			if code != http.StatusForbidden {
				t.Errorf("DELETE /user/mailboxes/%s: status %d (body: %s), want 403 Forbidden", escaped, code, body)
			}
			if !strings.Contains(body, "INBOX") {
				t.Errorf("DELETE /user/mailboxes/%s body = %s, want INBOX refusal message", escaped, body)
			}

			if err := tc.RDB.DeleteMailboxForUserWithRetry(ctx, accountID, "\u0130NBOX"); !errors.Is(err, consts.ErrNotPermitted) {
				t.Errorf("DeleteMailboxForUserWithRetry(\"\\u0130NBOX\") = %v, want ErrNotPermitted", err)
			}

			all := fetchMailboxMap(t, tc, "")
			if inbox, ok := all["INBOX"]; !ok || !inbox.Subscribed {
				t.Fatalf("INBOX missing or unsubscribed after refused DELETE: %+v (present=%v)", inbox, ok)
			}
		})
	}

	t.Run("ASCII case variants of INBOX are refused with 403", func(t *testing.T) {
		for _, variant := range []string{"INBOX", "inbox", "InBoX"} {
			code, body := doStatus(t, http.MethodDelete, "/user/mailboxes/"+variant, nil)
			if code != http.StatusForbidden || !strings.Contains(body, "Cannot delete INBOX") {
				t.Errorf("DELETE /user/mailboxes/%s: status %d (body: %s), want 403 Cannot delete INBOX", variant, code, body)
			}
		}
		if inbox, ok := fetchMailboxMap(t, tc, "")["INBOX"]; !ok || !inbox.Subscribed {
			t.Fatalf("INBOX missing or unsubscribed: %+v (present=%v)", inbox, ok)
		}
	})

	t.Run("long-s lookalike of Sent is an independent mailbox", func(t *testing.T) {
		const lookalikeSent = "\u017fent" // "ſent"
		escaped := url.PathEscape(lookalikeSent)

		if code, body := doStatus(t, http.MethodPost, "/user/mailboxes", map[string]string{"name": lookalikeSent}); code != http.StatusCreated {
			t.Fatalf("POST /user/mailboxes %q: status %d, want 201 (body: %s)", lookalikeSent, code, body)
		}
		if mb, ok := fetchMailboxMap(t, tc, "")[lookalikeSent]; !ok || mb.Subscribed {
			t.Errorf("GET /user/mailboxes %q = %+v (present=%v), want present and subscribed=false", lookalikeSent, mb, ok)
		}

		if code, body := doStatus(t, http.MethodPost, "/user/mailboxes/"+escaped+"/subscribe", nil); code != http.StatusOK {
			t.Fatalf("POST subscribe %q: status %d, want 200 (body: %s)", lookalikeSent, code, body)
		}
		if _, ok := fetchMailboxMap(t, tc, "subscribed=true")[lookalikeSent]; !ok {
			t.Errorf("GET /user/mailboxes?subscribed=true missing %q after subscribe", lookalikeSent)
		}

		if code, body := doStatus(t, http.MethodPost, "/user/mailboxes/"+escaped+"/unsubscribe", nil); code != http.StatusOK {
			t.Fatalf("POST unsubscribe %q: status %d, want 200 (body: %s)", lookalikeSent, code, body)
		}
		if _, ok := fetchMailboxMap(t, tc, "subscribed=true")[lookalikeSent]; ok {
			t.Errorf("GET /user/mailboxes?subscribed=true still includes %q after unsubscribe", lookalikeSent)
		}
		if sent, ok := fetchMailboxMap(t, tc, "subscribed=true")["Sent"]; !ok || !sent.Subscribed {
			t.Errorf("Sent missing or unsubscribed after unsubscribing %q: %+v (present=%v)", lookalikeSent, sent, ok)
		}

		if code, body := doStatus(t, http.MethodDelete, "/user/mailboxes/"+escaped, nil); code != http.StatusOK {
			t.Fatalf("DELETE %q: status %d, want 200 (body: %s)", lookalikeSent, code, body)
		}
		after := fetchMailboxMap(t, tc, "")
		if _, ok := after[lookalikeSent]; ok {
			t.Errorf("GET /user/mailboxes still lists %q after DELETE", lookalikeSent)
		}
		if sent, ok := after["Sent"]; !ok || !sent.Subscribed {
			t.Errorf("Sent missing or unsubscribed after deleting %q: %+v (present=%v)", lookalikeSent, sent, ok)
		}
	})
}
