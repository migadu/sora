//go:build integration

package userapi

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// TestPathNamesDecodedOnce checks that a mailbox or Sieve script name taken from
// the request path is percent-decoded exactly once: "+" (raw or as %2B) is a
// literal plus, never a space, "%25" names "%", and "%2F" is a "/" inside the
// name rather than a path separator (RFC 3986 §2.4).
func TestPathNamesDecodedOnce(t *testing.T) {
	tc := setupTestServer(t)
	tc.JWTToken = tc.loginFor(t, tc.TestUser.Email, tc.TestUser.Password)
	ctx := context.Background()
	accountID := tc.accountID(t)
	n := time.Now().UnixNano()

	do := func(t *testing.T, method, path string, body any) int {
		t.Helper()
		resp := tc.makeRequest(t, method, path, body)
		resp.Body.Close()
		return resp.StatusCode
	}
	createMailbox := func(t *testing.T, name string) {
		t.Helper()
		if got := do(t, "POST", "/user/mailboxes", map[string]string{"name": name}); got != http.StatusCreated {
			t.Fatalf("create mailbox %q: status %d, want 201", name, got)
		}
	}
	mailboxExists := func(name string) bool {
		_, err := tc.RDB.GetMailboxByNameWithRetry(ctx, accountID, name)
		return err == nil
	}
	scriptExists := func(name string) bool {
		_, err := tc.RDB.GetScriptByNameWithRetry(ctx, name, accountID)
		return err == nil
	}

	t.Run("Mailbox_PlusIsLiteral", func(t *testing.T) {
		name := fmt.Sprintf("Work+Personal-%d", n)
		createMailbox(t, name)
		for _, seg := range []string{name, fmt.Sprintf("Work%%2BPersonal-%d", n)} {
			base := "/user/mailboxes/" + seg
			for _, c := range []struct{ method, path string }{
				{"GET", base + "/messages"},
				{"GET", base + "/search?q=report"},
				{"POST", base + "/subscribe"},
				{"POST", base + "/unsubscribe"},
			} {
				if got := do(t, c.method, c.path, nil); got != http.StatusOK {
					t.Errorf("%s %s: status %d, want 200", c.method, c.path, got)
				}
			}
		}
	})

	t.Run("Mailbox_DeletePlusKeepsSpaceNamedMailbox", func(t *testing.T) {
		plus := fmt.Sprintf("Del+Me-%d", n)
		space := fmt.Sprintf("Del Me-%d", n)
		createMailbox(t, plus)
		createMailbox(t, space)
		if got := do(t, "DELETE", fmt.Sprintf("/user/mailboxes/Del%%2BMe-%d", n), nil); got != http.StatusOK {
			t.Fatalf("DELETE: status %d, want 200", got)
		}
		if mailboxExists(plus) {
			t.Errorf("mailbox %q still exists after DELETE of its name", plus)
		}
		if !mailboxExists(space) {
			t.Errorf("mailbox %q was deleted by a DELETE naming %q", space, plus)
		}
	})

	t.Run("Mailbox_PercentDecodedOnce", func(t *testing.T) {
		name := fmt.Sprintf("100%%-%d", n)
		createMailbox(t, name)
		path := fmt.Sprintf("/user/mailboxes/100%%25-%d/messages", n)
		if got := do(t, "GET", path, nil); got != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200", path, got)
		}
	})

	t.Run("Mailbox_EncodedSlashIsPartOfName", func(t *testing.T) {
		// The last level of this name is also an endpoint name; encoded, it is
		// still the mailbox being deleted, not the /search endpoint.
		name := fmt.Sprintf("Archive-%d/search", n)
		createMailbox(t, name)
		path := fmt.Sprintf("/user/mailboxes/Archive-%d%%2Fsearch", n)
		if got := do(t, "DELETE", path, nil); got != http.StatusOK {
			t.Fatalf("DELETE %s: status %d, want 200", path, got)
		}
		if mailboxExists(name) {
			t.Errorf("mailbox %q still exists after DELETE", name)
		}
	})

	t.Run("Filter_PlusIsLiteral", func(t *testing.T) {
		// PUT only accepts [A-Za-z0-9._-] names, but scripts stored over
		// ManageSieve may use any name and must be reachable here.
		name := fmt.Sprintf("rules+work-%d", n)
		if _, err := tc.RDB.CreateScriptWithRetry(ctx, accountID, name, "keep;"); err != nil {
			t.Fatalf("create script: %v", err)
		}
		path := fmt.Sprintf("/user/filters/rules%%2Bwork-%d", n)
		resp := tc.makeRequest(t, "GET", path, nil)
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("GET %s: status %d, want 200", path, resp.StatusCode)
		}
		var got map[string]any
		parseJSON(t, resp, &got)
		if got["name"] != name {
			t.Errorf("GET %s: name %v, want %q", path, got["name"], name)
		}
		if st := do(t, "POST", path+"/activate", nil); st != http.StatusOK {
			t.Errorf("POST %s/activate: status %d, want 200", path, st)
		}
		if st := do(t, "DELETE", path, nil); st != http.StatusOK {
			t.Errorf("DELETE %s: status %d, want 200", path, st)
		}
		if scriptExists(name) {
			t.Errorf("script %q still exists after DELETE", name)
		}
	})

	t.Run("Filter_PutDecodesOnce", func(t *testing.T) {
		// "%252E" is the three characters "%2E", which a script name may not
		// contain; decoding it a second time would store a script named ".".
		path := fmt.Sprintf("/user/filters/f%%252E-%d", n)
		if got := do(t, "PUT", path, map[string]string{"script": "keep;"}); got != http.StatusBadRequest {
			t.Errorf("PUT %s: status %d, want 400", path, got)
		}
		if decoded := fmt.Sprintf("f.-%d", n); scriptExists(decoded) {
			t.Errorf("PUT %s stored a script named %q", path, decoded)
		}
	})
}
