//go:build integration

package userapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
)

// Subscribing to or unsubscribing from a mailbox that does not exist is a client
// error: 404, as for the other mailbox endpoints, not 500.
func TestMailboxSubscriptions_UnknownMailbox(t *testing.T) {
	tc := setupTestServer(t)
	tc.JWTToken = tc.loginFor(t, tc.TestUser.Email, tc.TestUser.Password)
	name := fmt.Sprintf("NoSuchFolder-%d", time.Now().UnixNano())
	for _, op := range []string{"subscribe", "unsubscribe"} {
		resp := tc.makeRequest(t, "POST", "/user/mailboxes/"+name+"/"+op, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST .../%s of an unknown mailbox: status %d, want 404", op, resp.StatusCode)
		}
	}
}

// A new script past the per-account limit is refused with a 4xx that names the limit,
// as ManageSieve answers NO (QUOTA/MAXSCRIPTS); an existing script can still be updated.
func TestPutFilter_ScriptLimit(t *testing.T) {
	tc := setupTestServer(t)
	tc.JWTToken = tc.loginFor(t, tc.TestUser.Email, tc.TestUser.Password)
	ctx := context.Background()
	accountID := tc.accountID(t)
	limit := db.MaxScriptsPerAccount()
	for i := 0; i < limit; i++ {
		if _, err := tc.RDB.CreateScriptWithRetry(ctx, accountID, fmt.Sprintf("s%03d", i), "keep;"); err != nil {
			t.Fatalf("create script %d: %v", i, err)
		}
	}

	resp := tc.makeRequest(t, "PUT", "/user/filters/one-too-many", map[string]string{"script": "keep;"})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("PUT a new script at the limit: status %d (%s), want 409", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), strconv.Itoa(limit)) {
		t.Errorf("PUT a new script at the limit: body %s does not name the limit %d", body, limit)
	}

	resp = tc.makeRequest(t, "PUT", "/user/filters/s000", map[string]string{"script": "discard;"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("PUT an existing script at the limit: status %d, want 200", resp.StatusCode)
	}
}

// A script name PostgreSQL cannot hold (a NUL, invalid UTF-8) names no script: GET,
// DELETE and activate answer 404 as for any unknown script. The name was sent to the
// database, which refused it with SQLSTATE 22021, and the client got 500.
func TestFilterRoutes_UnstorableName(t *testing.T) {
	tc := setupTestServer(t)
	tc.JWTToken = tc.loginFor(t, tc.TestUser.Email, tc.TestUser.Password)
	for _, name := range []string{"%00", "a%00b", "%FF", "caf%C3"} {
		for _, req := range []struct{ method, path string }{
			{"GET", "/user/filters/" + name},
			{"DELETE", "/user/filters/" + name},
			{"POST", "/user/filters/" + name + "/activate"},
		} {
			resp := tc.makeRequest(t, req.method, req.path, nil)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s %s: status %d (%s), want 404", req.method, req.path, resp.StatusCode, body)
			}
		}
	}
}

// A script whose content decodes to a NUL byte (e.g. JSON \u0000 in a comment or string)
// violates RFC 5228 and cannot be stored in PostgreSQL text: PUT /user/filters/{name}
// must refuse it with 400 Bad Request rather than hitting SQLSTATE 22021 and answering 500.
func TestPutFilter_UnstorableScript(t *testing.T) {
	tc := setupTestServer(t)
	tc.JWTToken = tc.loginFor(t, tc.TestUser.Email, tc.TestUser.Password)

	resp := tc.makeRequest(t, "PUT", "/user/filters/existing", map[string]string{"script": "keep;\n"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("seed PUT /user/filters/existing: status %d, want 200", resp.StatusCode)
	}

	for _, script := range []string{
		"# \x00\nkeep;\n",
		"/* \x00 */\nkeep;\n",
		"require \"fileinto\";\nfileinto \"INBOX\x00\";\n",
		"require \"vacation\";\nvacation text:\naway \x00\n.\n;\n",
	} {
		for _, target := range []string{"vacation", "existing"} {
			resp := tc.makeRequest(t, "PUT", "/user/filters/"+target, map[string]string{"script": script})
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("PUT /user/filters/%s (%q): status %d (%s), want 400", target, script, resp.StatusCode, body)
			}
		}
	}
}
