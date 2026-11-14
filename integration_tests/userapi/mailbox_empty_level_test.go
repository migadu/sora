//go:build integration

package userapi

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestCreateMailbox_EmptyHierarchyLevel is issue #566. Creating "Parent/Child"
// creates the missing parents, so a name with an empty level ("x//y", "/lead") made
// a parent "x/" or "" on the way. Such a name is refused with 400, as "." and ".."
// levels are, and creates nothing; a trailing delimiter is still no part of the name.
func TestCreateMailbox_EmptyHierarchyLevel(t *testing.T) {
	tc := setupTestServer(t)
	tc.JWTToken = tc.loginFor(t, tc.TestUser.Email, tc.TestUser.Password)
	ctx := context.Background()
	accountID := tc.accountID(t)

	for _, name := range []string{"x//y", "/lead", "a/b//c/"} {
		resp := tc.makeRequest(t, "POST", "/user/mailboxes", map[string]string{"name": name})
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("create mailbox %q: status %d, want 400", name, resp.StatusCode)
		}
	}
	resp := tc.makeRequest(t, "POST", "/user/mailboxes", map[string]string{"name": "Foo/"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf(`create mailbox "Foo/": status %d, want 201`, resp.StatusCode)
	}

	mailboxes, err := tc.RDB.GetMailboxesWithRetry(ctx, accountID, false)
	if err != nil {
		t.Fatalf("GetMailboxesWithRetry: %v", err)
	}
	names := make(map[string]bool, len(mailboxes))
	for _, mb := range mailboxes {
		names[mb.Name] = true
		if mb.Name == "" || strings.HasPrefix(mb.Name, "/") || strings.HasSuffix(mb.Name, "/") || strings.Contains(mb.Name, "//") {
			t.Errorf("mailbox with an empty hierarchy level was created: %q", mb.Name)
		}
	}
	for _, parent := range []string{"x", "a", "a/b"} {
		if names[parent] {
			t.Errorf("refused name created the parent %q", parent)
		}
	}
	if !names["Foo"] {
		t.Errorf(`"Foo/" did not create "Foo"`)
	}
}
