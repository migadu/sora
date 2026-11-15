//go:build integration

package userapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
)

// TestUserAPI_EmptyListsAreArrays: the User API documents flags, to and messages as
// arrays. A new unread message without a To header, an empty mailbox and a search
// without matches must send them as [], not null, which a client that reads them as
// arrays (msg.flags.includes(...), messages.length) fails on (#688).
func TestUserAPI_EmptyListsAreArrays(t *testing.T) {
	h := newBodyStateHarness(t)
	ctx := context.Background()

	get := func(t *testing.T, path string) map[string]json.RawMessage {
		t.Helper()
		resp := h.tc.makeRequest(t, "GET", path, nil)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %d: %s", path, resp.StatusCode, body)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			t.Fatalf("GET %s: %v (body: %s)", path, err, body)
		}
		return fields
	}
	wantEmptyArray := func(t *testing.T, where string, fields map[string]json.RawMessage, key string) {
		t.Helper()
		if got := string(fields[key]); got != "[]" {
			t.Errorf("%s: %q = %s, want []", where, key, got)
		}
	}

	t.Run("EmptyMailbox", func(t *testing.T) {
		if err := h.rdb.CreateMailboxWithRetry(ctx, h.accountID, "Empty", nil); err != nil {
			t.Fatal(err)
		}
		wantEmptyArray(t, "list of an empty mailbox", get(t, "/user/mailboxes/Empty/messages"), "messages")
	})

	t.Run("SearchWithoutMatches", func(t *testing.T) {
		wantEmptyArray(t, "search without matches", get(t, "/user/mailboxes/INBOX/search?q=qzvnomatchword"), "messages")
	})

	t.Run("UnflaggedMessageWithoutTo", func(t *testing.T) {
		// Seeded through the subject, which the search matches in the same query, so no
		// FTS worker run stands between the insert and the search.
		const word = "kwyvrandomsubject"
		now := time.Now()
		hash := fmt.Sprintf("%064x", now.UnixNano())
		id, _, err := h.rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID: h.accountID, MailboxID: h.inbox.ID, MailboxName: "INBOX",
			S3Domain: "example.com", S3Localpart: "user", ContentHash: hash,
			MessageID: fmt.Sprintf("<%s@example.com>", hash[:16]), Flags: []imap.Flag{},
			InternalDate: now, Size: 64, Subject: "Re: " + word, SentDate: now,
			Recipients: []helpers.Recipient{{AddressType: "from", EmailAddress: "sender@example.com"}},
		}, db.PendingUpload{AccountID: h.accountID, ContentHash: hash, InstanceID: "this-node", Size: 64, CreatedAt: now, UpdatedAt: now})
		if err != nil {
			t.Fatal(err)
		}

		find := func(t *testing.T, where string, fields map[string]json.RawMessage) map[string]json.RawMessage {
			t.Helper()
			var messages []map[string]json.RawMessage
			if err := json.Unmarshal(fields["messages"], &messages); err != nil {
				t.Fatalf("%s: messages: %v", where, err)
			}
			for _, m := range messages {
				if string(m["id"]) == fmt.Sprint(id) {
					return m
				}
			}
			t.Fatalf("%s: message %d not in %s", where, id, fields["messages"])
			return nil
		}

		for where, msg := range map[string]map[string]json.RawMessage{
			"list":   find(t, "list", get(t, "/user/mailboxes/INBOX/messages")),
			"search": find(t, "search", get(t, "/user/mailboxes/INBOX/search?q="+word)),
			"get":    get(t, fmt.Sprintf("/user/messages/%d", id)),
		} {
			wantEmptyArray(t, where, msg, "flags")
			wantEmptyArray(t, where, msg, "to")
		}
	})
}
