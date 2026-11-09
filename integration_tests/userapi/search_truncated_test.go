//go:build integration

package userapi

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
)

// userAPISearchCap is the documented cap on GET /user/mailboxes/{name}/search
// (docs/user-api.md, Search). Written out rather than imported so the test also pins
// the number the documentation promises.
const userAPISearchCap = 100

// TestUserAPI_SearchReportsTruncation: a search with more matches than the cap must
// say so. It once answered the first 100 with "total": 100 and nothing else, so a
// client could not tell a complete result from a clipped one (#166).
func TestUserAPI_SearchReportsTruncation(t *testing.T) {
	h := newBodyStateHarness(t)

	// Seeded through the subject: the search statement matches LOWER(m.subject) in the
	// same query, so no FTS worker run stands between the inserts and the search.
	seed := func(word string, n int) {
		t.Helper()
		ctx := context.Background()
		base := time.Now().UnixNano()
		for i := 0; i < n; i++ {
			now := time.Now()
			hash := fmt.Sprintf("%016x%048x", base, i)
			subject := fmt.Sprintf("Re: %s batch %d", word, i)
			_, _, err := h.rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
				AccountID: h.accountID, MailboxID: h.inbox.ID, MailboxName: "INBOX",
				S3Domain: "example.com", S3Localpart: "user", ContentHash: hash,
				MessageID: fmt.Sprintf("<%s@example.com>", hash[:24]), Flags: []imap.Flag{},
				InternalDate: now, Size: 64, Subject: subject, SentDate: now,
			}, db.PendingUpload{AccountID: h.accountID, ContentHash: hash, InstanceID: "this-node", Size: 64, CreatedAt: now, UpdatedAt: now})
			if err != nil {
				t.Fatalf("insert message %d of %d for %q: %v", i+1, n, word, err)
			}
		}
	}

	search := func(word string) map[string]any {
		t.Helper()
		resp := h.tc.makeRequest(t, "GET", "/user/mailboxes/INBOX/search?q="+word, nil)
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("search %q: status %d", word, resp.StatusCode)
		}
		var result map[string]any
		parseJSON(t, resp, &result)
		return result
	}

	t.Run("OverCap", func(t *testing.T) {
		const word = "zyqwortal"
		seed(word, userAPISearchCap+1)

		result := search(word)
		messages, _ := result["messages"].([]any)
		truncated, present := result["truncated"]
		if !present {
			t.Fatalf("%d matches: answered %d messages with total %v and no \"truncated\" field, a clipped result presented as complete",
				userAPISearchCap+1, len(messages), result["total"])
		}
		if truncated != true {
			t.Errorf("truncated = %v, want true for %d matches over a cap of %d", truncated, userAPISearchCap+1, userAPISearchCap)
		}
		if len(messages) != userAPISearchCap {
			t.Errorf("len(messages) = %d, want the cap %d", len(messages), userAPISearchCap)
		}
		if result["total"] != float64(userAPISearchCap) {
			t.Errorf("total = %v, want %d (the number of messages returned)", result["total"], userAPISearchCap)
		}
		if result["limit"] != float64(userAPISearchCap) {
			t.Errorf("limit = %v, want %d", result["limit"], userAPISearchCap)
		}
	})

	t.Run("UnderCap", func(t *testing.T) {
		const word = "quvexilon"
		seed(word, 3)

		result := search(word)
		messages, _ := result["messages"].([]any)
		truncated, present := result["truncated"]
		if !present {
			t.Fatalf("3 matches: response has no \"truncated\" field")
		}
		if truncated != false {
			t.Errorf("truncated = %v, want false for 3 matches", truncated)
		}
		if len(messages) != 3 {
			t.Errorf("len(messages) = %d, want 3", len(messages))
		}
		if result["total"] != float64(3) {
			t.Errorf("total = %v, want 3", result["total"])
		}
	})
}
