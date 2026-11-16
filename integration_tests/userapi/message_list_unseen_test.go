//go:build integration

package userapi

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
)

// TestUserAPI_ListUnseenIncludesMissingState: a message without a message_state row
// has no flags. The list returns it with flags [] and search's unseen filter keeps it
// (#880), but the list's unseen=true filter and its total tested (ms.flags & \Seen) = 0,
// which is NULL for that message, so they dropped it (#984).
func TestUserAPI_ListUnseenIncludesMissingState(t *testing.T) {
	h := newBodyStateHarness(t)
	ctx := context.Background()

	base := time.Now().UnixNano()
	seed := func(i int, subject string, flags ...imap.Flag) {
		t.Helper()
		now := time.Now().Add(time.Duration(i) * time.Second)
		hash := fmt.Sprintf("%016x%048x", base, i)
		_, _, err := h.rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID: h.accountID, MailboxID: h.inbox.ID, MailboxName: "INBOX",
			S3Domain: "example.com", S3Localpart: "user", ContentHash: hash,
			MessageID: fmt.Sprintf("<%s@example.com>", hash[:24]), Flags: append([]imap.Flag{}, flags...),
			InternalDate: now, Size: 64, Subject: subject, SentDate: now,
		}, db.PendingUpload{AccountID: h.accountID, ContentHash: hash, InstanceID: "this-node", Size: 64, CreatedAt: now, UpdatedAt: now})
		if err != nil {
			t.Fatalf("insert %q: %v", subject, err)
		}
	}

	seed(1, "seen", imap.FlagSeen)
	seed(2, "seen and flagged", imap.FlagSeen, imap.FlagFlagged)
	seed(3, "unseen")
	seed(4, "unseen and flagged", imap.FlagFlagged)
	seed(5, "missing state")
	h.exec(t, `DELETE FROM message_state
		WHERE message_id IN (SELECT id FROM messages WHERE mailbox_id = $1 AND subject = 'missing state')`, h.inbox.ID)

	type listed struct {
		subjects []string
		flags    map[string][]string
		total    int
	}
	list := func(query string) listed {
		t.Helper()
		resp := h.tc.makeRequest(t, "GET", "/user/mailboxes/INBOX/messages"+query, nil)
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("list %q: status %d", query, resp.StatusCode)
		}
		var result struct {
			Messages []struct {
				Subject string   `json:"subject"`
				Flags   []string `json:"flags"`
			} `json:"messages"`
			Total int `json:"total"`
		}
		parseJSON(t, resp, &result)
		got := listed{flags: map[string][]string{}, total: result.Total}
		for _, m := range result.Messages {
			got.subjects = append(got.subjects, m.Subject)
			got.flags[m.Subject] = m.Flags
		}
		slices.Sort(got.subjects)
		return got
	}

	all := list("")
	wantAll := []string{"missing state", "seen", "seen and flagged", "unseen", "unseen and flagged"}
	if !slices.Equal(all.subjects, wantAll) || all.total != len(wantAll) {
		t.Fatalf("list = %q (total %d), want %q (total %d)", all.subjects, all.total, wantAll, len(wantAll))
	}
	if f := all.flags["missing state"]; len(f) != 0 {
		t.Fatalf("missing-state message has flags %q, want none", f)
	}

	wantUnseen := []string{"missing state", "unseen", "unseen and flagged"}
	unseen := list("?unseen=true")
	if !slices.Equal(unseen.subjects, wantUnseen) {
		t.Errorf("unseen list = %q, want %q", unseen.subjects, wantUnseen)
	}
	if unseen.total != len(wantUnseen) {
		t.Errorf("unseen total = %d, want %d", unseen.total, len(wantUnseen))
	}

	// The total is the unseen count, not the page size.
	page := list("?unseen=true&limit=1")
	if len(page.subjects) != 1 || page.total != len(wantUnseen) {
		t.Errorf("unseen page = %q (total %d), want 1 message (total %d)", page.subjects, page.total, len(wantUnseen))
	}
}
