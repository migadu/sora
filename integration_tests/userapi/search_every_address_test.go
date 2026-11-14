//go:build integration

package userapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
)

// TestUserAPI_SearchMatchesEveryAddress: GET /user/mailboxes/{name}/search matched q
// against the first From, To and Cc address only, and never against a Cc display name
// (#414), so a search for the second recipient of a message found nothing. The header
// condition is the one IMAP SEARCH TEXT uses (headerSubstringCond), which now also reads
// messages.extra_addresses (#281); this pins the User API side of it.
func TestUserAPI_SearchMatchesEveryAddress(t *testing.T) {
	h := newBodyStateHarness(t)
	ctx := context.Background()

	now := time.Now()
	hash := fmt.Sprintf("%064x", now.UnixNano())
	// No PlaintextBody: nothing is staged for FTS, so only the header condition can match.
	_, _, err := h.rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
		AccountID: h.accountID, MailboxID: h.inbox.ID, MailboxName: "INBOX",
		S3Domain: "example.com", S3Localpart: "user", ContentHash: hash,
		MessageID: fmt.Sprintf("<%s@example.com>", hash[:24]), Flags: []imap.Flag{},
		InternalDate: now, Size: 64, Subject: "quarterly figures", SentDate: now,
		Recipients: []helpers.Recipient{
			{AddressType: "from", Name: "Alice Example", EmailAddress: "alice@example.com"},
			{AddressType: "to", EmailAddress: "carol@example.com"},
			{AddressType: "to", Name: "Bobby Tables", EmailAddress: "bob@example.com"},
			{AddressType: "cc", Name: "Dave Cee", EmailAddress: "dave@example.com"},
			{AddressType: "cc", EmailAddress: "erin@example.org"},
		},
	}, db.PendingUpload{AccountID: h.accountID, ContentHash: hash, InstanceID: "this-node", Size: 64, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}

	for _, q := range []string{
		// Already matched through the first-address sort columns.
		"quarterly", "Alice Example", "alice@example.com", "carol@example.com", "dave@example.com",
		// Matched only through extra_addresses: a later To, its name, the first Cc's
		// name (there is no cc_name_sort) and a later Cc.
		"bob@example.com", "Bobby Tables", "Dave Cee", "erin@example.org",
	} {
		resp := h.tc.makeRequest(t, "GET", "/user/mailboxes/INBOX/search?q="+url.QueryEscape(q), nil)
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("search q=%q: status %d", q, resp.StatusCode)
		}
		var result struct {
			Total int `json:"total"`
		}
		parseJSON(t, resp, &result)
		if result.Total != 1 {
			t.Errorf("search q=%q: total = %d, want 1", q, result.Total)
		}
	}

	// A term no header holds still matches nothing.
	resp := h.tc.makeRequest(t, "GET", "/user/mailboxes/INBOX/search?q="+url.QueryEscape("zoe@example.com"), nil)
	var result struct {
		Total int `json:"total"`
	}
	parseJSON(t, resp, &result)
	if result.Total != 0 {
		t.Errorf("search q=%q: total = %d, want 0", "zoe@example.com", result.Total)
	}
}
