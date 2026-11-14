//go:build integration

package userapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
)

// TestUserAPI_SearchAppliesFilters: GET /user/mailboxes/{name}/search documents from,
// subject and unseen (docs/USER_API.md, user_api_openapi.yaml), each ANDed with q. The
// server once read only q, so a filtered search answered the unfiltered result (#543).
func TestUserAPI_SearchAppliesFilters(t *testing.T) {
	h := newBodyStateHarness(t)
	ctx := context.Background()

	// q matches the subject, which the search statement tests in the same query, so no
	// FTS worker run stands between the inserts and the searches.
	const word = "zorbulant"
	base := time.Now().UnixNano()
	// Every message gets user@example.com as its last To address, after addrs.
	seed := func(i int, subject string, seen bool, addrs ...helpers.Recipient) {
		t.Helper()
		now := time.Now()
		hash := fmt.Sprintf("%016x%048x", base, i)
		flags := []imap.Flag{}
		if seen {
			flags = append(flags, imap.FlagSeen)
		}
		recipients := append(addrs, helpers.Recipient{AddressType: "to", EmailAddress: "user@example.com"})
		_, _, err := h.rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID: h.accountID, MailboxID: h.inbox.ID, MailboxName: "INBOX",
			S3Domain: "example.com", S3Localpart: "user", ContentHash: hash,
			MessageID: fmt.Sprintf("<%s@example.com>", hash[:24]), Flags: flags,
			InternalDate: now, Size: 64, Subject: subject, SentDate: now, Recipients: recipients,
		}, db.PendingUpload{AccountID: h.accountID, ContentHash: hash, InstanceID: "this-node", Size: 64, CreatedAt: now, UpdatedAt: now})
		if err != nil {
			t.Fatalf("insert %q: %v", subject, err)
		}
	}
	from := func(name, email string) helpers.Recipient {
		return helpers.Recipient{AddressType: "from", Name: name, EmailAddress: email}
	}

	seed(1, word+" quarterly report", true, from("The Boss", "boss@example.com"))
	// user@example.com is the second To address here, so it is in extra_addresses' To
	// section, which the from filter must not read (FromIsNotTo).
	seed(2, word+" lunch", false, from("", "other@example.com"),
		helpers.Recipient{AddressType: "to", EmailAddress: "colleague@example.org"})
	seed(3, word+" Quarterly numbers", false, from("Assistant", "assistant@example.org"))
	// boss@example.com is the second From address: it is in extra_addresses, not the sort columns.
	seed(4, word+" joint memo", false, from("", "first@example.org"), from("", "boss@example.com"))
	// Matches every filter below but not q: filters narrow q, they never widen it.
	seed(5, "quarterly plan", false, from("The Boss", "boss@example.com"))

	search := func(params url.Values) []string {
		t.Helper()
		params.Set("q", word)
		resp := h.tc.makeRequest(t, "GET", "/user/mailboxes/INBOX/search?"+params.Encode(), nil)
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("search %s: status %d", params.Encode(), resp.StatusCode)
		}
		var result struct {
			Messages []struct {
				Subject string `json:"subject"`
			} `json:"messages"`
			Total int `json:"total"`
		}
		parseJSON(t, resp, &result)
		if result.Total != len(result.Messages) {
			t.Errorf("search %s: total %d for %d messages", params.Encode(), result.Total, len(result.Messages))
		}
		var subjects []string
		for _, m := range result.Messages {
			subjects = append(subjects, m.Subject)
		}
		slices.Sort(subjects)
		return subjects
	}

	tests := []struct {
		name   string
		params url.Values
		want   []string
	}{
		{"NoFilter", url.Values{}, []string{word + " Quarterly numbers", word + " joint memo", word + " lunch", word + " quarterly report"}},
		{"EmptyFiltersApplyNothing", url.Values{"from": {""}, "subject": {""}, "unseen": {"false"}},
			[]string{word + " Quarterly numbers", word + " joint memo", word + " lunch", word + " quarterly report"}},
		{"Unseen", url.Values{"unseen": {"true"}}, []string{word + " Quarterly numbers", word + " joint memo", word + " lunch"}},
		{"FromAddress", url.Values{"from": {"boss@example.com"}}, []string{word + " joint memo", word + " quarterly report"}},
		{"FromOtherAddress", url.Values{"from": {"other@example.com"}}, []string{word + " lunch"}},
		{"FromNameCaseInsensitive", url.Values{"from": {"ASSISTANT"}}, []string{word + " Quarterly numbers"}},
		{"FromIsNotTo", url.Values{"from": {"user@example.com"}}, nil},
		{"SubjectCaseInsensitive", url.Values{"subject": {"QUARTERLY"}}, []string{word + " Quarterly numbers", word + " quarterly report"}},
		{"SubjectIsLiteral", url.Values{"subject": {"quarterly%"}}, nil},
		{"SubjectAndUnseen", url.Values{"subject": {"quarterly"}, "unseen": {"true"}}, []string{word + " Quarterly numbers"}},
		{"FromAndUnseen", url.Values{"from": {"boss@"}, "unseen": {"true"}}, []string{word + " joint memo"}},
		{"FromAndSubject", url.Values{"from": {"other@example.com"}, "subject": {"quarterly"}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := search(tt.params); !slices.Equal(got, tt.want) {
				t.Errorf("search %s:\n got  %q\n want %q", tt.params.Encode(), got, tt.want)
			}
		})
	}

	t.Run("MissingStateIsUnseen", func(t *testing.T) {
		const suffix = " missing-state message"
		seed(6, word+suffix, false, from("", "other@example.com"))
		if _, err := h.rdb.ExecWithRetry(ctx, `DELETE FROM message_state
			WHERE message_id IN (SELECT id FROM messages WHERE mailbox_id=$1 AND subject=$2)`, h.inbox.ID, word+suffix); err != nil {
			t.Fatal(err)
		}
		// Search already returns absent state with flags=0, so the unseen filter
		// must include that same message as well as messages with an explicit row.
		want := []string{word + suffix}
		if got := search(url.Values{"subject": {suffix}}); !slices.Equal(got, want) {
			t.Fatalf("unfiltered missing-state message = %q, want %q", got, want)
		}
		if got := search(url.Values{"subject": {suffix}, "unseen": {"true"}}); !slices.Equal(got, want) {
			t.Errorf("unseen missing-state message = %q, want %q", got, want)
		}
	})
}

// TestUserAPI_SearchRejectsMalformedFilters: from and subject are bound as PostgreSQL
// text, which refuses a NUL and bytes that are not UTF-8 (SQLSTATE 22021). Such a filter
// is the client's malformed input, so it is a 400 and never reaches the database; it
// once answered 500 for a NUL, and searched for U+FFFD for invalid UTF-8.
func TestUserAPI_SearchRejectsMalformedFilters(t *testing.T) {
	h := newBodyStateHarness(t)
	for _, tt := range []struct {
		query string
		want  int
	}{
		{"q=x&from=%00", http.StatusBadRequest},
		{"q=x&from=boss%00@example.com", http.StatusBadRequest},
		{"q=x&from=%FF", http.StatusBadRequest},
		{"q=x&subject=%00", http.StatusBadRequest},
		{"q=x&subject=%FF", http.StatusBadRequest},
		{"q=x&subject=%C3%A9t%C3%A9&from=J%C3%BCrgen", http.StatusOK},
	} {
		resp := h.tc.makeRequest(t, "GET", "/user/mailboxes/INBOX/search?"+tt.query, nil)
		resp.Body.Close()
		if resp.StatusCode != tt.want {
			t.Errorf("search %s: status %d, want %d", tt.query, resp.StatusCode, tt.want)
		}
	}
}

// TestUserAPI_SearchRejectsMalformedQuery: q is bound as PostgreSQL text, in the header
// substring tests and in plainto_tsquery, which refuses a NUL and bytes that are not UTF-8
// (SQLSTATE 22021). Such a q is the client's malformed input, as the filters above are, so
// it is a 400 naming q and never reaches the database; it once answered 500 (#859).
func TestUserAPI_SearchRejectsMalformedQuery(t *testing.T) {
	h := newBodyStateHarness(t)
	for _, tt := range []struct {
		query string
		want  int
	}{
		{"q=%00", http.StatusBadRequest},
		{"q=report%00draft", http.StatusBadRequest},
		{"q=%FF", http.StatusBadRequest},
		{"q=caf%C3", http.StatusBadRequest}, // truncated two-byte sequence
		{"q=%C3%A9t%C3%A9", http.StatusOK},
	} {
		resp := h.tc.makeRequest(t, "GET", "/user/mailboxes/INBOX/search?"+tt.query, nil)
		var body struct {
			Error string `json:"error"`
		}
		err := json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode != tt.want {
			t.Errorf("search %s: status %d (%q), want %d", tt.query, resp.StatusCode, body.Error, tt.want)
			continue
		}
		if err != nil {
			t.Errorf("search %s: decode body: %v", tt.query, err)
		}
		if tt.want == http.StatusBadRequest && !strings.Contains(body.Error, "'q'") {
			t.Errorf("search %s: error %q does not name q", tt.query, body.Error)
		}
	}
}
