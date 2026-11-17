package db

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/emersion/go-message/mail"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/helpers"
)

func TestBuildEnvelopeQuotedAtLocalPart(t *testing.T) {
	t.Run("parsed RFC 5322 quoted local-parts across address headers and Sender fallback", func(t *testing.T) {
		hdr := mail.HeaderFromMap(map[string][]string{
			"From":     {`Alice <"a@b"@example.com>`},
			"To":       {`Bob <"t@1@2"@example.org>`},
			"Cc":       {`Carol <"c@d"@example.net>`},
			"Bcc":      {`<"hidden@x"@example.com>`},
			"Reply-To": {`<"reply@here"@example.com>`},
		})
		recipients := helpers.ExtractRecipients(hdr.Header)
		raw, err := json.Marshal(recipients)
		if err != nil {
			t.Fatalf("marshal recipients: %v", err)
		}

		env, err := BuildEnvelope(&Message{
			UID:            1,
			MailboxID:      10,
			RecipientsJSON: raw,
		})
		if err != nil {
			t.Fatalf("BuildEnvelope: %v", err)
		}

		wantFrom := []imap.Address{{Name: "Alice", Mailbox: "a@b", Host: "example.com"}}
		if !slices.Equal(env.From, wantFrom) {
			t.Errorf("From = %+v, want %+v", env.From, wantFrom)
		}
		if !slices.Equal(env.Sender, wantFrom) {
			t.Errorf("Sender (fallback from From) = %+v, want %+v", env.Sender, wantFrom)
		}
		wantTo := []imap.Address{{Name: "Bob", Mailbox: "t@1@2", Host: "example.org"}}
		if !slices.Equal(env.To, wantTo) {
			t.Errorf("To = %+v, want %+v", env.To, wantTo)
		}
		wantCc := []imap.Address{{Name: "Carol", Mailbox: "c@d", Host: "example.net"}}
		if !slices.Equal(env.Cc, wantCc) {
			t.Errorf("Cc = %+v, want %+v", env.Cc, wantCc)
		}
		wantBcc := []imap.Address{{Mailbox: "hidden@x", Host: "example.com"}}
		if !slices.Equal(env.Bcc, wantBcc) {
			t.Errorf("Bcc = %+v, want %+v", env.Bcc, wantBcc)
		}
		wantReplyTo := []imap.Address{{Mailbox: "reply@here", Host: "example.com"}}
		if !slices.Equal(env.ReplyTo, wantReplyTo) {
			t.Errorf("ReplyTo = %+v, want %+v", env.ReplyTo, wantReplyTo)
		}
	})

	t.Run("explicit Sender with quoted at-sign local-part", func(t *testing.T) {
		hdr := mail.HeaderFromMap(map[string][]string{
			"From":   {`Alice <"a@b"@example.com>`},
			"Sender": {`Bot <"srv@node"@example.org>`},
		})
		raw, err := json.Marshal(helpers.ExtractRecipients(hdr.Header))
		if err != nil {
			t.Fatalf("marshal recipients: %v", err)
		}

		env, err := BuildEnvelope(&Message{UID: 2, MailboxID: 10, RecipientsJSON: raw})
		if err != nil {
			t.Fatalf("BuildEnvelope: %v", err)
		}

		wantSender := []imap.Address{{Name: "Bot", Mailbox: "srv@node", Host: "example.org"}}
		if !slices.Equal(env.Sender, wantSender) {
			t.Errorf("Sender = %+v, want %+v", env.Sender, wantSender)
		}
	})

	t.Run("malformed stored addresses remain rejected", func(t *testing.T) {
		recipients := []helpers.Recipient{
			{AddressType: "to", EmailAddress: ""},
			{AddressType: "to", EmailAddress: "noat"},
			{AddressType: "to", EmailAddress: "@host"},
			{AddressType: "to", EmailAddress: "user@"},
			{AddressType: "to", EmailAddress: "@"},
			{AddressType: "to", EmailAddress: "a@b@"},
			{AddressType: "to", Name: "Valid", EmailAddress: "ok@example.com"},
		}
		raw, err := json.Marshal(recipients)
		if err != nil {
			t.Fatalf("marshal recipients: %v", err)
		}

		env, err := BuildEnvelope(&Message{UID: 3, MailboxID: 10, RecipientsJSON: raw})
		if err != nil {
			t.Fatalf("BuildEnvelope: %v", err)
		}

		wantTo := []imap.Address{{Name: "Valid", Mailbox: "ok", Host: "example.com"}}
		if !slices.Equal(env.To, wantTo) {
			t.Errorf("To = %+v, want only %+v", env.To, wantTo)
		}
	})
}

func TestSortOrderClauseQuotedAtLocalPart(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	runSort := func(t *testing.T, key imap.SortKey, addrs []string) []int64 {
		t.Helper()
		orderBy := db.buildSortOrderClause([]imap.SortCriterion{{Key: key}})
		query := `
			WITH m(uid, from_email_sort, to_email_sort, cc_email_sort) AS (
				SELECT ord::bigint, val, val, val
				FROM unnest($1::text[]) WITH ORDINALITY AS u(val, ord)
			)
			SELECT m.uid FROM m ` + orderBy
		rows, err := db.GetReadPool().Query(ctx, query, addrs)
		if err != nil {
			t.Fatalf("query for %s failed: %v\nSQL: %s", key, err, query)
		}
		defer rows.Close()

		var got []int64
		for rows.Next() {
			var uid int64
			if err := rows.Scan(&uid); err != nil {
				t.Fatalf("scan uid: %v", err)
			}
			got = append(got, uid)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("rows err: %v", err)
		}
		return got
	}

	for _, key := range []imap.SortKey{imap.SortKeyFrom, imap.SortKeyTo, imap.SortKeyCc} {
		t.Run(string(key)+"_ascii_quoted_at", func(t *testing.T) {
			// 1: addr-mailbox "a@z", 2: addr-mailbox "a@a" (domain zzz), 3: addr-mailbox "a@a" (domain aaa).
			// RFC 5256 §3 sorts by addr-mailbox only, with ascending UID tie-break: [2, 3, 1].
			got := runSort(t, key, []string{
				"a@z@example.com",
				"a@a@zzz.example",
				"a@a@aaa.example",
			})
			want := []int64{2, 3, 1}
			if !slices.Equal(got, want) {
				t.Errorf("SORT (%s) = %v, want %v", key, got, want)
			}
		})

		t.Run(string(key)+"_unicode_quoted_at_and_empty", func(t *testing.T) {
			got := runSort(t, key, []string{
				"émile@z@münchen.example",
				"",
				"émile@a@zürich.example",
			})
			want := []int64{2, 3, 1}
			if !slices.Equal(got, want) {
				t.Errorf("SORT (%s) unicode/empty = %v, want %v", key, got, want)
			}
		})
	}
}
