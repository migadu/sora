package db

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/emersion/go-message/mail"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The route of a source-routed address is the ENVELOPE's addr-adl (RFC 9051 §7.5.2,
// #2119); a row stored before the route was kept has none and reports NIL.
func TestBuildEnvelopeObsoleteSourceRoutes(t *testing.T) {
	env, err := BuildEnvelope(&Message{RecipientsJSON: []byte(`[{"email":"user@domain","type":"from"}]`)})
	if err != nil {
		t.Fatal(err)
	}
	if want := []imap.Address{{Mailbox: "user", Host: "domain"}}; !slices.Equal(env.From, want) {
		t.Errorf("row without a route: From = %+v, want %+v", env.From, want)
	}

	for _, explicit := range []bool{false, true} {
		name := "from only"
		h := mail.HeaderFromMap(map[string][]string{"From": {"<@route:user@domain>"}})
		if explicit {
			name = "explicit sender and reply-to"
			h.Set("Sender", "Sender <@first,@second:sender@domain>")
			h.Set("Reply-To", "Replies <@route:replies@domain>")
		}
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(helpers.ExtractRecipients(h.Header))
			if err != nil {
				t.Fatal(err)
			}
			env, err := BuildEnvelope(&Message{RecipientsJSON: raw})
			if err != nil {
				t.Fatal(err)
			}
			wantFrom := []imap.Address{{Mailbox: "user", Host: "domain", Route: "@route"}}
			if !slices.Equal(env.From, wantFrom) {
				t.Errorf("From = %+v, want %+v", env.From, wantFrom)
			}
			wantSender := wantFrom
			if explicit {
				wantSender = []imap.Address{{Name: "Sender", Mailbox: "sender", Host: "domain", Route: "@first,@second"}}
				wantReplyTo := []imap.Address{{Name: "Replies", Mailbox: "replies", Host: "domain", Route: "@route"}}
				if !slices.Equal(env.ReplyTo, wantReplyTo) {
					t.Errorf("ReplyTo = %+v, want %+v", env.ReplyTo, wantReplyTo)
				}
			}
			if !slices.Equal(env.Sender, wantSender) {
				t.Errorf("Sender = %+v, want %+v", env.Sender, wantSender)
			}
		})
	}
}

// TestInsertPathsKeepSourceRoute: delivery/APPEND, the importer and the batch insert all
// store the route in recipients_json, and nothing else changes with it: the sort and
// search columns of a routed message equal those of the same message without routes.
func TestInsertPathsKeepSourceRoute(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	routed := mail.HeaderFromMap(map[string][]string{
		"From": {"Sender <@first,@second:sender@example.com>"},
		"To":   {"<@route:to@example.com>, other@example.com"},
		"Cc":   {"team: <@route:member@example.com>;"},
	})
	plain := mail.HeaderFromMap(map[string][]string{
		"From": {"Sender <sender@example.com>"},
		"To":   {"<to@example.com>, other@example.com"},
		"Cc":   {"team: <member@example.com>;"},
	})
	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 100}
	base := time.Now().UnixNano()
	opts := func(n int, h mail.Header) *InsertMessageOptions {
		hash := fmt.Sprintf("route-%d-%d", base, n)
		return &InsertMessageOptions{
			AccountID: accountID, MailboxID: mailboxID, MailboxName: "INBOX",
			S3Domain: "example.com", S3Localpart: "route", ContentHash: hash,
			MessageID: fmt.Sprintf("<%s@example.com>", hash), InternalDate: time.Now(), SentDate: time.Now(),
			Size: 100, Subject: "route", BodyStructure: &bs, Recipients: helpers.ExtractRecipients(h.Header),
		}
	}

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	ids := map[string]int64{}
	ids["InsertMessage"], _, err = db.InsertMessage(ctx, tx, opts(1, routed), PendingUpload{InstanceID: "test", ContentHash: opts(1, routed).ContentHash, Size: 100, AccountID: accountID})
	require.NoError(t, err)
	ids["InsertMessageFromImporter"], _, err = db.InsertMessageFromImporter(ctx, tx, opts(2, routed))
	require.NoError(t, err)
	batchIDs, _, _, err := db.InsertMessagesBatch(ctx, tx, []*InsertMessageOptions{opts(3, routed)}, nil)
	require.NoError(t, err)
	require.Len(t, batchIDs, 1)
	ids["InsertMessagesBatch"] = batchIDs[0]
	plainID, _, err := db.InsertMessageFromImporter(ctx, tx, opts(4, plain))
	require.NoError(t, err)

	const columns = `concat_ws('|', from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort, extra_addresses)`
	var plainColumns string
	require.NoError(t, tx.QueryRow(ctx, `SELECT `+columns+` FROM messages WHERE id = $1`, plainID).Scan(&plainColumns))
	for path, id := range ids {
		var raw []byte
		var got string
		require.NoError(t, tx.QueryRow(ctx, `SELECT recipients_json, `+columns+` FROM messages WHERE id = $1`, id).Scan(&raw, &got), path)
		assert.Equal(t, plainColumns, got, "%s: the route must not reach the sort and search columns", path)
		env, err := BuildEnvelope(&Message{RecipientsJSON: raw})
		require.NoError(t, err, path)
		assert.Equal(t, []imap.Address{{Name: "Sender", Mailbox: "sender", Host: "example.com", Route: "@first,@second"}}, env.From, path)
		assert.Equal(t, []imap.Address{{Mailbox: "to", Host: "example.com", Route: "@route"}, {Mailbox: "other", Host: "example.com"}}, env.To, path)
		assert.Equal(t, []imap.Address{{Mailbox: "team"}, {Mailbox: "member", Host: "example.com", Route: "@route"}, {}}, env.Cc, path)
	}
}
