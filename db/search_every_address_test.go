package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 9051 §6.4.4: FROM, TO and CC match "the specified string in the envelope structure's
// FROM [TO, CC] field", which lists every address of that header, and "a message matches
// the key if the string is a substring of the associated text". The *_sort columns hold the
// first address only (they are the RFC 5256 SORT keys), so every other address must be
// searchable as well, through the insert paths and through COPY and MOVE.

// everyAddressRecipients is a message with two From, two To and two Cc addresses, in the
// order helpers.ExtractRecipients produces (To, Cc, Bcc, From).
var everyAddressRecipients = []helpers.Recipient{
	{AddressType: "to", EmailAddress: "carol@example.com"},
	{AddressType: "to", Name: "Bob Example", EmailAddress: "bob@example.com"},
	{AddressType: "cc", Name: "Dave Copy", EmailAddress: "dave@example.org"},
	{AddressType: "cc", EmailAddress: "erin@example.org"},
	{AddressType: "bcc", EmailAddress: "hidden@example.net"},
	{AddressType: "from", Name: "Alice", EmailAddress: "alice@example.com"},
	{AddressType: "from", Name: "Frank Author", EmailAddress: "frank@example.com"},
}

func TestHeaderSearchMatchesEveryAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, inboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	archiveID := createTestMailbox(t, db, accountID, "Archive")

	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 100}
	base := time.Now().UnixNano()
	opts := func(n int, recipients []helpers.Recipient) *InsertMessageOptions {
		hash := fmt.Sprintf("everyaddr-%d-%d", base, n)
		return &InsertMessageOptions{
			AccountID: accountID, MailboxID: inboxID, MailboxName: "INBOX",
			S3Domain: "example.com", S3Localpart: "everyaddr", ContentHash: hash,
			MessageID: fmt.Sprintf("<%s@example.com>", hash), InternalDate: time.Now(), SentDate: time.Now(),
			Size: 100, Subject: fmt.Sprintf("message %d", n), BodyStructure: &bs, Recipients: recipients,
		}
	}

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	// The three insert paths: delivery/APPEND, the importer, and the batch insert.
	_, uidInsert, err := db.InsertMessage(ctx, tx, opts(1, everyAddressRecipients), PendingUpload{InstanceID: "test", ContentHash: opts(1, nil).ContentHash, Size: 100, AccountID: accountID})
	require.NoError(t, err)
	_, uidImport, err := db.InsertMessageFromImporter(ctx, tx, opts(2, everyAddressRecipients))
	require.NoError(t, err)
	_, batchUIDs, _, err := db.InsertMessagesBatch(ctx, tx, []*InsertMessageOptions{opts(3, everyAddressRecipients)}, nil)
	require.NoError(t, err)
	require.Len(t, batchUIDs, 1)
	// A control message: the same people in other headers.
	_, uidControl, err := db.InsertMessage(ctx, tx, opts(4, []helpers.Recipient{
		{AddressType: "to", EmailAddress: "frank@example.com"},
		{AddressType: "cc", EmailAddress: "carol@example.com"},
		{AddressType: "from", Name: "Bob Example", EmailAddress: "bob@example.com"},
	}), PendingUpload{InstanceID: "test", ContentHash: opts(4, nil).ContentHash, Size: 100, AccountID: accountID})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	every := []imap.UID{imap.UID(uidInsert), imap.UID(uidImport), imap.UID(batchUIDs[0])}
	control := []imap.UID{imap.UID(uidControl)}

	search := func(t *testing.T, mailboxID int64, c *imap.SearchCriteria) []imap.UID {
		t.Helper()
		res, err := db.SearchMessagesWithCriteria(ctx, mailboxID, accountID, c, 0, 100)
		require.NoError(t, err)
		uids := []imap.UID{}
		for _, r := range res {
			uids = append(uids, r.UID)
		}
		return uids
	}
	header := func(key, value string) *imap.SearchCriteria {
		return &imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: key, Value: value}}}
	}

	cases := []struct {
		name     string
		criteria *imap.SearchCriteria
		want     []imap.UID
	}{
		{"TO second address", header("To", "bob@example.com"), every},
		{"TO second name", header("To", "BOB EXAMPLE"), every},
		{"FROM second address", header("From", "frank@"), every},
		{"FROM second name", header("From", "frank author"), every},
		{"CC first name", header("Cc", "dave copy"), every},
		{"CC second address", header("Cc", "erin@example.org"), every},
		{"TEXT second Cc address", &imap.SearchCriteria{Text: []string{"erin@example.org"}}, every},
		{"TEXT second From name", &imap.SearchCriteria{Text: []string{"Frank Author"}}, every},
		{"first addresses still match", header("To", "carol@"), every},
		// Each key matches its own header only.
		{"FROM does not see To", header("From", "carol"), []imap.UID{}},
		{"TO does not see Cc", header("To", "erin"), []imap.UID{}},
		{"CC does not see From", header("Cc", "frank"), []imap.UID{}},
		{"FROM bob is the control only", header("From", "bob@"), control},
		{"TO frank is the control only", header("To", "frank"), control},
		{"CC carol is the control only", header("Cc", "carol"), control},
		{"BCC is not TO", header("To", "hidden"), []imap.UID{}},
		{"NOT TO", &imap.SearchCriteria{Not: []imap.SearchCriteria{*header("To", "bob")}}, control},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ElementsMatch(t, tc.want, search(t, inboxID, tc.criteria))
		})
	}

	t.Run("COPY and MOVE keep every address", func(t *testing.T) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		copyUIDs := []imap.UID{imap.UID(uidInsert)}
		copied, _, err := db.CopyMessages(ctx, tx, &copyUIDs, inboxID, archiveID, accountID, "example.com", "everyaddr", "test")
		require.NoError(t, err)
		moveUIDs := []imap.UID{imap.UID(uidImport)}
		moved, err := db.MoveMessages(ctx, tx, &moveUIDs, inboxID, archiveID, accountID, "example.com", "everyaddr", "test")
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		want := []imap.UID{copied[imap.UID(uidInsert)], moved[imap.UID(uidImport)]}
		assert.ElementsMatch(t, want, search(t, archiveID, header("To", "bob@example.com")))
		assert.ElementsMatch(t, want, search(t, archiveID, header("Cc", "erin")))
	})
}

// TestHeaderSearchOnRowsWithoutExtraAddresses covers rows written before extra_addresses
// existed (or by a binary that does not write it): NULL there must behave as "no further
// addresses". The first-address columns keep matching, and a negated key must still return
// the row, which a bare NULL in the predicate would drop.
func TestHeaderSearchOnRowsWithoutExtraAddresses(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	bs := imap.BodyStructure(&imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 100})
	bsBytes, err := helpers.SerializeBodyStructureGob(&bs)
	require.NoError(t, err)
	// A legacy row: no extra_addresses in the column list, as every row before the migration.
	_, err = db.GetWritePool().Exec(ctx, `
		WITH inserted AS (
			INSERT INTO messages
			(account_id, mailbox_id, mailbox_path, uid, message_id, in_reply_to, content_hash, s3_domain, s3_localpart,
			 internal_date, size, subject, sent_date, body_structure, recipients_json, created_modseq,
			 subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort)
			VALUES ($1, $2, 'INBOX', 1, '<legacy@example.com>', '', 'legacyhash', 'd', 'lp', now(), 100, 'legacy', now(), $3,
			        '[{"type":"to","email":"carol@example.com"},{"type":"to","email":"bob@example.com"},{"type":"from","email":"alice@example.com"}]'::jsonb,
			        nextval('messages_modseq'), 'legacy', '', 'alice@example.com', '', 'carol@example.com', '')
			RETURNING id, mailbox_id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags)
		SELECT id, mailbox_id, 0, '[]'::jsonb FROM inserted`, accountID, mailboxID, bsBytes)
	require.NoError(t, err)

	search := func(c *imap.SearchCriteria) []imap.UID {
		res, err := db.SearchMessagesWithCriteria(ctx, mailboxID, accountID, c, 0, 10)
		require.NoError(t, err)
		uids := []imap.UID{}
		for _, r := range res {
			uids = append(uids, r.UID)
		}
		return uids
	}
	header := func(key, value string) imap.SearchCriteria {
		return imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: key, Value: value}}}
	}

	assert.Equal(t, []imap.UID{1}, search(&imap.SearchCriteria{Header: header("To", "carol").Header}))
	for _, key := range []string{"From", "To", "Cc"} {
		assert.Equal(t, []imap.UID{1}, search(&imap.SearchCriteria{Not: []imap.SearchCriteria{header(key, "nobody")}}), "NOT %s on a row without extra_addresses", key)
	}
	assert.Equal(t, []imap.UID{1}, search(&imap.SearchCriteria{Not: []imap.SearchCriteria{{Text: []string{"nobody"}}}}), "NOT TEXT on a row without extra_addresses")
}
