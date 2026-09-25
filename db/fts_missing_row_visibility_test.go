package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A message with NO full-text row at all must stay fully visible to search and threading.
//
// This is the behavioural half of TestFTSAccountScopeNeverInWhereClause. Scoping the FTS
// join by account is what makes body search cheap, but the scope has to sit in the JOIN ON
// clause: these are LEFT JOINs, and several are unconditional (THREAD joins the FTS table
// for every THREAD including THREAD ALL; the User API search ORs the FTS predicate with
// header LIKE predicates). Put the scope in WHERE and "mc.account_id = @accountID" is NULL
// for a message with no FTS row, which quietly turns the LEFT JOIN into an inner join.
//
// Messages without an FTS row are ordinary, not exotic. Bodies over 64KB are never staged,
// empty bodies are skipped, and PruneOldMessageVectors deletes rows once fts_retention
// expires. The failure mode is silent: the query succeeds and simply returns fewer rows.
func TestMessagesWithoutFTSRowStayVisible(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	ts := time.Now().UnixNano()

	indexedHash := fmt.Sprintf("fts_present_%d", ts)
	bareHash := fmt.Sprintf("fts_absent_%d", ts)

	// Only the first message gets an FTS row. The second stands in for every message whose
	// body was too large to stage, was empty, or whose vector has been pruned.
	_, err := db.GetWritePool().Exec(ctx, `
		INSERT INTO messages_fts_v2 (content_hash, account_id, text_body_tsv, sent_date)
		VALUES ($1, $2, to_tsvector('simple', 'needle'), now())
	`, indexedHash, accountID)
	require.NoError(t, err)

	insert := func(uid int, hash, subject string) {
		t.Helper()
		_, err := db.GetWritePool().Exec(ctx, `
			WITH inserted AS (
				INSERT INTO messages (account_id, mailbox_id, uid, content_hash, subject, subject_sort,
				                      sent_date, internal_date, size, uploaded, s3_domain, s3_localpart,
				                      message_id, body_structure, recipients_json, created_modseq)
				VALUES ($1, $2, $3, $4, $5, LOWER($5), now(), now(), 100, TRUE, 'domain', 'part', $6,
				        'body', '[]', nextval('messages_modseq'))
				RETURNING id, mailbox_id
			)
			INSERT INTO message_state (message_id, mailbox_id, flags)
			SELECT id, mailbox_id, 0 FROM inserted
		`, accountID, mailboxID, uid, hash, subject, fmt.Sprintf("<%s@example.com>", hash))
		require.NoError(t, err)
	}
	insert(9101, indexedHash, "Indexed haystack")
	insert(9102, bareHash, "Bare haystack")

	uids := func(msgs []SearchMessageResult) map[imap.UID]bool {
		out := map[imap.UID]bool{}
		for _, m := range msgs {
			out[m.UID] = true
		}
		return out
	}

	t.Run("THREAD ALL returns messages with no FTS row", func(t *testing.T) {
		// THREAD joins the FTS table unconditionally, so this is the query most exposed to
		// a WHERE-side account scope.
		msgs, err := db.GetMessagesForThreading(ctx, mailboxID, accountID, &imap.SearchCriteria{}, true)
		require.NoError(t, err)
		found := map[imap.UID]bool{}
		for _, m := range msgs {
			found[m.UID] = true
		}
		assert.True(t, found[9101], "the indexed message must be threaded")
		assert.True(t, found[9102],
			"SILENT LOSS: a message with no messages_fts_v2 row vanished from THREAD ALL, which "+
				"is what happens when the account scope is moved from the JOIN ON clause into WHERE")
	})

	t.Run("TEXT matching a header returns messages with no FTS row", func(t *testing.T) {
		// TEXT is (body OR headers). "Bare" matches only the subject of the message that has
		// no FTS row, so it can only be found through the header side of the disjunction.
		msgs, err := db.SearchMessagesWithCriteria(ctx, mailboxID, accountID,
			&imap.SearchCriteria{Text: []string{"Bare"}}, 0, 0)
		require.NoError(t, err)
		assert.True(t, uids(msgs)[9102],
			"a subject-only TEXT match must be returned even though the message has no FTS row")
	})

	t.Run("negated body search returns messages with no FTS row", func(t *testing.T) {
		// NOT BODY "needle" is TRUE for a message with no FTS row: it does not contain the
		// term. These true negatives are exactly what a WHERE-side account scope discards.
		msgs, err := db.SearchMessagesWithCriteria(ctx, mailboxID, accountID,
			&imap.SearchCriteria{Not: []imap.SearchCriteria{{Body: []string{"needle"}}}}, 0, 0)
		require.NoError(t, err)
		got := uids(msgs)
		assert.True(t, got[9102], "the message with no FTS row does not contain the term, so NOT BODY must match it")
		assert.False(t, got[9101], "the message that does contain the term must not match NOT BODY")
	})

	t.Run("body search still finds the indexed message and only it", func(t *testing.T) {
		msgs, err := db.SearchMessagesWithCriteria(ctx, mailboxID, accountID,
			&imap.SearchCriteria{Body: []string{"needle"}}, 0, 0)
		require.NoError(t, err)
		got := uids(msgs)
		assert.True(t, got[9101], "the indexed message must be found by body search")
		assert.False(t, got[9102], "a message with no FTS row must not match a body term")
	})
}

// The same body search must be scoped to the mailbox OWNER. Two accounts sharing one body
// each get their own messages_fts_v2 row, and neither may see the other's.
func TestBodySearchIsScopedToAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	ts := time.Now().UnixNano()
	sharedHash := fmt.Sprintf("fts_shared_%d", ts)
	otherAccountID := accountID + 1_000_000 // an account id that owns no messages here

	// The body is indexed for a DIFFERENT account only. Our account holds the message but
	// has no vector of its own, which is precisely the state the per-account table creates
	// before its worker fans the vector out.
	_, err := db.GetWritePool().Exec(ctx, `
		INSERT INTO messages_fts_v2 (content_hash, account_id, text_body_tsv, sent_date)
		VALUES ($1, $2, to_tsvector('simple', 'sharedneedle'), now())
	`, sharedHash, otherAccountID)
	require.NoError(t, err)

	_, err = db.GetWritePool().Exec(ctx, `
		WITH inserted AS (
			INSERT INTO messages (account_id, mailbox_id, uid, content_hash, subject, sent_date,
			                      internal_date, size, uploaded, s3_domain, s3_localpart,
			                      message_id, body_structure, recipients_json, created_modseq)
			VALUES ($1, $2, 9201, $3, 'Shared body', now(), now(), 100, TRUE, 'domain', 'part',
			        $4, 'body', '[]', nextval('messages_modseq'))
			RETURNING id, mailbox_id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags)
		SELECT id, mailbox_id, 0 FROM inserted
	`, accountID, mailboxID, sharedHash, fmt.Sprintf("<%s@example.com>", sharedHash))
	require.NoError(t, err)

	msgs, err := db.SearchMessagesWithCriteria(ctx, mailboxID, accountID,
		&imap.SearchCriteria{Body: []string{"sharedneedle"}}, 0, 0)
	require.NoError(t, err)
	for _, m := range msgs {
		assert.NotEqual(t, imap.UID(9201), m.UID,
			"a vector belonging to another account must not make this account's message searchable; "+
				"the FTS join is scoped by account precisely so one account's index cannot answer another's search")
	}

	// And once this account has its own row, the same search finds it.
	_, err = db.GetWritePool().Exec(ctx, `
		INSERT INTO messages_fts_v2 (content_hash, account_id, text_body_tsv, sent_date)
		VALUES ($1, $2, to_tsvector('simple', 'sharedneedle'), now())
	`, sharedHash, accountID)
	require.NoError(t, err)

	msgs, err = db.SearchMessagesWithCriteria(ctx, mailboxID, accountID,
		&imap.SearchCriteria{Body: []string{"sharedneedle"}}, 0, 0)
	require.NoError(t, err)
	var found bool
	for _, m := range msgs {
		if m.UID == 9201 {
			found = true
		}
	}
	assert.True(t, found, "with its own per-account row the message must be searchable")
}
