package db

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// msgIDPlanNode is the subset of an EXPLAIN (ANALYZE, FORMAT JSON) node the Message-ID plan
// test reads.
type msgIDPlanNode struct {
	NodeType     string          `json:"Node Type"`
	RelationName string          `json:"Relation Name"`
	IndexName    string          `json:"Index Name"`
	IndexCond    string          `json:"Index Cond"`
	Plans        []msgIDPlanNode `json:"Plans"`
}

// TestMessageIDSearchPlan runs SEARCH HEADER Message-ID through the real search path and
// replays the statement it issued under EXPLAIN (ANALYZE). RFC 9051 §6.4.4 makes the term a
// substring of the field, but the usual term is a whole ID in angle brackets, sent by
// clients looking for one message: that must stay an equality lookup on
// idx_messages_message_id, as it was before substring matching (a whole mailbox read for it
// would be a heap scan, measured at 38 s on a 534k-message mailbox, see substringCond). Any
// other term cannot use an index on the ID; it must still read this mailbox's rows only.
//
// Sequential scans are disabled for the EXPLAIN: this test's mailbox is most of the test
// table, so a seq scan is legitimately cheapest here, while in production a mailbox is a
// tiny fraction of messages.
func TestMessageIDSearchPlan(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	bs := imap.BodyStructure(&imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 100})
	bsBytes, err := helpers.SerializeBodyStructureGob(&bs)
	require.NoError(t, err)

	const rows = 20000
	_, err = db.GetWritePool().Exec(ctx, `
		INSERT INTO messages
		(account_id, mailbox_id, mailbox_path, uid, message_id, in_reply_to, content_hash, s3_domain, s3_localpart,
		 internal_date, size, subject, sent_date, body_structure, recipients_json, created_modseq,
		 subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort)
		SELECT $1, $2, 'INBOX', g, 'MsgID-' || g || '@Example.com', '', 'midhash-' || g, 'd', 'lp-' || g,
		       now() - (g || ' seconds')::interval, 100, 'Note ' || g, now() - (g || ' seconds')::interval, $3, '[]'::jsonb, nextval('messages_modseq'),
		       'NOTE ' || g, 'sender', 'sender@example.com', 'me', 'me@example.com', NULL
		FROM generate_series(1, $4::int) g`, accountID, mailboxID, bsBytes, rows)
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, "VACUUM ANALYZE messages")
	require.NoError(t, err)

	tracer := &queryCapturingTracer{}
	tracedPool := newCapturingPool(t, ctx, db.GetReadPool(), tracer)
	defer tracedPool.Close()
	traced := &Database{WritePool: db.GetWritePool(), ReadPool: tracedPool}

	explain := func(t *testing.T, term string, wantUIDs []imap.UID) msgIDPlanNode {
		t.Helper()
		before := len(tracer.captured())
		criteria := &imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Message-ID", Value: term}}}
		results, err := traced.SearchMessagesWithCriteria(ctx, mailboxID, accountID, criteria, 0, rows)
		require.NoError(t, err)
		var got []imap.UID
		for _, r := range results {
			got = append(got, r.UID)
		}
		assert.ElementsMatch(t, wantUIDs, got, "HEADER Message-ID %q", term)

		var stmt *capturedQuery
		for i, q := range tracer.captured()[before:] {
			if strings.Contains(q.SQL, "FROM messages m") && strings.Contains(q.SQL, "message_id") {
				stmt = &tracer.captured()[before+i]
			}
		}
		require.NotNil(t, stmt, "harness broken: the search statement was not captured")

		conn, err := db.GetReadPool().Acquire(ctx)
		require.NoError(t, err)
		defer conn.Release()
		_, err = conn.Exec(ctx, "SET enable_seqscan = off")
		require.NoError(t, err)
		defer conn.Exec(ctx, "RESET enable_seqscan")
		var raw []byte
		err = conn.QueryRow(ctx, "EXPLAIN (ANALYZE, FORMAT JSON) "+stmt.SQL, stmt.Args...).Scan(&raw)
		require.NoError(t, err, "failed to EXPLAIN the captured statement:\n%s", stmt.SQL)
		var explained []struct {
			Plan msgIDPlanNode `json:"Plan"`
		}
		require.NoError(t, json.Unmarshal(raw, &explained))
		require.Len(t, explained, 1)
		t.Logf("plan for %q:\n%s", term, string(raw))
		return explained[0].Plan
	}

	// messagesIndexes maps each index the plan reads messages through to its Index Cond,
	// and fails on a sequential scan of messages. A Bitmap Index Scan names no relation; it
	// belongs to the Bitmap Heap Scan above it (through any BitmapAnd/BitmapOr).
	messagesIndexes := func(t *testing.T, plan msgIDPlanNode) map[string]string {
		t.Helper()
		used := map[string]string{}
		var visit func(n msgIDPlanNode, underMessagesBitmap bool)
		visit = func(n msgIDPlanNode, underMessagesBitmap bool) {
			if n.RelationName == "messages" && n.NodeType == "Seq Scan" {
				t.Errorf("messages is read by a sequential scan")
			}
			if n.IndexName != "" && (n.RelationName == "messages" || (underMessagesBitmap && n.RelationName == "")) {
				used[n.IndexName] = n.IndexCond
			}
			childUnder := (n.NodeType == "Bitmap Heap Scan" && n.RelationName == "messages") ||
				(underMessagesBitmap && (n.NodeType == "BitmapAnd" || n.NodeType == "BitmapOr"))
			for _, c := range n.Plans {
				visit(c, childUnder)
			}
		}
		visit(plan, false)
		return used
	}

	t.Run("whole ID in brackets is an index lookup", func(t *testing.T) {
		plan := explain(t, "<MSGID-4242@example.COM>", []imap.UID{4242})
		used := messagesIndexes(t, plan)
		assert.Contains(t, used, "idx_messages_message_id", "a whole bracketed ID must be looked up through idx_messages_message_id")
	})

	t.Run("part of the ID reads only this mailbox", func(t *testing.T) {
		plan := explain(t, "4242@", []imap.UID{4242, 14242})
		used := messagesIndexes(t, plan)
		require.NotEmpty(t, used, "messages must be read through an index")
		for name, cond := range used {
			assert.Contains(t, cond, "mailbox_id", "index %s must be scoped to the mailbox", name)
		}
	})
}

// TestMessageIDSearchSQL pins the two shapes of a HEADER Message-ID criterion. A whole ID in
// angle brackets can only be a substring of the one-ID field if it is that ID, so it is an
// equality on LOWER(message_id), which idx_messages_message_id serves. Every other term,
// including one without the brackets, is a substring of the field rebuilt with its brackets.
func TestMessageIDSearchSQL(t *testing.T) {
	var db *Database // the builder never dereferences its receiver
	const field = `CASE WHEN left(m.message_id, 1) <> '<' THEN '<' || LOWER(m.message_id) || '>' END`

	for _, tc := range []struct {
		term      string
		equality  bool
		wantBound string
	}{
		{"<Support@Equishark.com>", true, "support@equishark.com"},
		{"Support@Equishark.com", false, "support@equishark.com"},
		{"equishark", false, "equishark"},
		{"<support@", false, "<support@"},
		{"@equishark.com>", false, "@equishark.com>"},
		{"", false, ""},
		{"<>", false, "<>"},
		{"<a> <b>", false, "<a> <b>"},
		{"<a@[x>", false, "<a@[x>"}, // the '>' could be inside a domain literal
	} {
		t.Run(tc.term, func(t *testing.T) {
			criteria := &imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Message-ID", Value: tc.term}}}
			paramCounter := 0
			query, args, err := db.buildSearchCriteria(criteria, "p", &paramCounter)
			require.NoError(t, err)
			require.Len(t, args, 1)
			for _, v := range args {
				assert.Equal(t, tc.wantBound, v)
			}
			if tc.equality {
				assert.Equal(t, "LOWER(m.message_id) = @p1", query)
			} else {
				assert.Equal(t, "COALESCE(strpos("+field+", @p1) > 0, FALSE)", query)
			}
		})
	}
}
