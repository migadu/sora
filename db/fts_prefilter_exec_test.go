package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/migadu/sora/pkg/metrics"
)

// The large-mailbox prefilter (WITH fts_hits AS MATERIALIZED ...) is only selected when the
// caller reports a mailbox at or above ftsCTEThreshold. No integration caller does, so
// without this test the SQL that path emits is never executed against PostgreSQL at all --
// the unit tests only inspect the generated string. This runs the executor through it, with
// and without a SORT, and checks both the results and that the path was really taken.
func TestFTSPrefilterPathExecutes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	ts := time.Now().UnixNano()

	insert := func(uid int, hash, subject, body string) {
		t.Helper()
		_, err := db.GetWritePool().Exec(ctx, `
			WITH inserted AS (
				INSERT INTO messages (account_id, mailbox_id, uid, content_hash, subject, subject_sort,
				                      from_email_sort, from_name_sort, to_email_sort, to_name_sort, cc_email_sort,
				                      sent_date, internal_date, size, uploaded, s3_domain, s3_localpart,
				                      message_id, in_reply_to, body_structure, recipients_json, created_modseq)
				VALUES ($1, $2, $3::bigint, $4, $5, LOWER($5), 'a@x', 'a', 'b@x', 'b', '',
				        now() - ($3::bigint::text || ' seconds')::interval, now(), 100, TRUE, 'domain', 'part',
				        $6, '', 'body', '[]', nextval('messages_modseq'))
				RETURNING id, mailbox_id
			)
			INSERT INTO message_state (message_id, mailbox_id, flags)
			SELECT id, mailbox_id, 0 FROM inserted
		`, accountID, mailboxID, uid, hash, subject, fmt.Sprintf("<%s@example.com>", hash))
		require.NoError(t, err)
		if body != "" {
			_, err = db.GetWritePool().Exec(ctx, `
				INSERT INTO messages_fts_v2 (content_hash, account_id, text_body_tsv, sent_date)
				VALUES ($1, $2, to_tsvector('simple', $3), now())
			`, hash, accountID, body)
			require.NoError(t, err)
		}
	}
	h := func(i int) string { return fmt.Sprintf("prefilter_%d_%d", ts, i) }
	insert(9401, h(1), "first", "prefilterneedle alpha")
	insert(9402, h(2), "second", "beta gamma")
	insert(9403, h(3), "third", "prefilterneedle delta")
	insert(9404, h(4), "fourth", "") // no FTS row at all

	pathCount := func() float64 {
		return testutil.ToFloat64(metrics.DBQueriesTotal.WithLabelValues("search_messages_complex_prefilter", "success", "read"))
	}
	body := &imap.SearchCriteria{Body: []string{"prefilterneedle"}}
	bySize := []imap.SortCriterion{{Key: imap.SortKeySize}}
	bySubject := []imap.SortCriterion{{Key: imap.SortKeySubject}}

	t.Run("lightweight executor", func(t *testing.T) {
		before := pathCount()
		res, err := db.SearchMessagesWithCriteria(ctx, mailboxID, accountID, body, 0, ftsCTEThreshold)
		require.NoError(t, err)
		require.Equal(t, before+1, pathCount(), "the prefilter path must actually be taken at the threshold")
		uids := map[imap.UID]bool{}
		for _, m := range res {
			uids[m.UID] = true
		}
		assert.Equal(t, map[imap.UID]bool{9401: true, 9403: true}, uids)
	})

	t.Run("lightweight executor sorted", func(t *testing.T) {
		before := pathCount()
		res, err := db.SearchMessagesSorted(ctx, mailboxID, accountID, body, bySubject, 0, ftsCTEThreshold)
		require.NoError(t, err)
		require.Equal(t, before+1, pathCount())
		require.Len(t, res, 2)
		assert.Equal(t, imap.UID(9401), res[0].UID, "SORT (SUBJECT): 'first' before 'third'")
	})

	t.Run("lightweight executor sorted by size", func(t *testing.T) {
		before := pathCount()
		res, err := db.SearchMessagesSorted(ctx, mailboxID, accountID, body, bySize, 0, ftsCTEThreshold)
		require.NoError(t, err)
		require.Equal(t, before+1, pathCount())
		assert.Len(t, res, 2)
	})

	t.Run("combined with a non-FTS criterion", func(t *testing.T) {
		before := pathCount()
		combined := &imap.SearchCriteria{Body: []string{"prefilterneedle"}, Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "third"}}}
		res, err := db.SearchMessagesWithCriteria(ctx, mailboxID, accountID, combined, 0, ftsCTEThreshold)
		require.NoError(t, err)
		require.Equal(t, before+1, pathCount())
		require.Len(t, res, 1)
		assert.Equal(t, imap.UID(9403), res[0].UID)
	})

	t.Run("below the threshold the probe path is used", func(t *testing.T) {
		before := pathCount()
		res, err := db.SearchMessagesWithCriteria(ctx, mailboxID, accountID, body, 0, ftsCTEThreshold-1)
		require.NoError(t, err)
		assert.Equal(t, before, pathCount(), "below the threshold the prefilter must not be selected")
		assert.Len(t, res, 2)
	})
}

// Every search shape a client sends -- body terms inside OR and NOT, several terms, TEXT next
// to BODY -- must return exactly the same messages through the large-mailbox match-set form
// as through the per-message probe, and must really take that form at the threshold.
//
// The fixture includes a message with no FTS row at all (subject-only match) and one whose
// body matches nothing searched for, so NOT keeps its true negatives and TEXT keeps its
// header-only matches: the two ways a wrong join type loses rows silently.
func TestFTSPrefilterMatchesProbeForEveryShape(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	ts := time.Now().UnixNano()

	insert := func(uid int, subject, body string) {
		t.Helper()
		hash := fmt.Sprintf("shapes_%d_%d", ts, uid)
		_, err := db.GetWritePool().Exec(ctx, `
			WITH inserted AS (
				INSERT INTO messages (account_id, mailbox_id, uid, content_hash, subject, subject_sort,
				                      from_email_sort, from_name_sort, to_email_sort, to_name_sort, cc_email_sort,
				                      sent_date, internal_date, size, uploaded, s3_domain, s3_localpart,
				                      message_id, in_reply_to, body_structure, recipients_json, created_modseq)
				VALUES ($1, $2, $3::bigint, $4, $5, LOWER($5), 'a@x', 'a', 'b@x', 'b', '',
				        now(), now(), 100, TRUE, 'domain', 'part',
				        $6, '', 'body', '[]', nextval('messages_modseq'))
				RETURNING id, mailbox_id
			)
			INSERT INTO message_state (message_id, mailbox_id, flags)
			SELECT id, mailbox_id, 0 FROM inserted
		`, accountID, mailboxID, uid, hash, subject, fmt.Sprintf("<%s@example.com>", hash))
		require.NoError(t, err)
		if body != "" {
			_, err = db.GetWritePool().Exec(ctx, `
				INSERT INTO messages_fts_v2 (content_hash, account_id, text_body_tsv, sent_date)
				VALUES ($1, $2, to_tsvector('simple', $3), now())
			`, hash, accountID, body)
			require.NoError(t, err)
		}
	}
	insert(1, "alpha report", "needle one")
	insert(2, "beta", "needle two")
	insert(3, "gamma", "other words")
	insert(4, "needle in subject", "") // no FTS row at all
	insert(5, "delta", "two only")

	subject := func(v string) imap.SearchCriteria {
		return imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: v}}}
	}
	body := func(v string) imap.SearchCriteria { return imap.SearchCriteria{Body: []string{v}} }

	shapes := []struct {
		name     string
		criteria func() *imap.SearchCriteria
		want     []imap.UID
	}{
		{"OR SUBJECT x BODY y (webmail subject/body search)", func() *imap.SearchCriteria {
			return &imap.SearchCriteria{Or: [][2]imap.SearchCriteria{{subject("gamma"), body("needle")}}}
		}, []imap.UID{1, 2, 3}},
		{"NOT BODY keeps messages with no FTS row", func() *imap.SearchCriteria {
			return &imap.SearchCriteria{Not: []imap.SearchCriteria{body("needle")}}
		}, []imap.UID{3, 4, 5}},
		{"two BODY terms intersect", func() *imap.SearchCriteria {
			return &imap.SearchCriteria{Body: []string{"needle", "two"}}
		}, []imap.UID{2}},
		{"two TEXT terms, one matching only a subject", func() *imap.SearchCriteria {
			return &imap.SearchCriteria{Text: []string{"needle", "two"}}
		}, []imap.UID{2}},
		{"OR BODY x NOT BODY y", func() *imap.SearchCriteria {
			return &imap.SearchCriteria{Or: [][2]imap.SearchCriteria{{
				body("other"), {Not: []imap.SearchCriteria{body("needle")}},
			}}}
		}, []imap.UID{3, 4, 5}},
		{"required BODY with a nested OR BODY", func() *imap.SearchCriteria {
			return &imap.SearchCriteria{
				Body: []string{"needle"},
				Or:   [][2]imap.SearchCriteria{{subject("alpha"), body("two")}},
			}
		}, []imap.UID{1, 2}},
		{"TEXT next to BODY", func() *imap.SearchCriteria {
			return &imap.SearchCriteria{Text: []string{"needle"}, Body: []string{"two"}}
		}, []imap.UID{2}},
		{"NOT (OR BODY x SUBJECT y)", func() *imap.SearchCriteria {
			return &imap.SearchCriteria{Not: []imap.SearchCriteria{{
				Or: [][2]imap.SearchCriteria{{body("needle"), subject("gamma")}},
			}}}
		}, []imap.UID{4, 5}},
	}

	pathCount := func() float64 {
		return testutil.ToFloat64(metrics.DBQueriesTotal.WithLabelValues("search_messages_complex_prefilter", "success", "read"))
	}
	sorted := func(uids []imap.UID) []imap.UID {
		out := append([]imap.UID(nil), uids...)
		for i := 1; i < len(out); i++ {
			for j := i; j > 0 && out[j] < out[j-1]; j-- {
				out[j], out[j-1] = out[j-1], out[j]
			}
		}
		return out
	}

	for _, shape := range shapes {
		for _, size := range []struct {
			name      string
			count     int
			prefilter bool
		}{{"probe", 0, false}, {"match sets", ftsCTEThreshold, true}} {
			t.Run(shape.name+"/"+size.name, func(t *testing.T) {
				before := pathCount()

				res, err := db.SearchMessagesWithCriteria(ctx, mailboxID, accountID, shape.criteria(), 0, size.count)
				require.NoError(t, err)
				var got []imap.UID
				for _, m := range res {
					got = append(got, m.UID)
				}
				assert.Equal(t, shape.want, sorted(got))

				taken := pathCount() - before
				if size.prefilter {
					assert.Equal(t, 1.0, taken, "at the threshold the match-set form must be taken")
				} else {
					assert.Equal(t, 0.0, taken, "below the threshold the per-message probe must be kept")
				}
			})
		}
	}
}
