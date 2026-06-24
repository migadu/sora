package db

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSearchConstants tests the search-related constants
func TestSearchConstants(t *testing.T) {
	assert.Equal(t, 100000, MaxSearchResults)
	assert.Equal(t, 500, MaxComplexSortResults)
	assert.Less(t, MaxComplexSortResults, MaxSearchResults, "Complex sort limit should be less than search limit")
}

// TestSeqNumSearchQueryPathSelection verifies the query-path selection after the
// seqnum→UID rewrite in getMessagesQueryExecutor:
//
//   - A pure sequence-number search (SEARCH <seqset>) is rewritten from sequence
//     numbers to UID ranges and then served by the optimized "simple" path —
//     without the unnecessary messages_fts join used by the complex paths.
//   - A search that also carries an FTS term (BODY) stays on the complex-fast
//     path, because recomputing complexity after the rewrite still sees the FTS
//     criteria.
//
// The assertions key off the per-path Prometheus query counters, which is the
// only externally observable signal of which template was executed.
func TestSeqNumSearchQueryPathSelection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	suite := NewPerformanceTestSuite(t, FastPerformanceConfig)
	defer suite.Close()

	ctx := context.Background()
	require.NoError(t, suite.CreateTestMessages(ctx, 10, "business"))

	// Counter for a given query-path label (success/read).
	pathCount := func(label string) float64 {
		return testutil.ToFloat64(metrics.DBQueriesTotal.WithLabelValues(label, "success", "read"))
	}

	t.Run("PureSeqNumUsesSimplePath", func(t *testing.T) {
		simpleBefore := pathCount("search_messages_simple")
		fastBefore := pathCount("search_messages_complex_fast")
		legacyBefore := pathCount("search_messages_complex_legacy")

		criteria := &imap.SearchCriteria{
			SeqNum: []imap.SeqSet{{imap.SeqRange{Start: 1, Stop: 5}}},
		}
		messages, err := suite.db.GetMessagesWithCriteria(ctx, suite.mailboxID, criteria, 0)
		require.NoError(t, err)
		require.NotEmpty(t, messages, "sequence search 1:5 should return messages")

		assert.Equal(t, 1.0, pathCount("search_messages_simple")-simpleBefore,
			"pure SeqNum search should be rewritten to UIDs and use the simple query path")
		assert.Equal(t, 0.0, pathCount("search_messages_complex_fast")-fastBefore,
			"pure SeqNum search must not use the complex-fast (messages_fts join) path")
		assert.Equal(t, 0.0, pathCount("search_messages_complex_legacy")-legacyBefore,
			"pure SeqNum search must not use the legacy ROW_NUMBER path")
	})

	t.Run("SeqNumWithFTSStaysComplex", func(t *testing.T) {
		simpleBefore := pathCount("search_messages_simple")
		fastBefore := pathCount("search_messages_complex_fast")
		legacyBefore := pathCount("search_messages_complex_legacy")

		// BODY keeps the query complex even after the seqnum→UID rewrite, so the
		// recompute must NOT downgrade it to the simple path. The FTS term may
		// match zero rows in the test environment; only the chosen path matters.
		criteria := &imap.SearchCriteria{
			SeqNum: []imap.SeqSet{{imap.SeqRange{Start: 1, Stop: 5}}},
			Body:   []string{"report"},
		}
		_, err := suite.db.GetMessagesWithCriteria(ctx, suite.mailboxID, criteria, 0)
		require.NoError(t, err)

		assert.Equal(t, 0.0, pathCount("search_messages_simple")-simpleBefore,
			"SeqNum+BODY search must not be downgraded to the simple path")
		assert.Equal(t, 1.0, pathCount("search_messages_complex_fast")-fastBefore,
			"SeqNum+BODY search should use the complex-fast path (FTS, no ROW_NUMBER)")
		assert.Equal(t, 0.0, pathCount("search_messages_complex_legacy")-legacyBefore,
			"SeqNum+BODY search should not need the legacy ROW_NUMBER path")
	})
}

// TestBuildSearchHeaderConditions verifies the SQL emitted for HEADER search
// criteria. buildSearchCriteria only assembles strings and never touches the
// receiver, so a nil *Database is sufficient and no database is required.
func TestBuildSearchHeaderConditions(t *testing.T) {
	var db *Database // builder does not dereference the receiver

	tests := []struct {
		name        string
		header      imap.SearchCriteriaHeaderField
		wantContain string // substring that must appear in the generated SQL
	}{
		{
			name:        "References maps to the references column",
			header:      imap.SearchCriteriaHeaderField{Key: "References", Value: "<parent@example.com>"},
			wantContain: `LOWER(m."references") LIKE`,
		},
		{
			name:        "non-indexed header matches nothing",
			header:      imap.SearchCriteriaHeaderField{Key: "X-Custom", Value: "anything"},
			wantContain: "FALSE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paramCounter := 0
			criteria := &imap.SearchCriteria{
				Header: []imap.SearchCriteriaHeaderField{tt.header},
			}
			condition, _, err := db.buildSearchCriteria(criteria, "p", &paramCounter)
			require.NoError(t, err)
			assert.Contains(t, condition, tt.wantContain)
		})
	}
}

// TestCanUseTextUnion verifies eligibility for the TEXT UNION rewrite. The decision
// is a pure function of the criteria, so a nil *Database suffices.
func TestCanUseTextUnion(t *testing.T) {
	var db *Database // canUseTextUnion does not dereference the receiver

	tests := []struct {
		name          string
		criteria      *imap.SearchCriteria
		needsSeqNum   bool
		orderByClause string
		want          bool
	}{
		{
			name:     "single TEXT term is eligible",
			criteria: &imap.SearchCriteria{Text: []string{"invoice"}},
			want:     true,
		},
		{
			name:     "TEXT plus non-FTS filters is eligible",
			criteria: &imap.SearchCriteria{Text: []string{"invoice"}, Flag: []imap.Flag{imap.FlagSeen}},
			want:     true,
		},
		{
			name:     "no TEXT term is ineligible",
			criteria: &imap.SearchCriteria{Body: []string{"invoice"}},
			want:     false,
		},
		{
			name:     "BODY alongside TEXT is ineligible",
			criteria: &imap.SearchCriteria{Text: []string{"invoice"}, Body: []string{"report"}},
			want:     false,
		},
		{
			name:     "multiple TEXT terms are ineligible",
			criteria: &imap.SearchCriteria{Text: []string{"invoice", "report"}},
			want:     false,
		},
		{
			name: "TEXT nested in OR is ineligible",
			criteria: &imap.SearchCriteria{
				Text: []string{"invoice"},
				Or: [][2]imap.SearchCriteria{{
					{Text: []string{"report"}},
					{Flag: []imap.Flag{imap.FlagFlagged}},
				}},
			},
			want: false,
		},
		{
			name:        "needsSeqNumSearch is ineligible",
			criteria:    &imap.SearchCriteria{Text: []string{"invoice"}},
			needsSeqNum: true,
			want:        false,
		},
		{
			name:          "ORDER BY seqnum is ineligible",
			criteria:      &imap.SearchCriteria{Text: []string{"invoice"}},
			orderByClause: "ORDER BY seqnum DESC",
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := db.canUseTextUnion(tt.criteria, tt.needsSeqNum, tt.orderByClause)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestBuildTextUnionQuerySQL verifies the SQL shape and arguments emitted for the
// TEXT UNION rewrite. buildTextUnionQuery only assembles strings, so a nil *Database
// is sufficient.
func TestBuildTextUnionQuerySQL(t *testing.T) {
	var db *Database

	t.Run("pure TEXT splits into header and body branches", func(t *testing.T) {
		paramCounter := 0
		criteria := &imap.SearchCriteria{Text: []string{"Invoice"}}
		const branchSelect = "m.id, m.uid, m.mailbox_id, m.content_hash, m.created_modseq, ms.updated_modseq, m.expunged_modseq"
		const outerSelect = "f.id, f.uid, f.mailbox_id, f.content_hash, f.created_modseq, f.updated_modseq, f.expunged_modseq, 0 as seqnum"

		query, args, err := db.buildTextUnionQuery(criteria, 42, branchSelect, textUnionSortColumnsLight, outerSelect, "", MaxSearchResults, &paramCounter)
		require.NoError(t, err)

		// Two indexable branches, UNIONed.
		assert.Contains(t, query, "UNION")
		// Body branch: FTS join + tsvector predicate.
		assert.Contains(t, query, "JOIN messages_fts mc ON m.content_hash = mc.content_hash")
		assert.Contains(t, query, "text_body_tsv @@ plainto_tsquery('simple',")
		// Header branch: trigram-indexable LIKE columns.
		assert.Contains(t, query, "LOWER(m.subject) LIKE")
		assert.Contains(t, query, "m.from_email_sort LIKE")
		assert.Contains(t, query, "m.cc_email_sort LIKE")
		// Outer query orders the deduped CTE (bias-busted) and limits.
		assert.Contains(t, query, "FROM matched f")
		assert.Contains(t, query, "ORDER BY f.uid + 0 DESC")
		assert.Contains(t, query, fmt.Sprintf("LIMIT %d", MaxSearchResults))
		// Sort columns carried in the CTE for ORDER BY.
		assert.Contains(t, query, "m.subject_sort")

		// Args: mailbox, tsquery term (original case), and lowercased LIKE pattern.
		assert.Equal(t, int64(42), args["mailboxID"])
		var sawTerm, sawLike bool
		for _, v := range args {
			if v == "Invoice" {
				sawTerm = true
			}
			if v == "%invoice%" {
				sawLike = true
			}
		}
		assert.True(t, sawTerm, "tsquery arg should preserve original term case")
		assert.True(t, sawLike, "LIKE arg should be lowercased and wildcard-wrapped")
	})

	t.Run("non-Text filter is replicated into both branches", func(t *testing.T) {
		paramCounter := 0
		criteria := &imap.SearchCriteria{
			Text: []string{"invoice"},
			Flag: []imap.Flag{imap.FlagSeen},
		}
		const branchSelect = "m.id, m.uid, m.mailbox_id, m.content_hash, m.created_modseq, ms.updated_modseq, m.expunged_modseq"
		const outerSelect = "f.id, f.uid, f.mailbox_id, f.content_hash, f.created_modseq, f.updated_modseq, f.expunged_modseq, 0 as seqnum"

		query, _, err := db.buildTextUnionQuery(criteria, 7, branchSelect, textUnionSortColumnsLight, outerSelect, "", MaxSearchResults, &paramCounter)
		require.NoError(t, err)

		// The \Seen base condition (ms.flags & 1) must appear once per UNION branch.
		seenFlag := FlagToBitwise(imap.FlagSeen)
		needle := fmt.Sprintf("(ms.flags & %d) != 0", seenFlag)
		assert.Equal(t, 2, strings.Count(query, needle),
			"non-Text base filter should be replicated into both UNION branches")
	})
}

// TestTextUnionSearchResults verifies that the TEXT UNION rewrite returns the same
// set as the combined-OR form: a term matching only the body, only a header, or both
// are all returned (the both-match deduped to one row), and non-matches excluded. It
// also asserts the UNION query path is the one actually executed.
func TestTextUnionSearchResults(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	// Unique, lowercase token so both the trigram (subject/header) and tsvector (body)
	// matchers fire on it and it cannot collide with other content.
	const token = "zzuniontokenzz"

	bs := imap.BodyStructure(&imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 100})
	bsBytes, err := helpers.SerializeBodyStructureGob(&bs)
	require.NoError(t, err)

	// insertMsg inserts one message; bodyTSVText (when non-empty) is written directly to
	// messages_fts.text_body_tsv because the async FTS worker does not run in tests.
	insertMsg := func(uid int64, subject, contentHash, bodyTSVText string) {
		_, err := db.GetWritePool().Exec(ctx, `
			WITH inserted AS (
				INSERT INTO messages
				(account_id, mailbox_id, mailbox_path, uid, message_id, content_hash, s3_domain, s3_localpart,
				 internal_date, size, subject, sent_date, body_structure, recipients_json, created_modseq,
				 subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort)
				VALUES ($1,$2,'INBOX',$3,$4,$5,'d',$6, now(), 100, $7, now(), $8, '[]'::jsonb, nextval('messages_modseq'),
				        $9, '', '', '', '', '')
				RETURNING id, mailbox_id
			)
			INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags)
			SELECT id, mailbox_id, 0, '[]'::jsonb FROM inserted`,
			accountID, mailboxID, uid, fmt.Sprintf("<%d@test>", uid), contentHash,
			fmt.Sprintf("lp-%d", uid), subject, bsBytes, normalizeForSort(subject))
		require.NoError(t, err)

		if bodyTSVText != "" {
			_, err = db.GetWritePool().Exec(ctx, `
				INSERT INTO messages_fts (content_hash, text_body_tsv)
				VALUES ($1, to_tsvector('simple', $2))
				ON CONFLICT (content_hash) DO UPDATE SET text_body_tsv = EXCLUDED.text_body_tsv`,
				contentHash, bodyTSVText)
			require.NoError(t, err)
		}
	}

	insertMsg(1, "Re: "+token+" please", "hash-A", "")                   // header-only match
	insertMsg(2, "unrelated subject", "hash-B", "monthly "+token+" pdf") // body-only match
	insertMsg(3, "about "+token, "hash-C", "the "+token+" is here")      // matches BOTH (dedup)
	insertMsg(4, "nothing relevant", "hash-D", "plain ordinary content") // control: no match

	pathCount := func(label string) float64 {
		return testutil.ToFloat64(metrics.DBQueriesTotal.WithLabelValues(label, "success", "read"))
	}
	unionBefore := pathCount("search_messages_complex_text_union")

	results, err := db.SearchMessagesWithCriteria(ctx, mailboxID, &imap.SearchCriteria{Text: []string{token}}, 0)
	require.NoError(t, err)

	gotUIDs := map[imap.UID]bool{}
	for _, r := range results {
		gotUIDs[r.UID] = true
	}
	assert.Len(t, results, 3, "union should return header-only, body-only, and both-match messages, deduped")
	assert.True(t, gotUIDs[1], "header-only match must be returned")
	assert.True(t, gotUIDs[2], "body-only match must be returned")
	assert.True(t, gotUIDs[3], "both-match must be returned exactly once")
	assert.False(t, gotUIDs[4], "non-matching message must be excluded")

	assert.Equal(t, 1.0, pathCount("search_messages_complex_text_union")-unionBefore,
		"TEXT search should execute via the UNION path")
}

// Database test helpers for search tests
func setupSearchTestDatabase(t *testing.T) (*Database, int64, int64) {
	db := setupTestDatabase(t)

	ctx := context.Background()

	// Use test name and timestamp to create unique email
	testEmail := fmt.Sprintf("test_%s_%d@example.com", t.Name(), time.Now().UnixNano())

	// Create test account
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	req := CreateAccountRequest{
		Email:     testEmail,
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	}
	_, err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get account ID
	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	// Create test mailbox
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx2, accountID, "INBOX", nil)
	require.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Get mailbox ID
	mailbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)

	return db, accountID, mailbox.ID
}

// TestBuildNumSetCondition tests the number set condition building (placeholder)
func TestBuildNumSetCondition(t *testing.T) {
	tests := []struct {
		name        string
		numSet      imap.NumSet
		columnName  string
		expectError bool
	}{
		{
			name:        "simple UID range",
			numSet:      imap.UIDSet{imap.UIDRange{Start: 1, Stop: 5}},
			columnName:  "uid",
			expectError: false,
		},
		{
			name:        "sequence set",
			numSet:      imap.SeqSet{imap.SeqRange{Start: 1, Stop: 10}},
			columnName:  "seqnum",
			expectError: false,
		},
		{
			name:        "empty column name",
			numSet:      imap.UIDSet{imap.UIDRange{Start: 1, Stop: 5}},
			columnName:  "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This would test the buildNumSetCondition function
			t.Skip("buildNumSetCondition is internal function")

			// Example test structure:
			// paramCounter := 0
			// condition, args, err := buildNumSetCondition(tt.numSet, tt.columnName, "p", &paramCounter)
			// if tt.expectError {
			//     assert.Error(t, err)
			// } else {
			//     assert.NoError(t, err)
			//     assert.NotEmpty(t, condition)
			//     assert.NotNil(t, args)
			// }
		})
	}
}

// TestBuildSearchCriteria tests search criteria building
func TestBuildSearchCriteria(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	// Test cases for different search criteria:

	tests := []struct {
		name     string
		criteria *imap.SearchCriteria
		hasError bool
	}{
		{
			name: "search by UID range",
			criteria: &imap.SearchCriteria{
				UID: []imap.UIDSet{{imap.UIDRange{Start: 1, Stop: 10}}},
			},
			hasError: false,
		},
		{
			name: "search by sequence range",
			criteria: &imap.SearchCriteria{
				SeqNum: []imap.SeqSet{{imap.SeqRange{Start: 1, Stop: 5}}},
			},
			hasError: false,
		},
		{
			name: "search by date range",
			criteria: &imap.SearchCriteria{
				Since:  time.Now().Add(-7 * 24 * time.Hour),
				Before: time.Now(),
			},
			hasError: false,
		},
		{
			name: "search by sent date",
			criteria: &imap.SearchCriteria{
				SentSince:  time.Now().Add(-30 * 24 * time.Hour),
				SentBefore: time.Now().Add(-1 * 24 * time.Hour),
			},
			hasError: false,
		},
		{
			name: "search by message size",
			criteria: &imap.SearchCriteria{
				Larger:  1024,  // larger than 1KB
				Smaller: 10240, // smaller than 10KB
			},
			hasError: false,
		},
		{
			name: "search by flags",
			criteria: &imap.SearchCriteria{
				Flag:    []imap.Flag{imap.FlagSeen},
				NotFlag: []imap.Flag{imap.FlagDeleted},
			},
			hasError: false,
		},
		{
			name: "search by subject header",
			criteria: &imap.SearchCriteria{
				Header: []imap.SearchCriteriaHeaderField{
					{Key: "Subject", Value: "test"},
				},
			},
			hasError: false,
		},
		{
			name: "search by message-id header",
			criteria: &imap.SearchCriteria{
				Header: []imap.SearchCriteriaHeaderField{
					{Key: "Message-ID", Value: "<test@example.com>"},
				},
			},
			hasError: false,
		},
		{
			name: "search by from header",
			criteria: &imap.SearchCriteria{
				Header: []imap.SearchCriteriaHeaderField{
					{Key: "From", Value: "user@example.com"},
				},
			},
			hasError: false,
		},
		{
			name: "search by body text",
			criteria: &imap.SearchCriteria{
				Body: []string{"important message"},
			},
			hasError: false,
		},
		{
			name: "search by full text",
			criteria: &imap.SearchCriteria{
				Text: []string{"conference call"},
			},
			hasError: false,
		},
		{
			name: "search by references header",
			criteria: &imap.SearchCriteria{
				Header: []imap.SearchCriteriaHeaderField{
					{Key: "References", Value: "<parent@example.com>"},
				},
			},
			hasError: false,
		},
		{
			name: "search with non-indexed header (matches nothing, no error)",
			criteria: &imap.SearchCriteria{
				Header: []imap.SearchCriteriaHeaderField{
					{Key: "X-Custom-Header", Value: "value"},
				},
			},
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paramCounter := 0
			condition, args, err := db.buildSearchCriteria(tt.criteria, "p", &paramCounter)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, condition)
				assert.NotNil(t, args)
			}
		})
	}
}

// TestBuildSortOrderClause tests sort order clause building
func TestBuildSortOrderClause(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	tests := []struct {
		name     string
		criteria []imap.SortCriterion
		expected string
	}{
		{
			name:     "sort by date ascending",
			criteria: []imap.SortCriterion{{Key: imap.SortKeyArrival, Reverse: false}},
			expected: "m.internal_date ASC",
		},
		{
			name:     "sort by date descending",
			criteria: []imap.SortCriterion{{Key: imap.SortKeyArrival, Reverse: true}},
			expected: "m.internal_date DESC",
		},
		{
			name:     "sort by subject",
			criteria: []imap.SortCriterion{{Key: imap.SortKeySubject, Reverse: false}},
			expected: "m.subject_sort ASC",
		},
		{
			name:     "sort by size",
			criteria: []imap.SortCriterion{{Key: imap.SortKeySize, Reverse: false}},
			expected: "m.size ASC",
		},
		{
			name:     "no sort criteria",
			criteria: []imap.SortCriterion{},
			expected: "m.uid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := db.buildSortOrderClause(tt.criteria)
			assert.Contains(t, result, tt.expected)
		})
	}
}

// TestNeedsComplexQuery tests complex query detection
func TestNeedsComplexQuery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	tests := []struct {
		name           string
		criteria       *imap.SearchCriteria
		orderByClause  string
		expectsComplex bool
	}{
		{
			name: "simple UID search",
			criteria: &imap.SearchCriteria{
				UID: []imap.UIDSet{{imap.UIDRange{Start: 1, Stop: 10}}},
			},
			orderByClause:  "",
			expectsComplex: false,
		},
		{
			name: "body text search",
			criteria: &imap.SearchCriteria{
				Body: []string{"search term"},
			},
			orderByClause:  "",
			expectsComplex: true,
		},
		{
			name: "header search (simple)",
			criteria: &imap.SearchCriteria{
				Header: []imap.SearchCriteriaHeaderField{
					{Key: "From", Value: "user@example.com"},
				},
			},
			orderByClause:  "",
			expectsComplex: false,
		},
		{
			name:           "complex sort order with seqnum",
			criteria:       &imap.SearchCriteria{},
			orderByClause:  "ORDER BY seqnum ASC",
			expectsComplex: true,
		},
		{
			name: "OR with body search (nested)",
			criteria: &imap.SearchCriteria{
				Or: [][2]imap.SearchCriteria{
					{
						{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "test"}}},
						{Body: []string{"important"}},
					},
				},
			},
			orderByClause:  "",
			expectsComplex: true,
		},
		{
			name: "OR with text search (nested)",
			criteria: &imap.SearchCriteria{
				Or: [][2]imap.SearchCriteria{
					{
						{Header: []imap.SearchCriteriaHeaderField{{Key: "From", Value: "sender@example.com"}}},
						{Text: []string{"meeting"}},
					},
				},
			},
			orderByClause:  "",
			expectsComplex: true,
		},
		{
			name: "NOT with body search",
			criteria: &imap.SearchCriteria{
				Not: []imap.SearchCriteria{
					{Body: []string{"spam"}},
				},
			},
			orderByClause:  "",
			expectsComplex: true,
		},
		{
			name: "deeply nested OR with body search",
			criteria: &imap.SearchCriteria{
				Or: [][2]imap.SearchCriteria{
					{
						{Header: []imap.SearchCriteriaHeaderField{{Key: "To", Value: "a@example.com"}}},
						{Or: [][2]imap.SearchCriteria{
							{
								{Header: []imap.SearchCriteriaHeaderField{{Key: "Cc", Value: "b@example.com"}}},
								{Body: []string{"urgent"}},
							},
						}},
					},
				},
			},
			orderByClause:  "",
			expectsComplex: true,
		},
		{
			name: "complex production-like query",
			criteria: &imap.SearchCriteria{
				Or: [][2]imap.SearchCriteria{
					{
						{Header: []imap.SearchCriteriaHeaderField{{Key: "To", Value: "user@example.com"}}},
						{Or: [][2]imap.SearchCriteria{
							{
								{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "report"}}},
								{Or: [][2]imap.SearchCriteria{
									{
										{Header: []imap.SearchCriteriaHeaderField{{Key: "From", Value: "sender@example.com"}}},
										{Body: []string{"quarterly"}},
									},
								}},
							},
						}},
					},
				},
			},
			orderByClause:  "",
			expectsComplex: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := db.needsComplexQuery(tt.criteria, tt.orderByClause)
			assert.Equal(t, tt.expectsComplex, result)
		})
	}
}

// TestGetMessagesWithCriteria tests message search functionality
func TestGetMessagesWithCriteria(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Search empty mailbox (should return empty results)
	criteria := &imap.SearchCriteria{}
	messages, err := db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages)

	// Test 2: Search with UID criteria
	uidSet := imap.UIDSet{}
	uidSet.AddRange(1, 10)
	criteria = &imap.SearchCriteria{
		UID: []imap.UIDSet{uidSet},
	}
	messages, err = db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Empty mailbox, so no results

	// Test 3: Search with date range criteria
	now := time.Now()
	criteria = &imap.SearchCriteria{
		Since:  now.Add(-7 * 24 * time.Hour),
		Before: now,
	}
	messages, err = db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Empty mailbox, so no results

	// Test 4: Search with flag criteria
	criteria = &imap.SearchCriteria{
		Flag:    []imap.Flag{imap.FlagSeen},
		NotFlag: []imap.Flag{imap.FlagDeleted},
	}
	messages, err = db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Empty mailbox, so no results

	// Test 5: Search with invalid mailbox ID
	criteria = &imap.SearchCriteria{}
	messages, err = db.GetMessagesWithCriteria(ctx, 99999, criteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Invalid mailbox returns empty

	t.Logf("Successfully tested GetMessagesWithCriteria with accountID: %d, mailboxID: %d", accountID, mailboxID)
}

// TestGetMessagesSorted tests sorted message retrieval
func TestGetMessagesSorted(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Sort empty result set
	criteria := &imap.SearchCriteria{}
	sortCriteria := []imap.SortCriterion{
		{Key: imap.SortKeyArrival, Reverse: false},
	}
	messages, err := db.GetMessagesSorted(ctx, mailboxID, criteria, sortCriteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages)

	// Test 2: Sort by date descending
	sortCriteria = []imap.SortCriterion{
		{Key: imap.SortKeyArrival, Reverse: true},
	}
	messages, err = db.GetMessagesSorted(ctx, mailboxID, criteria, sortCriteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Empty mailbox

	// Test 3: Sort by subject
	sortCriteria = []imap.SortCriterion{
		{Key: imap.SortKeySubject, Reverse: false},
	}
	messages, err = db.GetMessagesSorted(ctx, mailboxID, criteria, sortCriteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Empty mailbox

	// Test 4: Sort by size
	sortCriteria = []imap.SortCriterion{
		{Key: imap.SortKeySize, Reverse: false},
	}
	messages, err = db.GetMessagesSorted(ctx, mailboxID, criteria, sortCriteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Empty mailbox

	// Test 5: Sort with search criteria and invalid mailbox
	uidSet := imap.UIDSet{}
	uidSet.AddRange(1, 10)
	criteria = &imap.SearchCriteria{
		UID: []imap.UIDSet{uidSet},
	}
	messages, err = db.GetMessagesSorted(ctx, 99999, criteria, sortCriteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Invalid mailbox

	t.Logf("Successfully tested GetMessagesSorted with accountID: %d, mailboxID: %d", accountID, mailboxID)
}

// TestSortedSearchWithComplexCriteria is a regression test for an ambiguous
// column reference (SQLSTATE 42702) that occurred when a full-text (Body/Text)
// search was combined with a SORT. Complex query paths LEFT JOIN messages_fts,
// which also has a sent_date column, so an unqualified "ORDER BY sent_date" was
// ambiguous between messages.sent_date and messages_fts.sent_date. The bug is a
// query-planner error, so it reproduces even against an empty mailbox.
func TestSortedSearchWithComplexCriteria(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	now := time.Now()

	cases := []struct {
		name     string
		criteria *imap.SearchCriteria
		sort     []imap.SortCriterion
	}{
		{
			// Exact production scenario: body FTS + date range + SORT DATE.
			name: "body+daterange sort date",
			criteria: &imap.SearchCriteria{
				Body:   []string{"fence"},
				Since:  now.Add(-365 * 24 * time.Hour),
				Before: now,
			},
			sort: []imap.SortCriterion{{Key: imap.SortKeyDate, Reverse: false}},
		},
		{
			name:     "body sort arrival reverse",
			criteria: &imap.SearchCriteria{Body: []string{"important"}},
			sort:     []imap.SortCriterion{{Key: imap.SortKeyArrival, Reverse: true}},
		},
		{
			name:     "text sort subject",
			criteria: &imap.SearchCriteria{Text: []string{"conference call"}},
			sort:     []imap.SortCriterion{{Key: imap.SortKeySubject, Reverse: false}},
		},
		{
			name:     "text sort size",
			criteria: &imap.SearchCriteria{Text: []string{"agenda"}},
			sort:     []imap.SortCriterion{{Key: imap.SortKeySize, Reverse: true}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// SearchMessagesSorted is the lightweight path that produced the
			// original "column reference sent_date is ambiguous" error.
			searchResults, err := db.SearchMessagesSorted(ctx, mailboxID, tc.criteria, tc.sort, 0)
			assert.NoError(t, err, "SearchMessagesSorted must not error on complex criteria + sort")
			assert.Empty(t, searchResults)

			// GetMessagesSorted is the heavyweight path; it has the same join
			// structure and was vulnerable to the same ambiguity.
			messages, err := db.GetMessagesSorted(ctx, mailboxID, tc.criteria, tc.sort, 0)
			assert.NoError(t, err, "GetMessagesSorted must not error on complex criteria + sort")
			assert.Empty(t, messages)
		})
	}
}

// TestFullTextSearch tests full-text search capabilities
func TestFullTextSearch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Search for single word in body (empty mailbox)
	criteria := &imap.SearchCriteria{
		Body: []string{"important"},
	}
	messages, err := db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Empty mailbox

	// Test 2: Search for phrase in body
	criteria = &imap.SearchCriteria{
		Body: []string{"meeting agenda"},
	}
	messages, err = db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Empty mailbox

	// Test 3: Search in both headers and body (TEXT)
	criteria = &imap.SearchCriteria{
		Text: []string{"conference call"},
	}
	messages, err = db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
	assert.NoError(t, err)
	// TEXT search matches against text_body_tsv and dedicated header columns (subject, from/to/cc sort fields)
	t.Logf("TEXT search for 'conference call' returned %d results", len(messages))

	// Test 4: Search with special characters
	criteria = &imap.SearchCriteria{
		Body: []string{"user@example.com"},
	}
	messages, err = db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Empty mailbox

	// Test 5: Search in headers (subject)
	criteria = &imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{
			{Key: "Subject", Value: "test"},
		},
	}
	messages, err = db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Empty mailbox

	t.Logf("Successfully tested FullTextSearch with accountID: %d, mailboxID: %d", accountID, mailboxID)
}

// TestSearchCriteriaValidation tests search criteria validation using SearchCriteriaValidator
func TestSearchCriteriaValidation(t *testing.T) {
	validator := NewSearchCriteriaValidator()

	tests := []struct {
		name     string
		criteria *imap.SearchCriteria
		valid    bool
	}{
		{
			name:     "nil criteria",
			criteria: nil,
			valid:    false,
		},
		{
			name:     "empty criteria",
			criteria: &imap.SearchCriteria{},
			valid:    true,
		},
		{
			name: "valid UID range",
			criteria: &imap.SearchCriteria{
				UID: []imap.UIDSet{{imap.UIDRange{Start: 1, Stop: 100}}},
			},
			valid: true,
		},
		{
			name: "invalid date range",
			criteria: &imap.SearchCriteria{
				Since:  time.Now(),
				Before: time.Now().Add(-24 * time.Hour), // Before is after Since
			},
			valid: false,
		},
		{
			name: "invalid size range",
			criteria: &imap.SearchCriteria{
				Larger:  1000,
				Smaller: 500, // Smaller is less than Larger
			},
			valid: false,
		},
		{
			name: "too many text search terms",
			criteria: &imap.SearchCriteria{
				Text: make([]string, 15), // Exceeds MaxTextSearchTerms (10)
			},
			valid: false,
		},
		{
			name: "generic header field (now supported)",
			criteria: &imap.SearchCriteria{
				Header: []imap.SearchCriteriaHeaderField{{Key: "x-custom-header", Value: "test"}},
			},
			valid: true,
		},
		{
			name: "valid complex search",
			criteria: &imap.SearchCriteria{
				Header: []imap.SearchCriteriaHeaderField{{Key: "subject", Value: "test"}},
				Flag:   []imap.Flag{imap.FlagSeen},
				Text:   []string{"search term"},
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill empty text slices with valid values for the "too many" test
			if tt.criteria != nil && len(tt.criteria.Text) > 0 && tt.criteria.Text[0] == "" {
				for i := range tt.criteria.Text {
					tt.criteria.Text[i] = "term"
				}
			}

			result := validator.ValidateSearchCriteria(tt.criteria)

			if tt.valid {
				assert.True(t, result.Valid, "Expected criteria to be valid")
				if !result.Valid && len(result.Errors) > 0 {
					t.Logf("Validation errors: %v", result.Errors[0])
				}
			} else {
				assert.False(t, result.Valid, "Expected criteria to be invalid")
				assert.NotEmpty(t, result.Errors, "Expected validation errors")
			}
		})
	}
}

// TestSearchPerformanceBasic tests basic search performance characteristics
// For comprehensive performance testing, see search_performance_test.go
func TestSearchPerformanceBasic(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Basic performance validation - ensure search operations complete in reasonable time
	t.Run("BasicSearchPerformance", func(t *testing.T) {
		maxDuration := 5 * time.Second // Reasonable timeout for empty mailbox

		testCases := []struct {
			name     string
			criteria *imap.SearchCriteria
		}{
			{
				name:     "UID search",
				criteria: &imap.SearchCriteria{UID: []imap.UIDSet{{imap.UIDRange{Start: 1, Stop: 10}}}},
			},
			{
				name:     "Flag search",
				criteria: &imap.SearchCriteria{Flag: []imap.Flag{imap.FlagSeen}},
			},
			{
				name:     "Date range search",
				criteria: &imap.SearchCriteria{Since: time.Now().Add(-24 * time.Hour)},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				start := time.Now()
				messages, err := db.GetMessagesWithCriteria(ctx, mailboxID, tc.criteria, 0)
				elapsed := time.Since(start)

				assert.NoError(t, err)
				if messages != nil {
					assert.Empty(t, messages) // Empty mailbox in basic tests
				} else {
					t.Logf("Search returned nil (no results) as expected for empty mailbox")
				}

				if elapsed > maxDuration {
					t.Errorf("%s took %v, which exceeds maximum expected duration of %v",
						tc.name, elapsed, maxDuration)
				} else {
					t.Logf("%s completed in %v", tc.name, elapsed)
				}
			})
		}
	})

	// Validate search constants are reasonable
	t.Run("SearchConstants", func(t *testing.T) {
		assert.Equal(t, 100000, MaxSearchResults, "MaxSearchResults should be 100000")
		assert.Equal(t, 500, MaxComplexSortResults, "MaxComplexSortResults should be 500")
		assert.Less(t, MaxComplexSortResults, MaxSearchResults, "Complex sort limit should be less than regular search limit")

		t.Logf("Search limits: MaxSearchResults=%d, MaxComplexSortResults=%d",
			MaxSearchResults, MaxComplexSortResults)
	})

	t.Logf("Successfully tested basic search performance with accountID: %d, mailboxID: %d", accountID, mailboxID)
	t.Logf("Note: For comprehensive performance testing with large datasets, run the tests in search_performance_test.go")
}

// TestSearchEdgeCases tests edge cases in search functionality
func TestSearchEdgeCases(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Search with empty search terms
	criteria := &imap.SearchCriteria{
		Body: []string{""},
	}
	messages, err := db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Empty search term in empty mailbox

	// Test 2: Search with only whitespace
	criteria = &imap.SearchCriteria{
		Body: []string{"   "},
	}
	messages, err = db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Whitespace search

	// Test 3: Search with unicode characters
	criteria = &imap.SearchCriteria{
		Body: []string{"测试"},
	}
	messages, err = db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Unicode search

	// Test 4: Search with regex special characters
	criteria = &imap.SearchCriteria{
		Body: []string{"user@example.com [urgent]"},
	}
	messages, err = db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Special characters

	// Test 5: Search with complex criteria combination
	uidSet := imap.UIDSet{}
	uidSet.AddRange(1, 100)
	criteria = &imap.SearchCriteria{
		UID:     []imap.UIDSet{uidSet},
		Flag:    []imap.Flag{imap.FlagSeen},
		NotFlag: []imap.Flag{imap.FlagDeleted},
		Body:    []string{"important"},
		Since:   time.Now().Add(-30 * 24 * time.Hour),
		Before:  time.Now(),
	}
	messages, err = db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Complex criteria on empty mailbox

	t.Logf("Successfully tested SearchEdgeCases with accountID: %d, mailboxID: %d", accountID, mailboxID)
}
