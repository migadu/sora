package db

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The account scope for the FTS table MUST live in a JOIN ON clause and never in a WHERE
// clause. Every search query LEFT JOINs messages_fts_v2, and several join it
// unconditionally -- db/thread.go joins it for every THREAD including THREAD ALL, and
// db/user_operations.go ORs the FTS predicate with header LIKE predicates. For a message
// with no FTS row at all, "mc.account_id = @accountID" in WHERE evaluates to NULL, which
// silently turns the LEFT JOIN into an inner join and drops that message.
//
// Messages without an FTS row are ordinary: bodies over 64KB are never staged, empty
// bodies are skipped, and PruneOldMessageVectors deletes rows once fts_retention expires.
// A negated FTS criterion is TRUE for exactly those messages, so the WHERE placement also
// discards every true negative.
//
// This is a source-level guard because the failure is silent: the query still runs, still
// returns rows, and simply omits some of them.
func TestFTSAccountScopeNeverInWhereClause(t *testing.T) {
	root := moduleRoot(t)

	// Every reference to the FTS alias's account column must be part of that table's join
	// clause -- on the same line as the JOIN, or on the line immediately after it, which is
	// how a two-line join is written. Anything else is a filter, and a filter is the bug.
	//
	// Matching on "WHERE ... mc.account_id" on one line is NOT enough: SQL here is written
	// across several lines, so the WHERE and the offending AND are usually on different
	// ones. (This test was first written that way and did not fail when the scope was
	// deliberately moved into a WHERE clause.)
	scopeRef := regexp.MustCompile(`\b(mc|mf)\.account_id\b`)
	joinRef := regexp.MustCompile(`(?i)JOIN\s+messages_fts_v2`)

	var offenders []string
	err := filepath.WalkDir(filepath.Join(root, "db"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "--") {
				continue
			}
			if !scopeRef.MatchString(line) {
				continue
			}
			inJoin := joinRef.MatchString(line)
			if !inJoin && i > 0 {
				inJoin = joinRef.MatchString(lines[i-1])
			}
			if !inJoin {
				rel, _ := filepath.Rel(root, path)
				offenders = append(offenders, rel+":"+itoa(i+1)+": "+trimmed)
			}
		}
		return nil
	})
	require.NoError(t, err)

	assert.Empty(t, offenders,
		"the FTS account scope must sit in the JOIN ON clause, not in WHERE. In WHERE it degrades "+
			"the LEFT JOIN to an inner join and silently drops every message that has no FTS row "+
			"(>64KB bodies, empty bodies, retention-pruned rows) plus every true negative of a "+
			"negated FTS criterion. Offending lines:\n%s", strings.Join(offenders, "\n"))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// The scoped join itself must bind the account as a CONSTANT. Writing it as
// "mc.account_id = m.account_id" would be equally correct in results and useless for
// performance: the composite GIN on (account_id, text_body_tsv) can only build a scan key
// from a constant, so a column-to-column equality leaves the planner back with a
// per-message probe.
func TestFTSScopedJoinBindsAccountAsConstant(t *testing.T) {
	assert.Contains(t, ftsScopedJoin, "LEFT JOIN messages_fts_v2 mc")
	assert.Contains(t, ftsScopedJoin, "ON mc.content_hash = m.content_hash")
	assert.Contains(t, ftsScopedJoin, "AND mc.account_id = @accountID")
	assert.NotContains(t, ftsScopedJoin, "mc.account_id = m.account_id",
		"the GIN needs a constant scan key, not a column-to-column equality")
}

// Query-shape selection: which of the two forms a body search gets. Neither wins
// everywhere (see ftsCTEThreshold), so this pins the decision rather than the plan.
func TestCanUseFTSPrefilter(t *testing.T) {
	db := &Database{}
	body := func(terms ...string) *imap.SearchCriteria {
		return &imap.SearchCriteria{Body: terms}
	}

	tests := []struct {
		name         string
		criteria     *imap.SearchCriteria
		seqNum       bool
		orderBy      string
		mailboxCount int
		want         bool
		why          string
	}{
		{"small mailbox keeps the per-message probe", body("invoice"), false, "", 100, false,
			"below the threshold the probe is ~150x cheaper"},
		{"large mailbox gets the prefilter", body("invoice"), false, "", ftsCTEThreshold, true,
			"at and above the threshold the probe degrades to a full mailbox scan with a detoast per row"},
		{"unknown mailbox size keeps the probe", body("invoice"), false, "", 0, false,
			"callers with no count (User API, MULTISEARCH) must get the safe default"},
		{"two body terms share one match set", body("a", "b"), false, "", 100000, true,
			"required terms are intersected inside one account-scoped match set"},
		{"TEXT gets its own match set", &imap.SearchCriteria{Text: []string{"a"}}, false, "", 100000, true,
			"TEXT is body OR headers, so its body side is a LEFT JOINed match set, not an inner join"},
		{"nested FTS gets its own match set", &imap.SearchCriteria{
			Or: [][2]imap.SearchCriteria{{{Body: []string{"a"}}, {Body: []string{"b"}}}},
		}, false, "", 100000, true, "a term inside OR/NOT is tested against its own LEFT JOINed match set"},
		{"seqnum search is rejected", body("invoice"), true, "", 100000, false,
			"sequence numbers need the legacy CTE"},
		{"seqnum ORDER BY is rejected", body("invoice"), false, "ORDER BY seqnum", 100000, false,
			"the rewrite has no seqnum to order by"},
		{"no FTS term at all", &imap.SearchCriteria{}, false, "", 100000, false,
			"nothing to prefilter"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := db.canUseFTSPrefilter(tc.criteria, tc.seqNum, tc.orderBy, tc.mailboxCount)
			assert.Equal(t, tc.want, got, tc.why)
		})
	}
}

// The prefilter form must actually force the account-scoped evaluation. MATERIALIZED is
// load-bearing: without it PostgreSQL inlines the CTE and is free to fall back to the
// per-message probe this rewrite exists to avoid.
func TestBuildFTSPrefilterQuerySQL(t *testing.T) {
	var db *Database
	paramCounter := 0
	criteria := &imap.SearchCriteria{Body: []string{"Invoice"}}

	query, args, err := db.buildFTSPrefilterQuery(criteria, 42, 7,
		ftsLightBranchSelect+", "+textUnionSortColumnsLight, ftsLightOuterSelect, "", MaxSearchResults, &paramCounter)
	require.NoError(t, err)

	assert.Contains(t, query, "AS MATERIALIZED",
		"without MATERIALIZED the planner may inline the CTE and revert to the per-message probe")
	assert.Contains(t, query, "FROM messages_fts_v2")
	assert.Contains(t, query, "WHERE account_id = @accountID",
		"the match set must be scoped to the account, which is the entire point")
	assert.Contains(t, query, "text_body_tsv IS NOT NULL",
		"required for the PARTIAL composite GIN to be usable")
	assert.Contains(t, query, "JOIN fts_hits ON fts_hits.content_hash = m.content_hash")
	assert.Contains(t, query, "m.mailbox_id = @mailboxID")
	assert.NotContains(t, query, "m.account_id = @accountID",
		"messages must not be filtered on account_id: pre-June shared-mailbox mail carries the "+
			"appender's id, and mailbox_id already scopes the query (TestLegacySharedMailboxMessagesStaySearchable)")
	assert.NotContains(t, query, ftsScopedJoin,
		"the prefilter form replaces the per-message join; having both would evaluate the term twice")

	assert.Equal(t, int64(42), args["mailboxID"])
	assert.Equal(t, int64(7), args["accountID"])
	var sawTerm bool
	for _, v := range args {
		if v == "Invoice" {
			sawTerm = true
		}
	}
	assert.True(t, sawTerm, "tsquery arg should preserve the original term case")
}

// A search with no full-text term has nothing to prefilter and must be refused rather than
// built into a query with an empty match set.
func TestBuildFTSPrefilterQueryRefusesIneligibleCriteria(t *testing.T) {
	var db *Database
	paramCounter := 0
	_, _, err := db.buildFTSPrefilterQuery(&imap.SearchCriteria{Flag: []imap.Flag{imap.FlagSeen}}, 42, 7,
		ftsLightBranchSelect, ftsLightOuterSelect, "", 100, &paramCounter)
	require.Error(t, err)
}

// Terms that are not required AND factors -- inside OR or NOT, or TEXT (body OR headers) --
// each get their own account-scoped match set, LEFT JOINed, and the leaf becomes a test of
// whether the message's body was in it. Required top-level BODY terms are intersected in one
// combined set, inner-joined, so the GIN can AND them before any heap is touched.
func TestBuildFTSPrefilterQueryNestedTerms(t *testing.T) {
	var db *Database
	paramCounter := 0
	criteria := &imap.SearchCriteria{
		Body: []string{"alpha", "beta"},
		Text: []string{"delta"},
		Or: [][2]imap.SearchCriteria{{
			{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "invoice"}}},
			{Body: []string{"gamma"}},
		}},
		Not: []imap.SearchCriteria{{Body: []string{"gamma"}}},
	}

	query, args, err := db.buildFTSPrefilterQuery(criteria, 42, 7,
		ftsLightBranchSelect+", "+textUnionSortColumnsLight, ftsLightOuterSelect, "", MaxSearchResults, &paramCounter)
	require.NoError(t, err)

	// The required terms: one combined set, inner-joined.
	assert.Equal(t, 1, strings.Count(query, "fts_hits AS MATERIALIZED"))
	assert.Regexp(t, `(?m)^\s*JOIN fts_hits ON fts_hits\.content_hash = m\.content_hash`, query,
		"the required set is an INNER join; a LEFT join would stop it filtering")

	// TEXT delta and the (deduplicated) gamma each get one LEFT JOINed set.
	assert.Equal(t, 1, strings.Count(query, "fts_hits_1 AS MATERIALIZED"))
	assert.Equal(t, 1, strings.Count(query, "fts_hits_2 AS MATERIALIZED"))
	assert.NotContains(t, query, "fts_hits_3", "a repeated term must reuse its match set")
	assert.Contains(t, query, "LEFT JOIN fts_hits_1 ON fts_hits_1.content_hash = m.content_hash")
	assert.Contains(t, query, "LEFT JOIN fts_hits_2 ON fts_hits_2.content_hash = m.content_hash")

	// Every match set is account-scoped and usable by the partial composite GIN; four terms,
	// four tsqueries, and none of them evaluated per message.
	assert.Equal(t, 3, strings.Count(query, "WHERE account_id = @accountID"))
	assert.Equal(t, 3, strings.Count(query, "text_body_tsv IS NOT NULL"))
	assert.Equal(t, 4, strings.Count(query, "text_body_tsv @@ plainto_tsquery('simple',"))
	assert.NotContains(t, query, "messages_fts_v2 mc", "the per-message probe must be gone entirely")
	assert.NotContains(t, query, "m.account_id = @accountID")

	// delta is tested once (TEXT), gamma twice (inside OR and inside NOT).
	assert.Equal(t, 1, strings.Count(query, "fts_hits_1.content_hash IS NOT NULL"))
	assert.Equal(t, 2, strings.Count(query, "fts_hits_2.content_hash IS NOT NULL"))

	assert.Equal(t, int64(7), args["accountID"])
	terms := map[string]bool{}
	for _, v := range args {
		if s, ok := v.(string); ok {
			terms[s] = true
		}
	}
	for _, term := range []string{"alpha", "beta", "delta", "gamma"} {
		assert.True(t, terms[term], "term %q must be bound", term)
	}
}
