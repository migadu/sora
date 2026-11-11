package db

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Header search (SEARCH FROM/TO/CC/SUBJECT/HEADER References, TEXT, and the User API
// mailbox search) is written as strpos(), never LIKE, and is served by
// idx_messages_mailbox_headers (migration 000052) as an Index Only Scan.
//
// The two halves depend on each other. LIKE on these columns is served by the corpus-wide
// trigram GINs from migration 000034, whose planner cost estimate is wrong by three orders of
// magnitude (a production SEARCH FROM on a 777-message mailbox read 3.5 GB of GIN pages in
// 70 s). strpos is not indexable, which pins the plan to a mailbox index, but filtering heap
// rows that way read 1.8 GB in 38 s on the largest mailbox (534k rows). The covering index
// carries every column the lightweight search projection and its criteria reference, so the
// same statement reads ~200 bytes per message from the index and never touches the heap.
// These tests pin each link: no LIKE, literal terms, bounded columns so the index tuple fits,
// the index covering every referenced column, and the plan actually being index-only.

// TestHeaderSearchSQLNeverUsesLike scans the source of the header-search builders for a
// LIKE token outside comments. A header predicate written as LIKE would hand the planner
// the trigram GINs again, whatever the index below provides.
func TestHeaderSearchSQLNeverUsesLike(t *testing.T) {
	likeToken := regexp.MustCompile(`\bLIKE\b`)
	for _, name := range []string{"search.go", "user_operations.go"} {
		src, err := os.ReadFile(name)
		require.NoError(t, err)
		for i, line := range strings.Split(string(src), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "--") {
				continue
			}
			if likeToken.MatchString(line) {
				t.Errorf("%s:%d uses LIKE; header matching must use substringCond/strpos so the planner cannot pick the corpus-wide trigram GINs: %s", name, i+1, trimmed)
			}
		}
	}
}

// TestHeaderSearchCriteriaBindLiteralTerms verifies, for every header criterion, that the
// generated SQL is a strpos() test and the bound value is the bare lowercased term: no
// wildcard wrapping, which LIKE needed and which also turned a % or _ in the user's term
// into a wildcard.
func TestHeaderSearchCriteriaBindLiteralTerms(t *testing.T) {
	var db *Database // the builder never dereferences its receiver

	header := func(key string) *imap.SearchCriteria {
		return &imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: key, Value: "Support@Equishark.com"}}}
	}
	cases := []struct {
		name     string
		criteria *imap.SearchCriteria
		exprs    []string
	}{
		{"FROM", header("From"), []string{"m.from_email_sort", "m.from_name_sort"}},
		{"TO", header("To"), []string{"m.to_email_sort", "m.to_name_sort"}},
		{"CC", header("Cc"), []string{"m.cc_email_sort"}},
		{"SUBJECT", header("Subject"), []string{"LOWER(m.subject)"}},
		{"HEADER References", header("References"), []string{`LOWER(m."references")`}},
		{"TEXT", &imap.SearchCriteria{Text: []string{"Support@Equishark.com"}}, []string{"LOWER(m.subject)", "m.from_email_sort", "m.to_name_sort", "m.cc_email_sort"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			paramCounter := 0
			query, args, err := db.buildSearchCriteria(tc.criteria, "p", &paramCounter)
			require.NoError(t, err)
			for _, expr := range tc.exprs {
				assert.Contains(t, query, "strpos("+expr+", @")
			}
			assert.NotContains(t, query, " LIKE ")
			var bound []string
			for _, v := range args {
				if s, ok := v.(string); ok {
					bound = append(bound, s)
				}
			}
			assert.Contains(t, bound, "support@equishark.com", "term must be bound lowercased, exactly as typed")
			for _, s := range bound {
				assert.False(t, strings.HasPrefix(s, "%") || strings.HasSuffix(s, "%"), "no wildcard wrapping: %q", s)
			}
		})
	}
}

// TestSortColumnsAreBounded pins the write-time byte bounds that let the covering index
// carry the header columns: a btree tuple over 2704 bytes makes the INSERT fail, so every
// text column in the index must be bounded before it is written, without splitting a rune.
func TestSortColumnsAreBounded(t *testing.T) {
	// 'é' is two bytes; an odd byte bound must not cut one in half.
	longName := strings.Repeat("é", 400)
	longAddr := strings.Repeat("a", 300) + "@example.com"
	longSubject := "Re: " + strings.Repeat("ü", 700)

	subjectSort, fromName, fromEmail, toName, toEmail, ccEmail := sortColumnsFor(longSubject, []helpers.Recipient{
		{AddressType: "from", Name: longName, EmailAddress: strings.ToUpper(longAddr)},
		{AddressType: "to", Name: "Bob", EmailAddress: "Bob@Example.org"},
		{AddressType: "cc", EmailAddress: strings.Repeat("c", 250) + "@x.org"},
	})
	for name, v := range map[string]string{"subject_sort": subjectSort, "from_name_sort": fromName, "from_email_sort": fromEmail, "cc_email_sort": ccEmail} {
		assert.True(t, utf8.ValidString(v), "%s must stay valid UTF-8", name)
	}
	assert.LessOrEqual(t, len(subjectSort), helpers.MaxSubjectBytes)
	assert.LessOrEqual(t, len(fromName), helpers.MaxSortColumnBytes)
	assert.LessOrEqual(t, len(fromEmail), helpers.MaxSortColumnBytes)
	assert.LessOrEqual(t, len(ccEmail), helpers.MaxSortColumnBytes)
	assert.Equal(t, "bob", toName, "short values are lowercased and otherwise untouched")
	assert.Equal(t, "bob@example.org", toEmail)
	assert.Equal(t, strings.ToLower(longAddr)[:helpers.MaxSortColumnBytes], fromEmail, "truncation keeps the prefix")

	// scripts/fix_oversized_header_columns.sql bounds EXISTING rows before the index is built;
	// it must apply the same numbers, or the build fails on a row the application would
	// have bounded.
	script, err := os.ReadFile("../scripts/fix_oversized_header_columns.sql")
	require.NoError(t, err)
	want := map[string]int{"subject": helpers.MaxSubjectBytes, "subject_sort": helpers.MaxSubjectBytes,
		"from_email_sort": helpers.MaxSortColumnBytes, "from_name_sort": helpers.MaxSortColumnBytes,
		"to_email_sort": helpers.MaxSortColumnBytes, "to_name_sort": helpers.MaxSortColumnBytes, "cc_email_sort": helpers.MaxSortColumnBytes}
	for col, n := range want {
		assert.Contains(t, string(script), fmt.Sprintf("sora_trunc_utf8(m.%s, %d)", col, n), "the fix script must truncate %s to %d bytes like the application", col, n)
		assert.Contains(t, string(script), fmt.Sprintf("octet_length(%s) > %d", col, n), "the fix script must select %s rows over %d bytes", col, n)
	}

	// The sum the index relies on: worst-case text in one tuple stays under the btree limit
	// with room for the fixed columns and headers.
	const btreeTupleLimit, fixedColumnsAndHeaders = 2704, 130
	assert.LessOrEqual(t, 2*helpers.MaxSubjectBytes+5*helpers.MaxSortColumnBytes+fixedColumnsAndHeaders, btreeTupleLimit,
		"the byte bounds must keep an idx_messages_mailbox_headers tuple under the btree limit")
}

// headerIndexColumns parses the INCLUDE list, key column and predicate column of
// idx_messages_mailbox_headers from migration 000052, so the guards below follow the
// migration rather than a copy of it.
func headerIndexColumns(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile("migrations/000052_messages_mailbox_headers_index.up.sql")
	require.NoError(t, err)
	// The statement is the last CREATE INDEX in the file (the runbook quotes the DDL in a
	// comment above it); strip comment lines first.
	var code []string
	for _, line := range strings.Split(string(src), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			code = append(code, line)
		}
	}
	stmt := strings.Join(code, "\n")
	m := regexp.MustCompile(`(?s)ON messages \((\w+)\)\s*INCLUDE \(([^)]*)\)\s*WHERE (\w+) IS NULL`).FindStringSubmatch(stmt)
	require.NotNil(t, m, "could not parse the index definition from migration 000052:\n%s", stmt)
	cols := map[string]bool{m[1]: true, m[3]: true}
	for _, c := range strings.Split(m[2], ",") {
		cols[strings.TrimSpace(c)] = true
	}
	return cols
}

// headerIndexHeapOnlyColumns are messages.* columns the search builders may reference that
// are deliberately NOT in the index: rare criteria with their own index (message_id,
// in_reply_to) or no bounded representation (recipients_json for BCC/Reply-To, the 2000-byte
// "references"). A search on them reads the heap; everything else must not.
var headerIndexHeapOnlyColumns = map[string]bool{
	"recipients_json": true, `"references"`: true, "message_id": true, "in_reply_to": true,
}

// TestHeaderIndexCoversLightweightSearch asserts that every messages.* column the lightweight
// search can reference, in its projection, its criteria or its SORT keys, is carried by
// idx_messages_mailbox_headers. One missing column silently turns every header search back
// into the heap filter measured at 38 s, and nothing else would notice.
func TestHeaderIndexCoversLightweightSearch(t *testing.T) {
	indexed := headerIndexColumns(t)
	var db *Database
	colRef := regexp.MustCompile(`\bm\.("references"|[a-z_]+)`)
	referenced := map[string]string{} // column -> where it was seen

	note := func(sql, where string) {
		for _, m := range colRef.FindAllStringSubmatch(sql, -1) {
			referenced[m[1]] = where
		}
	}

	// Criteria: every leaf kind the builder knows.
	now := time.Now()
	criteria := &imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{
			{Key: "From", Value: "a"}, {Key: "To", Value: "a"}, {Key: "Cc", Value: "a"}, {Key: "Subject", Value: "a"},
			{Key: "References", Value: "a"}, {Key: "Message-Id", Value: "a"}, {Key: "In-Reply-To", Value: "a"},
			{Key: "Bcc", Value: "a"}, {Key: "Reply-To", Value: "a"},
		},
		Text: []string{"a"}, Body: []string{"a"},
		Since: now, Before: now, SentSince: now, SentBefore: now, Larger: 1, Smaller: 2,
		Flag: []imap.Flag{imap.FlagSeen, "$Custom"}, NotFlag: []imap.Flag{imap.FlagDraft},
		ModSeq: &imap.SearchCriteriaModSeq{ModSeq: 1},
	}
	var uids imap.UIDSet
	uids.AddRange(1, 10)
	criteria.UID = []imap.UIDSet{uids}
	paramCounter := 0
	where, _, err := db.buildSearchCriteria(criteria, "p", &paramCounter)
	require.NoError(t, err)
	note(where, "search criteria")

	// SORT keys.
	for _, key := range []imap.SortKey{imap.SortKeyArrival, imap.SortKeyDate, imap.SortKeySubject, imap.SortKeySize,
		imap.SortKeyDisplayFrom, imap.SortKeyFrom, imap.SortKeyDisplayTo, imap.SortKeyTo, imap.SortKeyCc} {
		note(db.buildSortOrderClause([]imap.SortCriterion{{Key: key}}), "SORT "+string(key))
	}

	// Projections and carried sort columns of the lightweight shapes.
	note(ftsLightBranchSelect, "ftsLightBranchSelect")
	note(textUnionSortColumnsLight, "textUnionSortColumnsLight")

	// The lightweight executor's own templates, from source: everything between its func
	// line and the next top-level closing brace.
	src, err := os.ReadFile("search.go")
	require.NoError(t, err)
	body := string(src)
	start := strings.Index(body, "func (db *Database) getSearchMessagesQueryExecutor(")
	require.Positive(t, start, "getSearchMessagesQueryExecutor not found")
	end := strings.Index(body[start:], "\n}\n")
	require.Positive(t, end)
	note(body[start:start+end], "getSearchMessagesQueryExecutor")

	var missing []string
	for col, where := range referenced {
		if !indexed[col] && !headerIndexHeapOnlyColumns[col] {
			missing = append(missing, fmt.Sprintf("%s (referenced by %s)", col, where))
		}
	}
	sort.Strings(missing)
	assert.Empty(t, missing, "messages.* columns referenced by the lightweight search but not carried by idx_messages_mailbox_headers; add them to the INCLUDE list (and bound them if text) or to headerIndexHeapOnlyColumns with a reason")
	// The guard must have seen the columns it exists for.
	for _, col := range []string{"from_email_sort", "subject", "subject_sort", "content_hash", "internal_date", "size"} {
		assert.Contains(t, referenced, col, "harness check: the probe must reference %s", col)
	}
}

// hdrPlanNode is the subset of an EXPLAIN (ANALYZE, FORMAT JSON) node the plan-shape test reads.
type hdrPlanNode struct {
	NodeType     string        `json:"Node Type"`
	RelationName string        `json:"Relation Name"`
	IndexName    string        `json:"Index Name"`
	HeapFetches  float64       `json:"Heap Fetches"`
	Plans        []hdrPlanNode `json:"Plans"`
}

func (n hdrPlanNode) walk(visit func(hdrPlanNode)) {
	visit(n)
	for _, c := range n.Plans {
		c.walk(visit)
	}
}

// TestHeaderSearchIsIndexOnly captures the statement IMAP SEARCH FROM actually issues and
// replays it under EXPLAIN (ANALYZE): the messages table must be read through an Index Only
// Scan on idx_messages_mailbox_headers and through nothing else. This is the property the
// migration exists for; a projection or predicate column outside the index breaks it, and
// only the plan shows that.
//
// Sequential scans are disabled for the EXPLAIN because on a test-sized table a seq scan is
// legitimately cheapest; the assertion is about index-only versus heap-reading index paths,
// which is the choice production faces.
func TestHeaderSearchIsIndexOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	bs := imap.BodyStructure(&imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 100})
	bsBytes, err := helpers.SerializeBodyStructureGob(&bs)
	require.NoError(t, err)

	// Enough rows that the index-only scan is worth choosing over a heap-reading index path,
	// with the matching sender on every 500th message.
	const rows = 20000
	_, err = db.GetWritePool().Exec(ctx, `
		INSERT INTO messages
		(account_id, mailbox_id, mailbox_path, uid, message_id, in_reply_to, content_hash, s3_domain, s3_localpart,
		 internal_date, size, subject, sent_date, body_structure, recipients_json, created_modseq,
		 subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort)
		SELECT $1, $2, 'INBOX', g, '<ios-' || g || '@test>', '', 'ioshash-' || g, 'd', 'lp-' || g,
		       now() - (g || ' seconds')::interval, 100, 'Invoice ' || g, now() - (g || ' seconds')::interval, $3, '[]'::jsonb, nextval('messages_modseq'),
		       'INVOICE ' || g, 'sender ' || (g % 500), 'sender' || (g % 500) || '@example.com', 'me', 'me@example.com', NULL
		FROM generate_series(1, $4::int) g`, accountID, mailboxID, bsBytes, rows)
	require.NoError(t, err)
	// Set the visibility map so the planner (and the scan) can go index-only.
	_, err = db.GetWritePool().Exec(ctx, "VACUUM ANALYZE messages")
	require.NoError(t, err)

	tracer := &queryCapturingTracer{}
	tracedPool := newCapturingPool(t, ctx, db.GetReadPool(), tracer)
	defer tracedPool.Close()
	traced := &Database{WritePool: db.GetWritePool(), ReadPool: tracedPool}

	criteria := &imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "From", Value: "sender42@"}}}
	results, err := traced.SearchMessagesWithCriteria(ctx, mailboxID, accountID, criteria, 0, rows)
	require.NoError(t, err)
	require.Len(t, results, rows/500, "the search must find every message from sender42")

	var searchStmt *capturedQuery
	for i, q := range tracer.captured() {
		if strings.Contains(q.SQL, "strpos(") && strings.Contains(q.SQL, "FROM messages m") {
			searchStmt = &tracer.captured()[i]
		}
	}
	require.NotNil(t, searchStmt, "harness broken: the header search statement was not captured")

	conn, err := db.GetReadPool().Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	_, err = conn.Exec(ctx, "SET enable_seqscan = off")
	require.NoError(t, err)
	var raw []byte
	err = conn.QueryRow(ctx, "EXPLAIN (ANALYZE, FORMAT JSON) "+searchStmt.SQL, searchStmt.Args...).Scan(&raw)
	require.NoError(t, err, "failed to EXPLAIN the captured statement:\n%s", searchStmt.SQL)
	var explained []struct {
		Plan hdrPlanNode `json:"Plan"`
	}
	require.NoError(t, json.Unmarshal(raw, &explained))
	require.Len(t, explained, 1)

	var indexOnly, otherMessagesScans []string
	explained[0].Plan.walk(func(n hdrPlanNode) {
		if n.RelationName != "messages" {
			return
		}
		if n.NodeType == "Index Only Scan" && n.IndexName == "idx_messages_mailbox_headers" {
			indexOnly = append(indexOnly, fmt.Sprintf("%s heap_fetches=%.0f", n.IndexName, n.HeapFetches))
			return
		}
		otherMessagesScans = append(otherMessagesScans, n.NodeType+" "+n.IndexName)
	})
	assert.NotEmpty(t, indexOnly, "header SEARCH must read messages through an Index Only Scan on idx_messages_mailbox_headers; plan:\n%s", string(raw))
	assert.Empty(t, otherMessagesScans, "header SEARCH must not read messages any other way (heap filter or trigram GIN); plan:\n%s", string(raw))
	t.Logf("messages access: %v", indexOnly)
}

// TestHeaderSearchMatchesLiterally runs header searches against PostgreSQL and checks the
// semantics the index-only form must keep: substring match, case insensitive, NULL columns
// excluded, and LIKE metacharacters in the term taken literally.
func TestHeaderSearchMatchesLiterally(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	bs := imap.BodyStructure(&imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 100})
	bsBytes, err := helpers.SerializeBodyStructureGob(&bs)
	require.NoError(t, err)

	insertMsg := func(uid int64, subject, fromName, fromEmail string) {
		var fromNameArg any = fromName
		if fromName == "" {
			fromNameArg = nil
		}
		_, err := db.GetWritePool().Exec(ctx, `
			WITH inserted AS (
				INSERT INTO messages
				(account_id, mailbox_id, mailbox_path, uid, message_id, in_reply_to, content_hash, s3_domain, s3_localpart,
				 internal_date, size, subject, sent_date, body_structure, recipients_json, created_modseq,
				 subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort)
				VALUES ($1,$2,'INBOX',$3,$4,'',$5,'d',$6, now(), 100, $7, now(), $8, '[]'::jsonb, nextval('messages_modseq'),
				        $9, $10, $11, '', '', '')
				RETURNING id, mailbox_id
			)
			INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags)
			SELECT id, mailbox_id, 0, '[]'::jsonb FROM inserted`,
			accountID, mailboxID, uid, fmt.Sprintf("<%d@test>", uid), fmt.Sprintf("hash-%d", uid),
			fmt.Sprintf("lp-%d", uid), subject, bsBytes, normalizeForSort(subject), fromNameArg, fromEmail)
		require.NoError(t, err)
	}

	insertMsg(1, "Quarterly report", "equishark support", "support@equishark.com")
	insertMsg(2, "100% off everything", "", "promo@shop.example") // NULL from_name_sort
	insertMsg(3, "Re: order_42 shipped", "ann marie", "ann_marie@example.org")
	insertMsg(4, `C:\path\file`, "bob", "bob@example.org")

	search := func(t *testing.T, c *imap.SearchCriteria) []imap.UID {
		t.Helper()
		res, err := db.SearchMessagesWithCriteria(ctx, mailboxID, accountID, c, 0, 4)
		require.NoError(t, err)
		var uids []imap.UID
		for _, r := range res {
			uids = append(uids, r.UID)
		}
		return uids
	}
	header := func(key, value string) *imap.SearchCriteria {
		return &imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: key, Value: value}}}
	}

	assert.ElementsMatch(t, []imap.UID{1}, search(t, header("From", "Support@EQUISHARK.com")))
	assert.ElementsMatch(t, []imap.UID{1}, search(t, header("From", "equishark")), "matches the display name too")
	assert.ElementsMatch(t, []imap.UID{1}, search(t, header("Subject", "REPORT")), "subject substring, case-folded")
	assert.ElementsMatch(t, []imap.UID{3}, search(t, header("Subject", "re: ")))

	assert.ElementsMatch(t, []imap.UID{2}, search(t, header("Subject", "100%")))
	assert.ElementsMatch(t, []imap.UID{2}, search(t, header("Subject", "%")), "a lone % matches only the subject that literally contains one")
	assert.Empty(t, search(t, header("From", "%")), "no address contains a literal %")
	assert.ElementsMatch(t, []imap.UID{3}, search(t, header("From", "ann_marie")))
	assert.Empty(t, search(t, header("From", "ann_mari_")), "_ is not a single-character wildcard")
	assert.ElementsMatch(t, []imap.UID{3}, search(t, &imap.SearchCriteria{Text: []string{"order_42"}}))
	assert.Empty(t, search(t, &imap.SearchCriteria{Text: []string{"order_4_"}}))
	assert.ElementsMatch(t, []imap.UID{4}, search(t, header("Subject", `c:\path`)), "a backslash in the term is literal")

	assert.ElementsMatch(t, []imap.UID{2}, search(t, header("From", "promo@shop")), "NULL from_name_sort must not hide the email match")
	assert.Empty(t, search(t, header("From", "zzznomatchzzz")))
}

// incompressibleText returns n bytes of hex digest text. Btree index tuples are compressed
// inline before the 2704-byte limit is applied, so a fixture built from a repeated character
// shrinks to a few bytes and never trips it; only incompressible text proves the bound matters.
func incompressibleText(n int) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, "%x", md5.Sum([]byte(fmt.Sprint(i))))
	}
	return b.String()[:n]
}

// TestInsertBoundsHeaderColumns delivers a message with pathological headers through the
// real insert path and checks the stored columns are bounded, so the row fits the covering
// index's tuple limit. Without the bounds this INSERT fails with "index row size exceeds
// btree version 4 maximum" once migration 000052 is applied (proved red 2026-10-01 with the
// same incompressible fixture).
func TestInsertBoundsHeaderColumns(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 1024}
	now := time.Now()
	longSubject := "Re: " + incompressibleText(3000) + "ü" // 3 KB of subject, multibyte at the tail
	longAddr := incompressibleText(900) + "@example.com"
	_, _, err = db.InsertMessage(ctx, tx, &InsertMessageOptions{
		AccountID: accountID, MailboxID: mailboxID, MailboxName: "INBOX",
		S3Domain: "example.com", S3Localpart: "bounds", ContentHash: "boundshash",
		MessageID: "<bounds@example.com>", InternalDate: now, SentDate: now, Size: 1024,
		Subject: longSubject, BodyStructure: &bs,
		Recipients: []helpers.Recipient{
			{AddressType: "from", Name: incompressibleText(500), EmailAddress: longAddr},
			{AddressType: "to", Name: incompressibleText(500), EmailAddress: longAddr},
			{AddressType: "cc", EmailAddress: longAddr},
		},
	}, PendingUpload{InstanceID: "test", ContentHash: "boundshash", Size: 1024, AccountID: accountID})
	require.NoError(t, err, "a message with oversized headers must still be deliverable")
	require.NoError(t, tx.Commit(ctx))

	var subj, subjSort, fromName, fromEmail, toName, toEmail, ccEmail int
	err = db.GetReadPool().QueryRow(ctx, `
		SELECT octet_length(subject), octet_length(subject_sort), octet_length(from_name_sort), octet_length(from_email_sort),
		       octet_length(to_name_sort), octet_length(to_email_sort), octet_length(cc_email_sort)
		FROM messages WHERE mailbox_id = $1 AND content_hash = 'boundshash'`, mailboxID).Scan(&subj, &subjSort, &fromName, &fromEmail, &toName, &toEmail, &ccEmail)
	require.NoError(t, err)
	assert.LessOrEqual(t, subj, helpers.MaxSubjectBytes)
	assert.LessOrEqual(t, subjSort, helpers.MaxSubjectBytes)
	for name, n := range map[string]int{"from_name_sort": fromName, "from_email_sort": fromEmail, "to_name_sort": toName, "to_email_sort": toEmail, "cc_email_sort": ccEmail} {
		assert.LessOrEqual(t, n, helpers.MaxSortColumnBytes, name)
	}
	assert.Positive(t, subj, "the subject is truncated, not dropped")
}
