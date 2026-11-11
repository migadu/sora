//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// A default database row cap must never turn an incomplete search into OK.
// Exercise the real cap and wire handlers: exactly the cap succeeds, one more
// match is refused, and an explicit caller limit still means a bounded page.
// Every refusal is counted in sora_imap_search_refused_total{reason="result_cap"},
// since it is otherwise invisible to the operator.
func TestIMAP_SearchOverflowIsLimit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	srv, account := common.SetupIMAPServer(t)
	defer srv.Close()
	c := dialRawIMAP(t, srv.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	ctx := context.Background()
	database := srv.ResilientDB.GetDatabase()
	mailboxID, accountID := seedMatchingMessages(t, c, database, account.Email, "Overflow", db.MaxSearchResults+1)
	c.do("SELECT Overflow")

	// ALL remains exempt, and an exact-cap filtered search is complete.
	all, _ := c.do("UID SEARCH RETURN (COUNT MIN MAX) ALL")
	require.Contains(t, strings.Join(all, " "), fmt.Sprintf("MIN 1 MAX %d COUNT %d", db.MaxSearchResults+1, db.MaxSearchResults+1))
	exact, _ := c.do(fmt.Sprintf("UID SEARCH RETURN (COUNT MIN MAX) UID 2:%d", db.MaxSearchResults+1))
	require.Contains(t, strings.Join(exact, " "), fmt.Sprintf("MIN 2 MAX %d COUNT %d", db.MaxSearchResults+1, db.MaxSearchResults))

	for _, command := range []string{
		"UID SEARCH SUBJECT match",
		"UID SEARCH RETURN (COUNT MIN MAX) SUBJECT match",
		"UID SORT (SUBJECT) UTF-8 SUBJECT match",
		"UID SORT RETURN (COUNT MIN MAX) (SUBJECT) UTF-8 SUBJECT match",
		"ESEARCH IN (SELECTED) RETURN (COUNT MIN MAX) SUBJECT match",
	} {
		t.Run(command, func(t *testing.T) {
			before := searchRefusedCount(t, "result_cap")
			untagged, tagged := c.read(c.send(command), command)
			require.Contains(t, tagged, " NO [LIMIT] ", "must refuse overflow rather than acknowledge partial results")
			for _, line := range untagged {
				require.False(t, strings.HasPrefix(line, "* SEARCH") || strings.HasPrefix(line, "* SORT") || strings.HasPrefix(line, "* ESEARCH"), "partial result leaked: %s", line)
			}
			require.Equal(t, before+1, searchRefusedCount(t, "result_cap"), `sora_imap_search_refused_total{reason="result_cap"} must count the refusal`)
		})
	}

	for _, command := range []string{
		"UID SEARCH RETURN (SAVE) SUBJECT match",
		"ESEARCH IN (SELECTED) RETURN (SAVE) SUBJECT match",
	} {
		t.Run(command, func(t *testing.T) {
			c.do("UID SEARCH RETURN (SAVE) UID 1")
			require.Len(t, c.fetchDollarUIDs(), 1)
			before := searchRefusedCount(t, "result_cap")
			require.Contains(t, c.status(command), "NO [LIMIT] ")
			require.Equal(t, before+1, searchRefusedCount(t, "result_cap"), `sora_imap_search_refused_total{reason="result_cap"} must count the refusal`)
			require.Empty(t, c.fetchDollarUIDs(), "failed SAVE must empty the old saved result")
		})
	}

	page, err := database.SearchMessagesWithCriteria(ctx, mailboxID, accountID, &imap.SearchCriteria{}, 2, db.MaxSearchResults+1)
	require.NoError(t, err, "an explicit caller limit is a page, not a complete search")
	require.Len(t, page, 2)
}

// DISPLAYFROM and DISPLAYTO sorts once carried a 500-row cap for the JSONB
// subselects they ordered by. Those are indexed columns now, and the cap is
// gone: a body-scope search sorted by display name with more than 500 matches
// is complete and succeeds, instead of being refused as an overflow.
func TestIMAP_SortByDisplayNameIsNotCappedAt500(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	srv, account := common.SetupIMAPServer(t)
	defer srv.Close()
	c := dialRawIMAP(t, srv.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	const matches = 501
	seedMatchingMessages(t, c, srv.ResilientDB.GetDatabase(), account.Email, "Display", matches)
	c.do("SELECT Display")

	untagged, tagged := c.do("UID SORT (DISPLAYFROM) UTF-8 TEXT match")
	require.Contains(t, tagged, " OK ", "a %d-match display sort is complete, not an overflow", matches)
	var sorted []string
	for _, line := range untagged {
		if strings.HasPrefix(line, "* SORT ") {
			sorted = append(sorted, strings.Fields(line)[2:]...)
		}
	}
	require.Len(t, sorted, matches)

	untagged, tagged = c.do("UID SORT RETURN (COUNT) (DISPLAYTO) UTF-8 OR SUBJECT match TEXT match")
	require.Contains(t, tagged, " OK ")
	require.Contains(t, strings.Join(untagged, " "), fmt.Sprintf("COUNT %d", matches))
}

// searchRefusedCount reads sora_imap_search_refused_total{reason} from the default
// registry, which the in-process server shares with the test. It finds the metric
// by name, so that a build without the metric reads 0 rather than failing to compile.
func searchRefusedCount(t *testing.T, reason string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != "sora_imap_search_refused_total" {
			continue
		}
		for _, m := range family.GetMetric() {
			if labelValue(m, "reason") == reason {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// seedMatchingMessages creates mailbox name holding n messages that match
// SUBJECT "match" and FROM sender@example.com: one real APPEND, cloned in SQL.
// The rows are deleted when the test ends, so a shared test database does not
// grow by n messages per run.
func seedMatchingMessages(t *testing.T, c *rawIMAP, database *db.Database, email, name string, n int) (mailboxID, accountID int64) {
	t.Helper()
	ctx := context.Background()
	c.do("CREATE " + name)
	c.appendMsg(name, "From: sender@example.com\r\nSubject: match\r\n\r\nbody\r\n")
	require.NoError(t, database.GetWritePool().QueryRow(ctx, `
		SELECT m.id, m.account_id FROM mailboxes m JOIN credentials c ON c.account_id = m.account_id
		WHERE m.name = $2 AND c.address = $1`, email, name).Scan(&mailboxID, &accountID))
	t.Cleanup(func() {
		_, err := database.GetWritePool().Exec(context.Background(), "DELETE FROM messages WHERE mailbox_id = $1", mailboxID)
		require.NoError(t, err)
	})
	_, err := database.GetWritePool().Exec(ctx, `
		INSERT INTO messages
		(account_id, mailbox_id, mailbox_path, uid, message_id, in_reply_to, content_hash, s3_domain, s3_localpart,
		 internal_date, size, subject, sent_date, body_structure, recipients_json, created_modseq,
		 subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort)
		SELECT m.account_id, m.mailbox_id, m.mailbox_path, s, '<seed-'||s||'@example.com>', '',
		 m.content_hash, m.s3_domain, m.s3_localpart, m.internal_date, m.size, m.subject, m.sent_date,
		 m.body_structure, m.recipients_json, nextval('messages_modseq'), m.subject_sort, m.from_name_sort,
		 m.from_email_sort, m.to_name_sort, m.to_email_sort, m.cc_email_sort
		FROM messages m CROSS JOIN generate_series(2, $2::integer) s
		WHERE m.mailbox_id = $1 AND m.uid = 1`, mailboxID, n)
	require.NoError(t, err)
	_, err = database.GetWritePool().Exec(ctx, "UPDATE mailboxes SET highest_uid = $2 WHERE id = $1", mailboxID, n)
	require.NoError(t, err)
	// Direct bulk seeding must publish realistic planner statistics as well as
	// mailbox state; these tests are about completeness, not a stale-statistics plan.
	_, err = database.GetWritePool().Exec(ctx, "ANALYZE messages")
	require.NoError(t, err)
	return mailboxID, accountID
}
