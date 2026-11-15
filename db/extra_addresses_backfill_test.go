package db

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExtraAddressesBackfillMatchesWriter runs the backfill function from
// scripts/backfill_extra_addresses.sql on rows the application wrote and checks it produces
// exactly the value the application stored, budget included. Everything runs in a
// transaction that is rolled back, so the script's functions never persist.
func TestExtraAddressesBackfillMatchesWriter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 100}
	many := []helpers.Recipient{{AddressType: "from", Name: "Sender", EmailAddress: "sender@example.com"}}
	for i := range 60 {
		many = append(many, helpers.Recipient{AddressType: "to", Name: fmt.Sprintf("Person Number %d", i), EmailAddress: fmt.Sprintf("person.number.%d@example.com", i)})
	}
	fixtures := map[string][]helpers.Recipient{
		"every":   everyAddressRecipients,
		"single":  {{AddressType: "from", EmailAddress: "a@example.com"}, {AddressType: "to", Name: "B", EmailAddress: "b@example.com"}},
		"cc-only": {{AddressType: "cc", Name: "Only Cc", EmailAddress: "cc@example.com"}},
		"tabbed":  {{AddressType: "to", EmailAddress: "x@example.com"}, {AddressType: "to", Name: "Tab\tAnd\nNewline", EmailAddress: "y@example.com"}},
		"bounded": many,
		"empty":   nil,
	}

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	base := time.Now().UnixNano()
	ids := map[string]int64{}
	for name, recipients := range fixtures {
		hash := fmt.Sprintf("backfill-%s-%d", name, base)
		id, _, err := db.InsertMessageFromImporter(ctx, tx, &InsertMessageOptions{
			AccountID: accountID, MailboxID: mailboxID, MailboxName: "INBOX",
			S3Domain: "example.com", S3Localpart: "backfill", ContentHash: hash,
			MessageID: "<" + hash + "@example.com>", InternalDate: time.Now(), SentDate: time.Now(),
			Size: 100, Subject: name, BodyStructure: &bs, Recipients: recipients,
		})
		require.NoError(t, err)
		ids[name] = id
	}

	script, err := os.ReadFile("../scripts/backfill_extra_addresses.sql")
	require.NoError(t, err)
	_, err = tx.Exec(ctx, string(script))
	require.NoError(t, err, "the backfill script must load as plain DDL")
	// A zero batch never advances hi; a negative one walks upwards forever.
	// Reject these before the procedure starts its transaction-control loop.
	for _, tc := range []struct {
		batch, sleep any
		want         string
	}{{0, 100, "p_batch must be positive"}, {-1, 100, "p_batch must be positive"}, {nil, 100, "p_batch must be positive"}, {5000, -1, "p_sleep_ms must not be negative"}, {5000, nil, "p_sleep_ms must not be negative"}} {
		_, err = tx.Exec(ctx, "SAVEPOINT invalid_settings")
		require.NoError(t, err)
		_, err = tx.Exec(ctx, "CALL sora_backfill_extra_addresses(NULL, $1, $2)", tc.batch, tc.sleep)
		require.ErrorContains(t, err, tc.want)
		_, err = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT invalid_settings")
		require.NoError(t, err)
	}

	for name, id := range ids {
		var stored, backfilled string
		var budgetOK bool
		err := tx.QueryRow(ctx, `
			SELECT COALESCE(extra_addresses, '<NULL>'), COALESCE(sora_extra_addresses(recipients_json, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort), '<NULL>'),
			       octet_length(extra_addresses) + octet_length(from_name_sort) + octet_length(from_email_sort)
			       + octet_length(to_name_sort) + octet_length(to_email_sort) + octet_length(cc_email_sort) <= $2
			FROM messages m WHERE id = $1`, id, helpers.MaxAddressColumnsBytes).Scan(&stored, &backfilled, &budgetOK)
		require.NoError(t, err, name)
		assert.Equal(t, stored, backfilled, "%s: the backfill must compute what the application writes", name)
		assert.True(t, budgetOK, "%s: the address columns must stay within their shared budget", name)
	}

	// The batch function fills NULL rows only, and only where there is something to store.
	_, err = tx.Exec(ctx, `UPDATE messages SET extra_addresses = NULL WHERE id = ANY($1)`, []int64{ids["every"], ids["single"]})
	require.NoError(t, err)
	var updated int64
	require.NoError(t, tx.QueryRow(ctx, `SELECT sora_backfill_extra_addresses_batch($1, $2)`, ids["every"], ids["every"]).Scan(&updated))
	assert.EqualValues(t, 1, updated)
	require.NoError(t, tx.QueryRow(ctx, `SELECT sora_backfill_extra_addresses_batch($1, $2)`, ids["single"], ids["single"]).Scan(&updated))
	assert.EqualValues(t, 0, updated, "a row with no further addresses is left NULL: no non-HOT update for nothing")
	var got string
	require.NoError(t, tx.QueryRow(ctx, `SELECT extra_addresses FROM messages WHERE id = $1`, ids["every"]).Scan(&got))
	assert.Equal(t, "frank author\tfrank@example.com\nbob example\tbob@example.com\ndave copy\terin@example.org", got)
}
