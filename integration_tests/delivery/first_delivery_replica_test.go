//go:build integration

package delivery_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/delivery"
	"github.com/stretchr/testify/require"
)

// TestDelivery_FirstDeliveryReadsTheDefaultMailboxesFromTheWriter is issue #474: the
// first Admin API delivery to an account that has never logged in or received mail
// creates its default mailboxes (LookupRecipient, on the writer) and must then find
// them, as LMTP does by reading from the writer for the rest of the delivery. Read
// from a replica that has not replayed the create, INBOX does not exist yet and the
// delivery failed with "mailbox not found".
//
// The read pool is a migrated database holding only the account and its credentials:
// a replica that has replayed the account's creation but none of this delivery's
// writes. The calls are the ones the Admin API makes for each recipient.
func TestDelivery_FirstDeliveryReadsTheDefaultMailboxesFromTheWriter(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()

	replica := laggingReplicaDB(t)
	lagged, err := resilient.NewResilientDatabase(ctx, &config.DatabaseConfig{
		Write: testDBEndpoint(testDBName()),
		Read:  testDBEndpoint(replica),
	}, false, false)
	require.NoError(t, err)
	t.Cleanup(lagged.Close)

	fake := common.NewFakeS3()
	t.Cleanup(fake.Close)
	uploader := common.NewSyncUploaderWithS3(t, rdb, fake, "first-delivery-host")

	cases := []struct {
		name   string
		header string // an extra header line
		want   string
	}{
		{name: "INBOX", want: "INBOX"},
		// The default script files spam into Junk, another default mailbox.
		{name: "Junk", header: "X-Spam: Yes\r\n", want: "Junk"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			email := fmt.Sprintf("first-delivery-%d-%d@example.com", i, common.GetTimestamp())
			accountID, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
				Email: email, Password: "password", HashType: "bcrypt", IsPrimary: true,
			})
			require.NoError(t, err)
			mailboxes, err := rdb.GetMailboxesWithRetry(ctx, accountID, false)
			require.NoError(t, err)
			require.Empty(t, mailboxes, "the account must not have its default mailboxes yet")
			replicateAccount(t, rdb, replica, accountID)

			dctx := &delivery.DeliveryContext{
				Ctx:          ctx,
				RDB:          lagged,
				Uploader:     uploader,
				Hostname:     "first-delivery-host",
				MetricsLabel: "http_delivery",
				Logger:       testLogger{t},
			}
			dctx.SieveExecutor = &delivery.StandardSieveExecutor{
				DeliveryCtx:    dctx,
				VacationOracle: &delivery.VacationOracle{RDB: lagged},
			}

			recipient, err := dctx.LookupRecipient(ctx, email)
			require.NoError(t, err)
			require.Equal(t, accountID, recipient.AccountID)

			subject := fmt.Sprintf("first-delivery-%d", common.GetTimestamp())
			msg := []byte("From: sender@example.com\r\nTo: " + email + "\r\nSubject: " + subject +
				"\r\nMessage-ID: <" + subject + "@example.com>\r\n" + tc.header + "\r\nbody\r\n")
			res, err := dctx.DeliverMessage(*recipient, msg)
			require.NoError(t, err, "delivery failed (result=%+v)", res)
			require.Equal(t, tc.want, res.MailboxName)
			require.Equal(t, 1, countLiveInMailbox(t, rdb, accountID, tc.want))
		})
	}
}

// replicateAccount copies the account's row and credentials from the writer into the
// replica database, as replication of the account's creation would, and removes them
// again when the test ends so the replica stays empty for the other tests.
func replicateAccount(t *testing.T, rdb *resilient.ResilientDatabase, replica string, accountID int64) {
	t.Helper()
	ctx := context.Background()

	type credential struct {
		address, password string
		primary           bool
	}
	var creds []credential
	rows, err := rdb.QueryWithRetry(ctx,
		`SELECT address, password, primary_identity FROM credentials WHERE account_id = $1`, accountID)
	require.NoError(t, err)
	for rows.Next() {
		var c credential
		require.NoError(t, rows.Scan(&c.address, &c.password, &c.primary))
		creds = append(creds, c)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.NotEmpty(t, creds)

	conn, err := pgx.Connect(ctx, fmt.Sprintf("postgres://postgres@localhost:5432/%s?sslmode=disable", replica))
	require.NoError(t, err)
	defer conn.Close(ctx)

	remove := func(conn *pgx.Conn) error {
		if _, err := conn.Exec(ctx, `DELETE FROM credentials WHERE account_id = $1`, accountID); err != nil {
			return err
		}
		_, err := conn.Exec(ctx, `DELETE FROM accounts WHERE id = $1`, accountID)
		return err
	}
	require.NoError(t, remove(conn)) // a leftover of an interrupted run
	_, err = conn.Exec(ctx, `INSERT INTO accounts (id) VALUES ($1)`, accountID)
	require.NoError(t, err)
	for _, c := range creds {
		_, err = conn.Exec(ctx, `INSERT INTO credentials (account_id, address, password, primary_identity) VALUES ($1, $2, $3, $4)`,
			accountID, c.address, c.password, c.primary)
		require.NoError(t, err)
	}

	t.Cleanup(func() {
		conn, err := pgx.Connect(ctx, fmt.Sprintf("postgres://postgres@localhost:5432/%s?sslmode=disable", replica))
		if err != nil {
			t.Errorf("connect to %s: %v", replica, err)
			return
		}
		defer conn.Close(ctx)
		if err := remove(conn); err != nil {
			t.Errorf("remove account %d from %s: %v", accountID, replica, err)
		}
	})
}
