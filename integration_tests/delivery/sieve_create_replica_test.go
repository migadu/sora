//go:build integration

package delivery_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/stretchr/testify/require"
)

// TestDelivery_SieveCreateReadsTheNewMailboxFromTheWriter: a fileinto :create target
// is created on the writer, so the delivery must read it back from there. Reads
// otherwise go to the read pool, and a replica that has not replayed the create yet
// does not have the mailbox, nor (for a new account) even INBOX to fall back to.
//
// The read pool here is a migrated but empty database: a replica that has replayed
// none of the account's writes, which every read issued after the create would hit
// were it not pinned to the writer.
func TestDelivery_SieveCreateReadsTheNewMailboxFromTheWriter(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()

	account := common.CreateTestAccount(t, rdb)
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	lagged, err := resilient.NewResilientDatabase(ctx, &config.DatabaseConfig{
		Write: testDBEndpoint(testDBName()),
		Read:  testDBEndpoint(laggingReplicaDB(t)),
	}, false, false)
	require.NoError(t, err)
	t.Cleanup(lagged.Close)

	fake := common.NewFakeS3()
	t.Cleanup(fake.Close)
	dctx := &delivery.DeliveryContext{
		Ctx:          ctx,
		RDB:          lagged,
		Uploader:     common.NewSyncUploaderWithS3(t, rdb, fake, "replica-delivery-host"),
		Hostname:     "replica-delivery-host",
		MetricsLabel: "http_delivery",
		Logger:       testLogger{t},
	}
	dctx.SieveExecutor = &delivery.StandardSieveExecutor{
		DeliveryCtx:    dctx,
		VacationOracle: &delivery.VacationOracle{RDB: lagged},
	}

	// No user script (the replica has none either): the default script files a
	// +detail recipient with fileinto :create "${detail}".
	primary, err := server.NewAddress(account.Email)
	require.NoError(t, err)
	to, err := server.NewAddress(primary.LocalPart() + "+receipts@" + primary.Domain())
	require.NoError(t, err)
	subject := fmt.Sprintf("replica-create-%d", common.GetTimestamp())
	msg := []byte("From: sender@example.com\r\nTo: " + to.FullAddress() +
		"\r\nSubject: " + subject + "\r\nMessage-ID: <" + subject + "@example.com>\r\n\r\nbody\r\n")

	res, err := dctx.DeliverMessage(delivery.RecipientInfo{AccountID: accountID, Address: &primary, ToAddress: &to}, msg)
	require.NoError(t, err, "delivery failed (result=%+v)", res)
	require.Equal(t, "receipts", res.MailboxName)
	require.Equal(t, 1, countLiveInMailbox(t, rdb, accountID, "receipts"))
}

// testDBName is the database common.SetupTestDatabase uses.
func testDBName() string {
	if name := os.Getenv("SORA_TEST_DB_NAME"); name != "" {
		return name
	}
	return "sora_test_db"
}

func testDBEndpoint(name string) *config.DatabaseEndpointConfig {
	return &config.DatabaseEndpointConfig{Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: name}
}

// laggingReplicaDB returns a database with the current schema and no rows, creating
// and migrating it if needed. Nothing writes to it but replicateAccount, which removes
// what it adds when its test ends.
func laggingReplicaDB(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	name := testDBName() + "_replica"

	admin, err := pgx.Connect(ctx, "postgres://postgres@localhost:5432/postgres?sslmode=disable")
	require.NoError(t, err)
	defer admin.Close(ctx)
	var exists bool
	require.NoError(t, admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", name).Scan(&exists))
	if !exists {
		if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			require.ErrorContains(t, err, "already exists") // another package created it first
		}
	}

	migrated, err := resilient.NewResilientDatabase(ctx, &config.DatabaseConfig{Write: testDBEndpoint(name)}, false, true)
	require.NoError(t, err, "migrate %s", name)
	migrated.Close()
	return name
}
