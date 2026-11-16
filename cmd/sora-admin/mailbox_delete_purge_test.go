//go:build integration

package main

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

const deletePurgeHelperEnv = "SORA_ADMIN_DELETE_PURGE_HELPER_EMAIL"

// TestMailboxDeletePurgeCommandHelper is not a test: it is `sora-admin mailbox delete
// --purge`, run by TestMailboxDeletePurgeNeedsNoS3 in a process of its own because the
// command exits. Its [s3] section cannot build a client.
func TestMailboxDeletePurgeCommandHelper(t *testing.T) {
	email := os.Getenv(deletePurgeHelperEnv)
	if email == "" {
		t.Skip("helper process for TestMailboxDeletePurgeNeedsNoS3")
	}
	name := os.Getenv("SORA_TEST_DB_NAME")
	if name == "" {
		name = "sora_test_db"
	}
	globalConfig.Database = config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
		Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: name,
	}}
	globalConfig.S3 = config.S3Config{Timeout: "not-a-duration", Encrypt: true, EncryptionKey: "not-a-key"}
	os.Args = []string{"sora-admin", "mailbox", "delete", "--email", email,
		"--mailbox", "PurgeMe", "--confirm", "--purge"}
	handleMailboxDelete(context.Background())
}

// TestMailboxDeletePurgeNeedsNoS3 (#316 item 6): --purge only expunges rows (the cleaner
// reclaims the objects), so an [s3] section that cannot build a client must not stop it.
func TestMailboxDeletePurgeNeedsNoS3(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
	require.NoError(t, err)
	require.NoError(t, rdb.CreateMailboxWithRetry(ctx, accountID, "PurgeMe", nil))

	cmd := exec.Command(os.Args[0], "-test.run=^TestMailboxDeletePurgeCommandHelper$")
	cmd.Env = append(os.Environ(), deletePurgeHelperEnv+"="+account.Email)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "mailbox delete --purge failed:\n%s", out)

	_, err = rdb.GetMailboxByNameWithRetry(ctx, accountID, "PurgeMe")
	require.ErrorIs(t, err, consts.ErrMailboxNotFound, "the mailbox was not deleted:\n%s", out)
}
