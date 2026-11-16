//go:build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/testutils"
	"github.com/stretchr/testify/require"
)

func TestMessagesRepairHeaderPresence(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
	require.NoError(t, err)
	require.NoError(t, rdb.CreateMailboxWithRetry(ctx, accountID, "Copies", nil))
	inbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	require.NoError(t, err)
	copies, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "Copies")
	require.NoError(t, err)

	original := insertAdminTestMessage(t, ctx, rdb, accountID, inbox.ID, inbox.Name, "hp-original")
	first := insertAdminTestMessage(t, ctx, rdb, accountID, copies.ID, copies.Name, "hp-first")
	second := insertAdminTestMessage(t, ctx, rdb, accountID, copies.ID, copies.Name, "hp-second")
	s3Only := insertAdminTestMessage(t, ctx, rdb, accountID, copies.ID, copies.Name, "hp-s3only")
	unuploaded := insertAdminTestMessage(t, ctx, rdb, accountID, copies.ID, copies.Name, "hp-pending")

	pool := rdb.GetOperationalDatabase().GetWritePool()
	fromBit, _ := helpers.HeaderPresenceBit("from")
	ccBit, _ := helpers.HeaderPresenceBit("cc")
	subjectBit, _ := helpers.HeaderPresenceBit("subject")
	donorMask := fromBit | ccBit
	s3Mask := fromBit | subjectBit

	_, err = pool.Exec(ctx, `UPDATE messages SET header_presence = $1 WHERE id = $2`, donorMask, original)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		UPDATE messages SET content_hash = (SELECT content_hash FROM messages WHERE id = $1), header_presence = NULL
		WHERE id = ANY($2)`, original, []int64{first, second})
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE messages SET header_presence = NULL, uploaded = true WHERE id = $1`, s3Only)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE messages SET header_presence = NULL, uploaded = false WHERE id = $1`, unuploaded)
	require.NoError(t, err)

	// Stage the S3 object for s3Only in a FileBasedS3Mock.
	var s3Dom, s3Loc, s3Hash string
	require.NoError(t, pool.QueryRow(ctx, `SELECT s3_domain, s3_localpart, content_hash FROM messages WHERE id = $1`, s3Only).Scan(&s3Dom, &s3Loc, &s3Hash))
	mockS3, err := testutils.NewFileBasedS3Mock(t.TempDir())
	require.NoError(t, err)
	rawBody := []byte("From: a@example.com\r\nSubject:\r\n\r\nCc: in-body-only@example.com\r\n")
	require.NoError(t, mockS3.Put(helpers.NewS3Key(s3Dom, s3Loc, s3Hash), bytes.NewReader(rawBody), int64(len(rawBody))))

	presence := func(id int64) *int16 {
		t.Helper()
		var v *int16
		require.NoError(t, pool.QueryRow(ctx, `SELECT header_presence FROM messages WHERE id = $1`, id).Scan(&v))
		return v
	}
	start := strconv.FormatInt(original-1, 10)

	// 1. Dry run without --from-s3: DB donors only, changes nothing.
	out := runMessagesRepairHeaderPresence(t, ctx, nil, "--start-after", start, "--batch-size", "1")
	for _, id := range []int64{original, first, second, s3Only, unuploaded} {
		require.Contains(t, out, fmt.Sprintf("(resume with --start-after %d)", id))
	}
	fillable, dbFills, s3Fills, cannot := repairHeaderPresenceTotals(t, out)
	require.GreaterOrEqual(t, fillable, 2)
	require.GreaterOrEqual(t, dbFills, 2)
	require.Equal(t, 0, s3Fills)
	require.GreaterOrEqual(t, cannot, 2)
	require.Contains(t, out, "Dry run: nothing was changed. Run again with --apply to fill them.")
	for _, id := range []int64{first, second, s3Only, unuploaded} {
		require.Nil(t, presence(id))
	}

	// 2. Resumed after first without --from-s3: fills second from DB donor, leaves first & s3Only NULL.
	out = runMessagesRepairHeaderPresence(t, ctx, nil, "--start-after", strconv.FormatInt(first, 10), "--apply")
	require.Contains(t, out, "Filled ")
	require.Nil(t, presence(first))
	require.Equal(t, &donorMask, presence(second))
	require.Nil(t, presence(s3Only))
	require.Nil(t, presence(unuploaded))

	// 3. With --from-s3 --apply from start: fills first from DB donor and s3Only from S3 header block;
	// unuploaded has no S3 object yet so stays NULL.
	out = runMessagesRepairHeaderPresence(t, ctx, mockS3, "--start-after", start, "--from-s3", "--apply")
	_, dbFills, s3Fills, _ = repairHeaderPresenceTotals(t, out)
	require.GreaterOrEqual(t, dbFills, 1)
	require.GreaterOrEqual(t, s3Fills, 1)
	require.Equal(t, &donorMask, presence(first))
	require.Equal(t, &s3Mask, presence(s3Only))
	require.Nil(t, presence(unuploaded))
}

func repairHeaderPresenceTotals(t *testing.T, out string) (fillable, dbFills, s3Fills, cannot int) {
	t.Helper()
	m := regexp.MustCompile(`(\d+) can be filled \((\d+) from DB, (\d+) from S3\), (\d+) cannot\.`).FindStringSubmatch(out)
	require.NotNil(t, m, "summary line missing in:\n%s", out)
	fillable, _ = strconv.Atoi(m[1])
	dbFills, _ = strconv.Atoi(m[2])
	s3Fills, _ = strconv.Atoi(m[3])
	cannot, _ = strconv.Atoi(m[4])
	return
}

func runMessagesRepairHeaderPresence(t *testing.T, ctx context.Context, mockS3 objectStorage, flags ...string) string {
	t.Helper()
	prevCfg, prevArgs, prevEvery, prevNewS3 := globalConfig, os.Args, repairHeaderPresenceProgressEvery, newRepairHeaderPresenceStorage
	t.Cleanup(func() {
		globalConfig, os.Args, repairHeaderPresenceProgressEvery, newRepairHeaderPresenceStorage = prevCfg, prevArgs, prevEvery, prevNewS3
	})
	repairHeaderPresenceProgressEvery = 0
	if mockS3 != nil {
		newRepairHeaderPresenceStorage = func(_ config.S3Config) (objectStorage, error) {
			return mockS3, nil
		}
	}
	name := os.Getenv("SORA_TEST_DB_NAME")
	if name == "" {
		name = "sora_test_db"
	}
	globalConfig.Database = config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
		Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: name,
	}}
	os.Args = append([]string{"sora-admin", "messages", "repair-header-presence"}, flags...)
	out := captureStdout(t, func() error {
		handleRepairHeaderPresence(ctx)
		return nil
	})
	t.Logf("%s\n%s", strings.Join(os.Args[2:], " "), out)
	return out
}
