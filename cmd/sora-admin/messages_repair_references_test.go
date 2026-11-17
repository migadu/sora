//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// TestMessagesRepairReferences: "messages repair-references" counts the live rows whose
// "references" is NULL and how many of them another row with the same body can fill,
// changes nothing until --apply is given, then fills them, and resumes after the id
// --start-after names. The scan reads the whole table after the cursor, which other test
// packages share, so the totals are checked as lower bounds and the rows of this test
// exactly.
func TestMessagesRepairReferences(t *testing.T) {
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

	original := insertAdminTestMessage(t, ctx, rdb, accountID, inbox.ID, inbox.Name, "original")
	first := insertAdminTestMessage(t, ctx, rdb, accountID, copies.ID, copies.Name, "first")
	second := insertAdminTestMessage(t, ctx, rdb, accountID, copies.ID, copies.Name, "second")
	orphan := insertAdminTestMessage(t, ctx, rdb, accountID, copies.ID, copies.Name, "orphan")
	pool := rdb.GetOperationalDatabase().GetWritePool()
	// The original holds its References; the two copies share its body and hold NULL, as
	// COPY and MOVE wrote them before #837. The orphan's body is held by no other row.
	_, err = pool.Exec(ctx, `UPDATE messages SET "references" = 'q@example.com r@example.com' WHERE id = $1`, original)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		UPDATE messages SET content_hash = (SELECT content_hash FROM messages WHERE id = $1), "references" = NULL
		WHERE id = ANY($2)`, original, []int64{first, second})
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE messages SET "references" = NULL WHERE id = $1`, orphan)
	require.NoError(t, err)
	references := func(id int64) *string {
		t.Helper()
		var v *string
		require.NoError(t, pool.QueryRow(ctx, `SELECT "references" FROM messages WHERE id = $1`, id).Scan(&v))
		return v
	}
	filled := "q@example.com r@example.com"
	start := strconv.FormatInt(original-1, 10)

	// Dry run, one row per batch: every batch prints where to resume, nothing changes.
	out := runMessagesRepairReferences(t, ctx, "--start-after", start, "--batch-size", "1")
	for _, id := range []int64{original, first, second, orphan} {
		require.Contains(t, out, fmt.Sprintf("(resume with --start-after %d)", id))
	}
	fillable, cannot := repairReferencesTotals(t, out)
	require.GreaterOrEqual(t, fillable, 2, "both copies can be filled from the original")
	require.GreaterOrEqual(t, cannot, 1, "the orphan cannot")
	require.Contains(t, out, "Dry run: nothing was changed. Run again with --apply to fill them.")
	for _, id := range []int64{first, second, orphan} {
		require.Nil(t, references(id), "a dry run changes nothing (row %d)", id)
	}

	// Resumed after the first copy, --apply fills only what follows it.
	out = runMessagesRepairReferences(t, ctx, "--start-after", strconv.FormatInt(first, 10), "--apply")
	require.Contains(t, out, "Filled ")
	require.Nil(t, references(first), "before the cursor")
	require.Equal(t, &filled, references(second))
	require.Nil(t, references(orphan), "no donor: stays NULL")

	// From the start, it fills the first copy too.
	runMessagesRepairReferences(t, ctx, "--start-after", start, "--apply")
	require.Equal(t, &filled, references(first))
	require.Equal(t, &filled, references(original))
	require.Nil(t, references(orphan))
}

// TestMessagesRepairReferencesRejectsPositionalArgs: unexpected positional arguments
// (such as "apply" without "--" or trailing words after "--apply") must fail with a
// non-zero exit status before connecting to or modifying the database.
func TestMessagesRepairReferencesRejectsPositionalArgs(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()

	account := common.CreateTestAccount(t, rdb)
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
	require.NoError(t, err)
	inbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	require.NoError(t, err)

	donor := insertAdminTestMessage(t, ctx, rdb, accountID, inbox.ID, inbox.Name, "pos-donor")
	target := insertAdminTestMessage(t, ctx, rdb, accountID, inbox.ID, inbox.Name, "pos-target")
	pool := rdb.GetOperationalDatabase().GetWritePool()
	_, err = pool.Exec(ctx, `UPDATE messages SET "references" = 'donor@example.com' WHERE id = $1`, donor)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		UPDATE messages SET content_hash = (SELECT content_hash FROM messages WHERE id = $1), "references" = NULL
		WHERE id = $2`, donor, target)
	require.NoError(t, err)

	name := os.Getenv("SORA_TEST_DB_NAME")
	if name == "" {
		name = "sora_test_db"
	}
	configPath := filepath.Join(t.TempDir(), "config.toml")
	configBody := fmt.Sprintf("[database.write]\nhosts = [\"localhost\"]\nport = 5432\nuser = \"postgres\"\nname = %q\n", name)
	require.NoError(t, os.WriteFile(configPath, []byte(configBody), 0o600))

	start := strconv.FormatInt(donor-1, 10)
	for _, tc := range []struct {
		name   string
		args   []string
		badArg string
	}{
		{
			name:   "apply without dashes",
			args:   []string{"--config", configPath, "messages", "repair-references", "apply"},
			badArg: "apply",
		},
		{
			name:   "positional arg after flags",
			args:   []string{"--config", configPath, "messages", "repair-references", "--start-after", start, "apply"},
			badArg: "apply",
		},
		{
			name:   "trailing arg after --apply",
			args:   []string{"--config", configPath, "messages", "repair-references", "--start-after", start, "--apply", "extra"},
			badArg: "extra",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, code := runAdminMain(t, tc.args...)
			require.NotEqual(t, 0, code, "unexpected positional argument must exit non-zero:\n%s", out)
			require.Contains(t, out, fmt.Sprintf("Error: unexpected argument %q", tc.badArg))
			require.Contains(t, out, "Usage:")
			require.NotContains(t, out, "Checked ")

			var refs *string
			require.NoError(t, pool.QueryRow(ctx, `SELECT "references" FROM messages WHERE id = $1`, target).Scan(&refs))
			require.Nil(t, refs, "database must remain untouched when positional arguments are rejected")
		})
	}
}

// repairReferencesTotals reads the fillable and unfillable totals from the summary line
// of "messages repair-references".
func repairReferencesTotals(t *testing.T, out string) (fillable, cannot int) {
	t.Helper()
	m := regexp.MustCompile(`(\d+) can be filled from another row with the same body, (\d+) cannot`).FindStringSubmatch(out)
	require.NotNil(t, m, "summary line missing")
	fillable, _ = strconv.Atoi(m[1])
	cannot, _ = strconv.Atoi(m[2])
	return fillable, cannot
}

// runMessagesRepairReferences runs "sora-admin messages repair-references" against the
// test database, with a progress line after every batch, and returns what it printed.
func runMessagesRepairReferences(t *testing.T, ctx context.Context, flags ...string) string {
	t.Helper()
	previousConfig, previousArgs, previousEvery := globalConfig, os.Args, repairReferencesProgressEvery
	t.Cleanup(func() {
		globalConfig, os.Args, repairReferencesProgressEvery = previousConfig, previousArgs, previousEvery
	})
	repairReferencesProgressEvery = 0
	name := os.Getenv("SORA_TEST_DB_NAME")
	if name == "" {
		name = "sora_test_db"
	}
	globalConfig.Database = config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
		Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: name,
	}}
	os.Args = append([]string{"sora-admin", "messages", "repair-references"}, flags...)
	out := captureStdout(t, func() error {
		handleRepairReferences(ctx)
		return nil
	})
	t.Logf("%s\n%s", strings.Join(os.Args[2:], " "), out)
	return out
}
