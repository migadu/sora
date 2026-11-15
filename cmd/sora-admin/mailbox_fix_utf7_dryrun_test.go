//go:build integration

package main

import (
	"context"
	"regexp"
	"sort"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

var (
	fixUTF7RenameLineRe = regexp.MustCompile(`(?m)^\s+(?:WOULD RENAME|OK)\s+account_id=\d+\s+(".*")\s+->\s+(".*")$`)
	fixUTF7FailLineRe   = regexp.MustCompile(`(?m)^\s+(?:WOULD FAIL|FAIL)\s+account_id=\d+\s+(".*")\s+->\s+(".*")\s+\(error:\s+(.*)\)$`)
)

func parseFixUTF7Renames(out string) []string {
	var got []string
	for _, m := range fixUTF7RenameLineRe.FindAllStringSubmatch(out, -1) {
		got = append(got, m[1]+" -> "+m[2])
	}
	sort.Strings(got)
	return got
}

func parseFixUTF7Failures(out string) []string {
	var got []string
	for _, m := range fixUTF7FailLineRe.FindAllStringSubmatch(out, -1) {
		got = append(got, m[1]+" -> "+m[2]+" ("+m[3]+")")
	}
	sort.Strings(got)
	return got
}

func TestMailboxFixUTF7DryRunParityOnRefusedRenames(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()

	t.Run("shared namespace boundary refusal in both directions with descendants", func(t *testing.T) {
		previousConfig := globalConfig
		t.Cleanup(func() { globalConfig = previousConfig })
		globalConfig.SharedMailboxes = config.SharedMailboxesConfig{
			Enabled:         true,
			NamespacePrefix: "Partagés/",
			DefaultRights:   "lrswipkxtea",
		}
		sharedCtx := context.WithValue(ctx, consts.ConfigContextKey, &config.Config{
			SharedMailboxes: globalConfig.SharedMailboxes,
		})

		account := common.CreateTestAccount(t, rdb)
		accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
		require.NoError(t, err)

		// 1. Personal mailbox whose decoded name crosses into NamespacePrefix, with encoded child.
		_, err = rdb.ResolveOrCreateMailboxPathWithRetry(sharedCtx, accountID, "Partag&AOk-s/R&AOk-sum&AOk-")
		require.NoError(t, err)

		// 2. Shared mailbox whose decoded name lies outside NamespacePrefix, with personal child.
		_, err = rdb.ResolveOrCreateMailboxPathWithRetry(sharedCtx, accountID, "Legacy&AOk-/N&AOk-")
		require.NoError(t, err)
		legacyMbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "Legacy&AOk-")
		require.NoError(t, err)
		_, err = rdb.GetOperationalDatabase().WritePool.Exec(ctx,
			`UPDATE mailboxes SET is_shared = TRUE WHERE id = $1`,
			legacyMbox.ID,
		)
		require.NoError(t, err)

		// 3. Valid shared mailbox remaining within NamespacePrefix.
		_, err = rdb.ResolveOrCreateMailboxPathWithRetry(sharedCtx, accountID, "Partagés/R&AOk-pertoire")
		require.NoError(t, err)

		dryOut := runMailboxFixUTF7(t, ctx, account.Email, "--dry-run")
		liveOut := runMailboxFixUTF7(t, ctx, account.Email)

		predictedRenames := parseFixUTF7Renames(dryOut)
		madeRenames := parseFixUTF7Renames(liveOut)
		require.Equal(t, []string{
			`"Legacy&AOk-/N&AOk-" -> "Legacy&AOk-/Né"`,
			`"Partag&AOk-s/R&AOk-sum&AOk-" -> "Partag&AOk-s/Résumé"`,
			`"Partagés/R&AOk-pertoire" -> "Partagés/Répertoire"`,
		}, madeRenames)
		require.Equal(t, madeRenames, predictedRenames, "dry-run renames must match live renames")
		require.Equal(t, parseFixUTF7Failures(liveOut), parseFixUTF7Failures(dryOut), "dry-run failures must match live failures")
		require.Contains(t, dryOut, "3 would be renamed, 0 skipped, 2 would fail")
	})

	t.Run("invalid decoded mailbox name refusal with descendants", func(t *testing.T) {
		account := common.CreateTestAccount(t, rdb)
		accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
		require.NoError(t, err)

		for _, name := range []string{
			"Bad&AAk-Name/R&AOk-sum&AOk-",  // &AAk- decodes to TAB
			"Null&AAA-Name/R&AOk-sum&AOk-", // &AAA- decodes to NUL
		} {
			_, err := rdb.ResolveOrCreateMailboxPathWithRetry(ctx, accountID, name)
			require.NoError(t, err, "create %q", name)
		}

		dryOut := runMailboxFixUTF7(t, ctx, account.Email, "--dry-run")
		liveOut := runMailboxFixUTF7(t, ctx, account.Email)

		predictedRenames := parseFixUTF7Renames(dryOut)
		madeRenames := parseFixUTF7Renames(liveOut)
		require.Equal(t, []string{
			`"Bad&AAk-Name/R&AOk-sum&AOk-" -> "Bad&AAk-Name/Résumé"`,
			`"Null&AAA-Name/R&AOk-sum&AOk-" -> "Null&AAA-Name/Résumé"`,
		}, madeRenames)
		require.Equal(t, madeRenames, predictedRenames, "dry-run renames must match live renames")
		require.Equal(t, parseFixUTF7Failures(liveOut), parseFixUTF7Failures(dryOut), "dry-run failures must match live failures")
		require.Contains(t, dryOut, "2 would fail")
	})

	t.Run("case-insensitive target intra-run and child collisions with descendants", func(t *testing.T) {
		account := common.CreateTestAccount(t, rdb)
		accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
		require.NoError(t, err)

		// 1. Pre-existing uppercase "CAFÉ" collides case-insensitively with "Caf&AOk-" -> "Café".
		require.NoError(t, rdb.CreateMailboxWithRetry(ctx, accountID, "CAFÉ", nil))
		_, err = rdb.ResolveOrCreateMailboxPathWithRetry(ctx, accountID, "Caf&AOk-/R&AOk-sum&AOk-")
		require.NoError(t, err)

		// 2. Intra-run case-insensitive collision: "ARK&AMk-" -> "ARKÉ" succeeds first,
		// so "Ark&AOk-" -> "Arké" fails and its child renames under "Ark&AOk-".
		_, err = rdb.ResolveOrCreateMailboxPathWithRetry(ctx, accountID, "ARK&AMk-")
		require.NoError(t, err)
		_, err = rdb.ResolveOrCreateMailboxPathWithRetry(ctx, accountID, "Ark&AOk-/N&AOk-")
		require.NoError(t, err)

		// 3. Descendant collision: top-level "Déjà/Sub" exists without "Déjà", so renaming
		// "D&AOk-j&AOA-" -> "Déjà" conflicts on cascaded child "Déjà/Sub".
		require.NoError(t, rdb.CreateMailboxWithRetry(ctx, accountID, "Déjà/Sub", nil))
		_, err = rdb.ResolveOrCreateMailboxPathWithRetry(ctx, accountID, "D&AOk-j&AOA-/Sub")
		require.NoError(t, err)
		_, err = rdb.ResolveOrCreateMailboxPathWithRetry(ctx, accountID, "D&AOk-j&AOA-/R&AOk-sum&AOk-")
		require.NoError(t, err)

		dryOut := runMailboxFixUTF7(t, ctx, account.Email, "--dry-run")
		liveOut := runMailboxFixUTF7(t, ctx, account.Email)

		predictedRenames := parseFixUTF7Renames(dryOut)
		madeRenames := parseFixUTF7Renames(liveOut)
		require.Equal(t, []string{
			`"ARK&AMk-" -> "ARKÉ"`,
			`"Ark&AOk-/N&AOk-" -> "Ark&AOk-/Né"`,
			`"Caf&AOk-/R&AOk-sum&AOk-" -> "Caf&AOk-/Résumé"`,
			`"D&AOk-j&AOA-/R&AOk-sum&AOk-" -> "D&AOk-j&AOA-/Résumé"`,
		}, madeRenames)
		require.Equal(t, madeRenames, predictedRenames, "dry-run renames must match live renames")
		require.Equal(t, parseFixUTF7Failures(liveOut), parseFixUTF7Failures(dryOut), "dry-run failures must match live failures")
		require.Contains(t, dryOut, "4 would be renamed, 1 skipped, 3 would fail")
	})
}

// PostgreSQL LOWER, used by RenameMailbox and its unique index, is not
// Unicode simple case folding (for example Greek final sigma and dotted I).
func TestMailboxFixUTF7DryRunDatabaseCaseParity(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()
	for _, tc := range []struct{ name, existing, encoded string }{
		{"final sigma is distinct", "ς", "&A6M-"},
		{"dotted I lower expansion conflicts", "i\u0307", "&ATA-"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := common.CreateTestAccount(t, rdb)
			id, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
			require.NoError(t, err)
			require.NoError(t, rdb.CreateMailboxWithRetry(ctx, id, tc.existing, nil))
			require.NoError(t, rdb.CreateMailboxWithRetry(ctx, id, tc.encoded, nil))
			dry := runMailboxFixUTF7(t, ctx, account.Email, "--dry-run")
			live := runMailboxFixUTF7(t, ctx, account.Email)
			require.Equal(t, parseFixUTF7Renames(live), parseFixUTF7Renames(dry), "dry=%s live=%s", dry, live)
			require.Equal(t, parseFixUTF7Failures(live), parseFixUTF7Failures(dry), "dry=%s live=%s", dry, live)
		})
	}
}

func TestMailboxFixUTF7DryRunDescendantSharedBoundary(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()
	previous := globalConfig
	t.Cleanup(func() { globalConfig = previous })
	globalConfig.SharedMailboxes = config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Téam/Shared/", DefaultRights: "lrswipkxtea"}
	account := common.CreateTestAccount(t, rdb)
	id, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
	require.NoError(t, err)
	_, err = rdb.ResolveOrCreateMailboxPathWithRetry(ctx, id, "T&AOk-am/Shared")
	require.NoError(t, err)
	dry := runMailboxFixUTF7(t, ctx, account.Email, "--dry-run")
	live := runMailboxFixUTF7(t, ctx, account.Email)
	require.Empty(t, parseFixUTF7Renames(live))
	require.Contains(t, live, consts.ErrMailboxSharedBoundary.Error())
	require.Equal(t, parseFixUTF7Renames(live), parseFixUTF7Renames(dry), "dry=%s live=%s", dry, live)
	require.Equal(t, parseFixUTF7Failures(live), parseFixUTF7Failures(dry), "dry=%s live=%s", dry, live)
}

func TestMailboxFixUTF7DryRunDatabaseDescendantCaseParity(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()
	for _, tc := range []struct{ name, existing, encoded string }{
		{"final sigma subtree is distinct", "ς/Sub", "&A6M-/Sub"},
		{"dotted I subtree conflicts", "i\u0307/Sub", "&ATA-/Sub"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := common.CreateTestAccount(t, rdb)
			id, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
			require.NoError(t, err)
			require.NoError(t, rdb.CreateMailboxWithRetry(ctx, id, tc.existing, nil))
			_, err = rdb.ResolveOrCreateMailboxPathWithRetry(ctx, id, tc.encoded)
			require.NoError(t, err)
			dry := runMailboxFixUTF7(t, ctx, account.Email, "--dry-run")
			live := runMailboxFixUTF7(t, ctx, account.Email)
			require.Equal(t, parseFixUTF7Renames(live), parseFixUTF7Renames(dry), "dry=%s live=%s", dry, live)
			// The live index violation includes its constraint detail; both modes
			// must refuse the same number of renames without cascading the parent.
			require.Len(t, parseFixUTF7Failures(dry), len(parseFixUTF7Failures(live)), "dry=%s live=%s", dry, live)
		})
	}
}
