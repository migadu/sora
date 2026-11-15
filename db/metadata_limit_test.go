package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestMetadataCountLimitAccountsForOverwrites verifies that the per-scope entry
// count limit only counts genuinely new entries: overwriting an existing entry
// is net-zero and deleting one frees a slot. Before the fix, SetMetadata counted
// every non-nil request entry as a new addition (currentCount + newEntries), so
// overwriting an entry while at the limit was wrongly rejected as TOOMANY.
func TestMetadataCountLimitAccountsForOverwrites(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	db := setupTestDatabase(t)
	ctx := context.Background()
	accountID := createTestAccount(t, db, fmt.Sprintf("test-meta-count-%d@example.com", time.Now().UnixNano()), "password")

	limits := &MetadataLimits{MaxEntriesPerServer: 2}

	set := func(t *testing.T, entries map[string]*[]byte) error {
		t.Helper()
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		if err := db.SetMetadata(ctx, tx, accountID, nil, entries, limits); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	// Fill to the limit of 2 entries.
	require.NoError(t, set(t, map[string]*[]byte{
		"/private/a": bytePtr([]byte("v1")),
		"/private/b": bytePtr([]byte("v2")),
	}))

	// Overwriting an existing entry must NOT be counted as a new one (RED before fix).
	if err := set(t, map[string]*[]byte{"/private/a": bytePtr([]byte("v1-updated"))}); err != nil {
		t.Fatalf("overwriting an existing entry at the count limit should succeed, got: %v", err)
	}

	// Adding a genuinely new entry beyond the limit must be rejected.
	err := set(t, map[string]*[]byte{"/private/c": bytePtr([]byte("v3"))})
	if err == nil {
		t.Fatalf("adding a 3rd entry past the limit of 2 should be rejected as TOOMANY")
	}
	if metaErr, ok := err.(*MetadataError); !ok || metaErr.Type != MetadataErrTooMany {
		t.Fatalf("expected MetadataErrTooMany, got %T: %v", err, err)
	}

	// Deleting an existing entry frees a slot, so a delete+add in one request stays
	// within the limit.
	if err := set(t, map[string]*[]byte{
		"/private/a": nil,                   // delete existing
		"/private/c": bytePtr([]byte("v3")), // add new
	}); err != nil {
		t.Fatalf("delete-existing + add-new (net zero) at the limit should succeed, got: %v", err)
	}
}

// TestMetadataSizeQuotaAccountsForOverwrites verifies that the total-size quota
// charges only the net delta of an overwrite, not the full new value on top of
// the already-counted old value.
func TestMetadataSizeQuotaAccountsForOverwrites(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	db := setupTestDatabase(t)
	ctx := context.Background()
	accountID := createTestAccount(t, db, fmt.Sprintf("test-meta-size-%d@example.com", time.Now().UnixNano()), "password")

	limits := &MetadataLimits{MaxTotalSize: 15}

	set := func(entries map[string]*[]byte) error {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		if err := db.SetMetadata(ctx, tx, accountID, nil, entries, limits); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	// Store a 10-byte value (total = 10, under the 15-byte quota).
	require.NoError(t, set(map[string]*[]byte{"/private/a": bytePtr([]byte("0123456789"))}))

	// Overwrite with a 12-byte value: net delta is +2 → total 12, still under quota.
	// Before the fix this was 10 + 12 = 22 > 15 → wrongly QUOTA-exceeded.
	if err := set(map[string]*[]byte{"/private/a": bytePtr([]byte("012345678901"))}); err != nil {
		t.Fatalf("overwrite whose net delta stays under quota should succeed, got: %v", err)
	}

	// A genuinely larger overwrite that pushes the true total past the quota is rejected.
	err := set(map[string]*[]byte{"/private/a": bytePtr([]byte("0123456789012345"))}) // 16 bytes
	if err == nil {
		t.Fatalf("overwrite pushing total past the quota should be rejected")
	}
	if metaErr, ok := err.(*MetadataError); !ok || metaErr.Type != MetadataErrQuotaExceeded {
		t.Fatalf("expected MetadataErrQuotaExceeded, got %T: %v", err, err)
	}
}

// TestMetadataOverLimitAccountCanShrink verifies that an account already past a
// count or size limit (the limit was lowered after the entries were stored) can
// get back under it one command at a time. Only a command that grows the usage
// is refused: RFC 5464 §4.3 sends [METADATA TOOMANY] when the server "is unable
// to set a new annotation because the maximum number of allowed annotations has
// already been reached", and RFC 9208 §4.3.1 sends OVERQUOTA when "the addition
// of the message(s) puts the target mailbox over any one of its quota limits".
func TestMetadataOverLimitAccountCanShrink(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	db := setupTestDatabase(t)
	ctx := context.Background()

	set := func(t *testing.T, accountID int64, entries map[string]*[]byte, limits *MetadataLimits) error {
		t.Helper()
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		if err := db.SetMetadata(ctx, tx, accountID, nil, entries, limits); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	// newAccount stores /private/k0 .. /private/k3, 4 bytes each, with no
	// limits: 4 entries and 16 bytes.
	newAccount := func(t *testing.T) int64 {
		t.Helper()
		accountID := createTestAccount(t, db, fmt.Sprintf("test-meta-over-%d@example.com", time.Now().UnixNano()), "password")
		require.NoError(t, set(t, accountID, map[string]*[]byte{
			"/private/k0": bytePtr([]byte("val0")),
			"/private/k1": bytePtr([]byte("val1")),
			"/private/k2": bytePtr([]byte("val2")),
			"/private/k3": bytePtr([]byte("val3")),
		}, nil))
		return accountID
	}

	requireRefused := func(t *testing.T, err error, want MetadataErrorType) {
		t.Helper()
		var metaErr *MetadataError
		require.ErrorAs(t, err, &metaErr)
		require.Equal(t, want, metaErr.Type, "error: %v", err)
	}

	t.Run("count", func(t *testing.T) {
		limits := &MetadataLimits{MaxEntriesPerServer: 2}

		cases := []struct {
			name    string
			entries map[string]*[]byte
		}{
			{"delete", map[string]*[]byte{"/private/k0": nil}},
			{"overwrite", map[string]*[]byte{"/private/k1": bytePtr([]byte("v"))}},
			{"delete absent", map[string]*[]byte{"/private/none": nil}},
			{"add and delete", map[string]*[]byte{"/private/new": bytePtr([]byte("v")), "/private/k2": nil}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				accountID := newAccount(t)
				require.NoError(t, set(t, accountID, tc.entries, limits),
					"a command adding no entry overall must not be refused with TOOMANY")
			})
		}

		t.Run("add", func(t *testing.T) {
			accountID := newAccount(t)
			err := set(t, accountID, map[string]*[]byte{"/private/new": bytePtr([]byte("v"))}, limits)
			requireRefused(t, err, MetadataErrTooMany)
		})

		t.Run("one at a time back under the limit", func(t *testing.T) {
			accountID := newAccount(t)
			require.NoError(t, set(t, accountID, map[string]*[]byte{"/private/k0": nil}, limits))
			require.NoError(t, set(t, accountID, map[string]*[]byte{"/private/k1": nil}, limits))
			// At the limit now: one more entry is still refused.
			err := set(t, accountID, map[string]*[]byte{"/private/new": bytePtr([]byte("v"))}, limits)
			requireRefused(t, err, MetadataErrTooMany)
		})
	})

	t.Run("size", func(t *testing.T) {
		limits := &MetadataLimits{MaxTotalSize: 8}

		cases := []struct {
			name    string
			entries map[string]*[]byte
		}{
			{"delete", map[string]*[]byte{"/private/k1": nil}},
			{"shrink", map[string]*[]byte{"/private/k1": bytePtr([]byte("v"))}},
			{"same size", map[string]*[]byte{"/private/k1": bytePtr([]byte("VAL1"))}},
			{"grow one shrink another", map[string]*[]byte{"/private/k1": bytePtr([]byte("val1+")), "/private/k2": nil}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				accountID := newAccount(t)
				require.NoError(t, set(t, accountID, tc.entries, limits),
					"a command not increasing the total size must not be refused with OVERQUOTA")
			})
		}

		t.Run("grow", func(t *testing.T) {
			accountID := newAccount(t)
			err := set(t, accountID, map[string]*[]byte{"/private/k1": bytePtr([]byte("val1+"))}, limits)
			requireRefused(t, err, MetadataErrQuotaExceeded)
		})
	})
}
