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
