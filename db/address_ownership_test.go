package db

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIsAddressOwnedByAccount verifies the credential-ownership check used to
// constrain SIEVE vacation ":from" addresses (audit finding L3). The security-
// critical properties are account scoping (one account's credential is not "owned"
// by another) and case-insensitive matching.
func TestIsAddressOwnedByAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	// Account A: a primary address plus an alias.
	primaryA := "ownerbase" + testRunID + "@example.com"
	aliasA := "owneralias" + testRunID + "@example.com"
	accountA := createAccountWithCredential(t, database, ctx, primaryA)
	addCredential(t, database, ctx, accountA, aliasA)

	// Account B: a separate account whose address A must NOT be able to claim.
	addressB := "other" + testRunID + "@example.com"
	createAccountWithCredential(t, database, ctx, addressB)

	cases := []struct {
		name    string
		address string
		want    bool
	}{
		{"primary is owned", primaryA, true},
		{"alias is owned", aliasA, true},
		{"primary owned case-insensitively", strings.ToUpper(primaryA), true},
		{"other account's address is NOT owned", addressB, false},
		{"unknown address is NOT owned", "nobody" + testRunID + "@example.com", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := database.IsAddressOwnedByAccount(ctx, accountA, c.address)
			require.NoError(t, err)
			require.Equal(t, c.want, got)
		})
	}
}

// TestIsAnyAddressOwnedByAccount verifies the batched ownership check used by the
// SIEVE vacation personal message check (RFC 5230 §4.5, issue #487): the same
// account scoping and case-insensitive match as IsAddressOwnedByAccount, for any
// address of a list.
func TestIsAnyAddressOwnedByAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	primaryA := "anybase" + testRunID + "@example.com"
	aliasA := "anyalias" + testRunID + "@example.com"
	accountA := createAccountWithCredential(t, database, ctx, primaryA)
	addCredential(t, database, ctx, accountA, aliasA)
	addressB := "anyother" + testRunID + "@example.com"
	createAccountWithCredential(t, database, ctx, addressB)
	unknown := "anynobody" + testRunID + "@example.com"

	cases := []struct {
		name      string
		addresses []string
		want      bool
	}{
		{"no addresses", nil, false},
		{"primary among others", []string{unknown, addressB, primaryA}, true},
		{"alias owned case-insensitively", []string{unknown, strings.ToUpper(aliasA)}, true},
		{"other account's and unknown addresses are NOT owned", []string{addressB, unknown}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := database.IsAnyAddressOwnedByAccount(ctx, accountA, c.addresses)
			require.NoError(t, err)
			require.Equal(t, c.want, got)
		})
	}
}

func createAccountWithCredential(t *testing.T, database *Database, ctx context.Context, email string) int64 {
	t.Helper()
	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	id, err := database.CreateAccount(ctx, tx, CreateAccountRequest{
		Email:     email,
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return id
}

func addCredential(t *testing.T, database *Database, ctx context.Context, accountID int64, email string) {
	t.Helper()
	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	require.NoError(t, database.AddCredential(ctx, tx, AddCredentialRequest{
		AccountID:   accountID,
		NewEmail:    email,
		NewPassword: "password456",
		IsPrimary:   false,
		NewHashType: "bcrypt",
	}))
	require.NoError(t, tx.Commit(ctx))
}
