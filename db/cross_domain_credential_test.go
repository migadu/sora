package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the cross-domain hardening:
//  1. AddCredential / UpdateAccount must not switch an account's primary identity to a
//     different domain once the account has messages (would split s3_domain). Non-primary
//     cross-domain aliases and same-domain primary changes stay allowed.
//  2. GetAliasCredentialsByDomain surfaces the cross-domain aliases that domain purge must
//     remove (non-primary credentials in a domain, on accounts whose primary lives elsewhere).

func setupAccountWithInbox(t *testing.T, db *Database, ctx context.Context, email string) (accountID, inboxID int64) {
	t.Helper()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = db.CreateAccount(ctx, tx, CreateAccountRequest{Email: email, Password: "password123", IsPrimary: true, HashType: "bcrypt"})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	accountID, err = db.GetAccountIDByAddress(ctx, email)
	require.NoError(t, err)

	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)
	require.NoError(t, db.CreateMailbox(ctx, tx2, accountID, "INBOX", nil))
	require.NoError(t, tx2.Commit(ctx))

	inbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	return accountID, inbox.ID
}

func addCredentialTx(t *testing.T, db *Database, ctx context.Context, req AddCredentialRequest) error {
	t.Helper()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	if err := db.AddCredential(ctx, tx, req); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func updateAccountTx(t *testing.T, db *Database, ctx context.Context, req UpdateAccountRequest) error {
	t.Helper()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	if err := db.UpdateAccount(ctx, tx, req); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// uniqueDomains returns two distinct, valid, run-unique domains so concurrent/repeat runs
// never collide on the globally-unique credential address.
func uniqueDomains(t *testing.T) (domainA, domainB string) {
	t.Helper()
	tok := fmt.Sprintf("%d", time.Now().UnixNano())
	return fmt.Sprintf("doma%s.com", tok), fmt.Sprintf("domb%s.com", tok)
}

func TestAddCredentialCrossDomainPrimaryGuard(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	domainA, domainB := uniqueDomains(t)
	accountID, inboxID := setupAccountWithInbox(t, db, ctx, "user@"+domainA)

	// A non-primary cross-domain alias is always allowed (this is the alias sign-in feature).
	err := addCredentialTx(t, db, ctx, AddCredentialRequest{
		AccountID: accountID, NewEmail: "alias@" + domainB, NewPassword: "pw", NewHashType: "bcrypt",
	})
	require.NoError(t, err, "non-primary cross-domain alias must be allowed")

	// Populate the account.
	insertTestMessage(t, db, accountID, inboxID, "INBOX", "Hello", "<guard-add-1@example.com>")

	// Cross-domain primary on a populated account is blocked.
	err = addCredentialTx(t, db, ctx, AddCredentialRequest{
		AccountID: accountID, NewEmail: "boss@" + domainB, NewPassword: "pw", IsPrimary: true, NewHashType: "bcrypt",
	})
	assert.ErrorIs(t, err, ErrCrossDomainPrimaryChange, "cross-domain primary on a populated account must be blocked")

	// Same-domain primary change on a populated account stays allowed.
	err = addCredentialTx(t, db, ctx, AddCredentialRequest{
		AccountID: accountID, NewEmail: "user2@" + domainA, NewPassword: "pw", IsPrimary: true, NewHashType: "bcrypt",
	})
	assert.NoError(t, err, "same-domain primary change must be allowed even with messages")
}

func TestAddCredentialCrossDomainPrimaryAllowedWhenEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	domainA, domainB := uniqueDomains(t)
	accountID, _ := setupAccountWithInbox(t, db, ctx, "user@"+domainA)

	// No messages yet → cross-domain primary is allowed (nothing to split).
	err := addCredentialTx(t, db, ctx, AddCredentialRequest{
		AccountID: accountID, NewEmail: "boss@" + domainB, NewPassword: "pw", IsPrimary: true, NewHashType: "bcrypt",
	})
	assert.NoError(t, err, "cross-domain primary must be allowed on an account with no messages")
}

func TestUpdateAccountCrossDomainPrimaryGuard(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	domainA, domainB := uniqueDomains(t)
	accountID, inboxID := setupAccountWithInbox(t, db, ctx, "user@"+domainA)

	// Add a cross-domain alias (allowed) and a same-domain alias (allowed).
	require.NoError(t, addCredentialTx(t, db, ctx, AddCredentialRequest{
		AccountID: accountID, NewEmail: "other@" + domainB, NewPassword: "pw", NewHashType: "bcrypt",
	}))
	require.NoError(t, addCredentialTx(t, db, ctx, AddCredentialRequest{
		AccountID: accountID, NewEmail: "user2@" + domainA, NewPassword: "pw", NewHashType: "bcrypt",
	}))

	// Populate the account.
	insertTestMessage(t, db, accountID, inboxID, "INBOX", "Hello", "<guard-upd-1@example.com>")

	// Promoting the cross-domain alias to primary is blocked.
	err := updateAccountTx(t, db, ctx, UpdateAccountRequest{Email: "other@" + domainB, MakePrimary: true})
	assert.ErrorIs(t, err, ErrCrossDomainPrimaryChange, "cross-domain MakePrimary on a populated account must be blocked")

	// Promoting the same-domain alias to primary is allowed.
	err = updateAccountTx(t, db, ctx, UpdateAccountRequest{Email: "user2@" + domainA, MakePrimary: true})
	assert.NoError(t, err, "same-domain MakePrimary must be allowed even with messages")
}

func TestGetAliasCredentialsByDomain(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	domainA, domainB := uniqueDomains(t)

	// Account 1: primary in domainA, with a non-primary alias in domainB.
	account1, _ := setupAccountWithInbox(t, db, ctx, "primary@"+domainA)
	require.NoError(t, addCredentialTx(t, db, ctx, AddCredentialRequest{
		AccountID: account1, NewEmail: "aliasinb@" + domainB, NewPassword: "pw", NewHashType: "bcrypt",
	}))

	// Account 2: primary IS in domainB.
	setupAccountWithInbox(t, db, ctx, "primaryinb@"+domainB)

	aliases, err := db.GetAliasCredentialsByDomain(ctx, domainB)
	require.NoError(t, err)

	// Only the non-primary alias must be returned; the domainB primary must be excluded.
	assert.Equal(t, []string{"aliasinb@" + domainB}, aliases)
}
