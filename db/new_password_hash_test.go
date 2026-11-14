package db

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewPasswordsRefuseUnsaltedSHA512: unsalted SHA-512 is still verified for legacy
// credentials, but none of the paths that hash a new password writes it, as sora-admin's
// --hash flags already promise ("bcrypt, ssha512").
func TestNewPasswordsRefuseUnsaltedSHA512(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	stamp := time.Now().UnixNano()

	inTx := func(t *testing.T, fn func(tx pgx.Tx) error) error {
		t.Helper()
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	storedHash := func(t *testing.T, address string) string {
		t.Helper()
		var hash string
		err := db.GetWritePool().QueryRow(ctx, "SELECT password FROM credentials WHERE address = $1", address).Scan(&hash)
		if err == pgx.ErrNoRows {
			return ""
		}
		require.NoError(t, err)
		return hash
	}
	refused := func(t *testing.T, err error, address string) {
		t.Helper()
		if assert.Error(t, err, "sha512 was accepted for a new password") {
			assert.ErrorIs(t, err, ErrUnsupportedHashType)
		}
		assert.False(t, strings.HasPrefix(storedHash(t, address), "{SHA512}"), "an unsalted SHA-512 hash was stored for %s", address)
	}

	existing := fmt.Sprintf("sha512-existing-%d@example.com", stamp)
	var accountID int64
	require.NoError(t, inTx(t, func(tx pgx.Tx) error {
		var err error
		accountID, err = db.CreateAccount(ctx, tx, CreateAccountRequest{Email: existing, Password: "pw-123456", IsPrimary: true, HashType: "bcrypt"})
		return err
	}))

	t.Run("CreateAccountWithCredentials", func(t *testing.T) {
		email := fmt.Sprintf("sha512-multi-%d@example.com", stamp)
		err := inTx(t, func(tx pgx.Tx) error {
			_, err := db.CreateAccountWithCredentials(ctx, tx, CreateAccountWithCredentialsRequest{
				Credentials: []CredentialSpec{{Email: email, Password: "pw-123456", IsPrimary: true, HashType: "sha512"}},
			})
			return err
		})
		refused(t, err, email)
	})

	t.Run("CreateAccount", func(t *testing.T) {
		email := fmt.Sprintf("sha512-single-%d@example.com", stamp)
		err := inTx(t, func(tx pgx.Tx) error {
			_, err := db.CreateAccount(ctx, tx, CreateAccountRequest{Email: email, Password: "pw-123456", IsPrimary: true, HashType: "sha512"})
			return err
		})
		refused(t, err, email)
	})

	t.Run("AddCredential", func(t *testing.T) {
		email := fmt.Sprintf("sha512-alias-%d@example.com", stamp)
		err := inTx(t, func(tx pgx.Tx) error {
			return db.AddCredential(ctx, tx, AddCredentialRequest{AccountID: accountID, NewEmail: email, NewPassword: "pw-123456", NewHashType: "sha512"})
		})
		refused(t, err, email)
	})

	t.Run("UpdateAccount", func(t *testing.T) {
		err := inTx(t, func(tx pgx.Tx) error {
			return db.UpdateAccount(ctx, tx, UpdateAccountRequest{Email: existing, Password: "pw-654321", HashType: "sha512"})
		})
		refused(t, err, existing)
	})
}
