package db

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStoredPasswordHashesMustBeVerifiable: a pre-computed hash is stored only when
// VerifyPassword can check it. A value it cannot check (a password pasted into the
// hash field, a scheme sora does not verify, malformed data) used to be stored without
// a word, and the account could then never log in. Every path that stores a hash
// refuses it as an invalid request (the Admin API's 400) and writes nothing. A Dovecot
// spelling sora verifies is stored, and the stored value verifies.
func TestStoredPasswordHashesMustBeVerifiable(t *testing.T) {
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

	const password = "pw-123456"
	unverifiable := map[string]string{
		"password in the hash field": "Secret-2026",
		"unsupported scheme":         sha512CryptOfSecret,
		"SSHA512 without a salt":     "{SSHA512}" + base64.StdEncoding.EncodeToString([]byte("tooshort")),
	}
	dovecot := dovecotSpellings(t, password)[2] // {SSHA512.hex}

	original, err := GenerateSSHA512Hash(password)
	require.NoError(t, err)
	existing := fmt.Sprintf("hash-existing-%d@example.com", stamp)
	var accountID int64
	require.NoError(t, inTx(t, func(tx pgx.Tx) error {
		var err error
		accountID, err = db.CreateAccount(ctx, tx, CreateAccountRequest{Email: existing, PasswordHash: original, IsPrimary: true})
		return err
	}))

	paths := []struct {
		name  string
		store func(tx pgx.Tx, address, hash string) error
		// address the hash is stored for; "" = a new address per attempt
		address string
	}{
		{"CreateAccount", func(tx pgx.Tx, address, hash string) error {
			_, err := db.CreateAccount(ctx, tx, CreateAccountRequest{Email: address, PasswordHash: hash, IsPrimary: true})
			return err
		}, ""},
		{"CreateAccountWithCredentials", func(tx pgx.Tx, address, hash string) error {
			_, err := db.CreateAccountWithCredentials(ctx, tx, CreateAccountWithCredentialsRequest{
				Credentials: []CredentialSpec{{Email: address, PasswordHash: hash, IsPrimary: true}},
			})
			return err
		}, ""},
		{"AddCredential", func(tx pgx.Tx, address, hash string) error {
			return db.AddCredential(ctx, tx, AddCredentialRequest{AccountID: accountID, NewEmail: address, NewPasswordHash: hash})
		}, ""},
		{"UpdateAccount", func(tx pgx.Tx, address, hash string) error {
			return db.UpdateAccount(ctx, tx, UpdateAccountRequest{Email: address, PasswordHash: hash})
		}, existing},
	}

	n := 0
	for _, p := range paths {
		address := func() string {
			if p.address != "" {
				return p.address
			}
			n++
			return fmt.Sprintf("hash-%d-%d@example.com", n, stamp)
		}
		t.Run(p.name, func(t *testing.T) {
			for what, hash := range unverifiable {
				addr := address()
				before := storedHash(t, addr)
				err := inTx(t, func(tx pgx.Tx) error { return p.store(tx, addr, hash) })
				assert.ErrorIs(t, err, ErrInvalidAccountRequest, "%s (%q) was not refused as an invalid request", what, hash)
				assert.Equal(t, before, storedHash(t, addr), "%s (%q) was stored for %s", what, hash, addr)
			}

			addr := address()
			require.NoError(t, inTx(t, func(tx pgx.Tx) error { return p.store(tx, addr, dovecot) }), "storing %q", dovecot)
			stored := storedHash(t, addr)
			assert.Equal(t, dovecot, stored)
			assert.NoError(t, VerifyPassword(stored, password), "the stored %q does not verify", stored)
		})
	}
}
