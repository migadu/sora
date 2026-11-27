package db

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateStorageQuota(t *testing.T) {
	zero, negative, positive := int64(0), int64(-1), int64(1)
	assert.NoError(t, ValidateStorageQuota(nil))
	assert.NoError(t, ValidateStorageQuota(&positive))
	assert.Error(t, ValidateStorageQuota(&zero))
	assert.Error(t, ValidateStorageQuota(&negative))
}

func TestAccountStorageQuota(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	database := setupTestDatabase(t)
	ctx := context.Background()

	create := func(t *testing.T, quota *int64) (int64, string) {
		t.Helper()
		email := fmt.Sprintf("quota-%d@example.com", time.Now().UnixNano())
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		id, err := database.CreateAccount(ctx, tx, CreateAccountRequest{
			Email: email, Password: "password", IsPrimary: true, HashType: "bcrypt", StorageQuota: quota,
		})
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return id, email
	}
	set := func(email string, quota *int64) error {
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		if err := database.SetAccountStorageQuota(ctx, tx, email, quota); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	t.Run("CreatedUnlimited", func(t *testing.T) {
		id, _ := create(t, nil)
		q, err := database.GetAccountQuota(ctx, id)
		require.NoError(t, err)
		assert.Nil(t, q.StorageQuota)
		assert.Equal(t, int64(0), q.StorageUsed)
	})

	t.Run("CreatedWithLimit", func(t *testing.T) {
		limit := int64(5 << 30)
		id, email := create(t, &limit)
		q, err := database.GetAccountQuota(ctx, id)
		require.NoError(t, err)
		require.NotNil(t, q.StorageQuota)
		assert.Equal(t, limit, *q.StorageQuota)

		details, err := database.GetAccountDetails(ctx, email)
		require.NoError(t, err)
		require.NotNil(t, details.StorageQuota)
		assert.Equal(t, limit, *details.StorageQuota)
	})

	t.Run("CreateRefusesZero", func(t *testing.T) {
		zero := int64(0)
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = database.CreateAccount(ctx, tx, CreateAccountRequest{
			Email: fmt.Sprintf("quota-zero-%d@example.com", time.Now().UnixNano()), Password: "password",
			IsPrimary: true, HashType: "bcrypt", StorageQuota: &zero,
		})
		assert.ErrorIs(t, err, ErrInvalidAccountRequest)
	})

	t.Run("SetAndClear", func(t *testing.T) {
		id, email := create(t, nil)
		limit := int64(1 << 20)
		require.NoError(t, set(email, &limit))
		q, err := database.GetAccountQuotaByEmail(ctx, email)
		require.NoError(t, err)
		require.NotNil(t, q.StorageQuota)
		assert.Equal(t, limit, *q.StorageQuota)

		require.NoError(t, set(email, nil))
		q, err = database.GetAccountQuota(ctx, id)
		require.NoError(t, err)
		assert.Nil(t, q.StorageQuota)
	})

	t.Run("SetRefusesZeroAndUnknown", func(t *testing.T) {
		_, email := create(t, nil)
		zero := int64(0)
		assert.ErrorIs(t, set(email, &zero), ErrInvalidAccountRequest)
		limit := int64(1)
		assert.True(t, errors.Is(set("nobody-"+email, &limit), consts.ErrUserNotFound))
	})

	t.Run("ConstraintBacksValidation", func(t *testing.T) {
		id, _ := create(t, nil)
		_, err := database.GetWritePool().Exec(ctx, "UPDATE accounts SET storage_quota = 0 WHERE id = $1", id)
		assert.Error(t, err, "accounts_storage_quota_positive refuses 0")
	})

	t.Run("UnknownAccount", func(t *testing.T) {
		_, err := database.GetAccountQuota(ctx, -1)
		assert.ErrorIs(t, err, consts.ErrUserNotFound)
		_, err = database.GetAccountQuotaByEmail(ctx, "no-such-quota-account@example.com")
		assert.ErrorIs(t, err, consts.ErrUserNotFound)
	})
}
