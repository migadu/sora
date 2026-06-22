package db

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/migadu/sora/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigration38_ParentPath(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	ctx := context.Background()

	// 1. Load test database config
	configPath, err := findTestConfig()
	require.NoError(t, err)

	var cfg TestConfig
	_, err = tomlDecodeFile(configPath, &cfg) // helper wrapping toml.DecodeFile if needed, or direct
	require.NoError(t, err)

	dbConfig := &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{
			Hosts:    cfg.Database.Write.Hosts,
			Port:     cfg.Database.Write.Port,
			User:     cfg.Database.Write.User,
			Password: cfg.Database.Write.Password,
			Name:     cfg.Database.Write.Name,
			TLSMode:  cfg.Database.Write.TLS,
		},
	}

	// 2. Set up migration driver
	migrations, err := fs.Sub(MigrationsFS, "migrations")
	require.NoError(t, err)

	sourceDriver, err := iofs.New(migrations, ".")
	require.NoError(t, err)

	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cfg.Database.Write.User,
		cfg.Database.Write.Password,
		cfg.Database.Write.Hosts[0],
		cfg.Database.Write.Port,
		cfg.Database.Write.Name,
	)

	m, err := migrate.NewWithSourceInstance("iofs", sourceDriver, dbURL)
	require.NoError(t, err)

	// Ensure database is migrated to latest first (to have a clean baseline)
	err = m.Up()
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("failed to migrate up to latest: %v", err)
	}

	// Rollback to version 37
	err = m.Migrate(37)
	require.NoError(t, err)

	// In case test fails, ensure we restore the database to latest
	defer func() {
		err := m.Migrate(38) // restore to 38/latest
		if err != nil && !errors.Is(err, migrate.ErrNoChange) {
			t.Logf("cleanup: failed to restore to version 38: %v", err)
		}
	}()

	// 3. Connect to database at version 37 (runMigrations=false)
	database, err := NewDatabaseFromConfig(ctx, dbConfig, false, false)
	require.NoError(t, err)
	defer database.Close()

	// Clear out any existing accounts/mailboxes to start with a clean slate
	_, err = database.WritePool.Exec(ctx, "TRUNCATE TABLE accounts, mailboxes CASCADE")
	require.NoError(t, err)

	// 4. Set up an account and mailboxes under version 37 schema
	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)

	testEmail := fmt.Sprintf("migration_38_test_%d@example.com", time.Now().UnixNano())
	accountReq := CreateAccountRequest{Email: testEmail, Password: "password", IsPrimary: true, HashType: "bcrypt"}
	_, err = database.CreateAccount(ctx, tx, accountReq)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	accountID, err := database.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	// Create root mailbox
	tx, err = database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	err = database.CreateMailbox(ctx, tx, accountID, "INBOX", nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	inbox, err := database.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	assert.NotEmpty(t, inbox.Path)

	// Create child mailbox
	tx, err = database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	err = database.CreateMailbox(ctx, tx, accountID, "INBOX/Child", &inbox.ID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	child, err := database.GetMailboxByName(ctx, accountID, "INBOX/Child")
	require.NoError(t, err)
	assert.NotEmpty(t, child.Path)

	// Verify that parent_path column does not exist yet (will error if queried)
	var parentPathColExists bool
	err = database.GetReadPool().QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns 
			WHERE table_name='mailboxes' AND column_name='parent_path'
		)
	`).Scan(&parentPathColExists)
	require.NoError(t, err)
	assert.False(t, parentPathColExists, "parent_path column should not exist at version 37")

	// Close database connection so migration lock is not blocked
	database.Close()

	// 5. Migrate up to version 38
	err = m.Migrate(38)
	require.NoError(t, err)

	// Reconnect to database
	database, err = NewDatabaseFromConfig(ctx, dbConfig, false, false)
	require.NoError(t, err)

	// Verify that parent_path column now exists
	err = database.GetReadPool().QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns 
			WHERE table_name='mailboxes' AND column_name='parent_path'
		)
	`).Scan(&parentPathColExists)
	require.NoError(t, err)
	assert.True(t, parentPathColExists, "parent_path column should exist at version 38")

	// 6. Verify backfilled parent_path values
	var inboxParentPath *string
	err = database.GetReadPool().QueryRow(ctx, "SELECT parent_path FROM mailboxes WHERE id = $1", inbox.ID).Scan(&inboxParentPath)
	require.NoError(t, err)
	assert.Nil(t, inboxParentPath, "Root mailbox should have NULL parent_path")

	var childParentPath *string
	err = database.GetReadPool().QueryRow(ctx, "SELECT parent_path FROM mailboxes WHERE id = $1", child.ID).Scan(&childParentPath)
	require.NoError(t, err)
	require.NotNil(t, childParentPath)
	assert.Equal(t, inbox.Path, *childParentPath, "Child mailbox parent_path should match parent mailbox path")

	// 7. Test trigger on INSERT (creating a new grandchild mailbox)
	tx, err = database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	err = database.CreateMailbox(ctx, tx, accountID, "INBOX/Child/Grandchild", &child.ID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	grandchild, err := database.GetMailboxByName(ctx, accountID, "INBOX/Child/Grandchild")
	require.NoError(t, err)

	var grandchildParentPath *string
	err = database.GetReadPool().QueryRow(ctx, "SELECT parent_path FROM mailboxes WHERE id = $1", grandchild.ID).Scan(&grandchildParentPath)
	require.NoError(t, err)
	require.NotNil(t, grandchildParentPath)
	assert.Equal(t, child.Path, *grandchildParentPath, "Grandchild parent_path should match child path")

	// 8. Test trigger on UPDATE (moving/renaming mailbox)
	// Create another root mailbox
	tx, err = database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	err = database.CreateMailbox(ctx, tx, accountID, "Archive", nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	archive, err := database.GetMailboxByName(ctx, accountID, "Archive")
	require.NoError(t, err)

	// Move "INBOX/Child" into "Archive" (making it "Archive/Child")
	tx, err = database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	err = database.RenameMailbox(ctx, tx, child.ID, accountID, "Archive/Child", &archive.ID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	// Refetch child and check path/parent_path
	childMoved, err := database.GetMailboxByName(ctx, accountID, "Archive/Child")
	require.NoError(t, err)

	var childMovedParentPath *string
	err = database.GetReadPool().QueryRow(ctx, "SELECT parent_path FROM mailboxes WHERE id = $1", childMoved.ID).Scan(&childMovedParentPath)
	require.NoError(t, err)
	require.NotNil(t, childMovedParentPath)
	assert.Equal(t, archive.Path, *childMovedParentPath, "Moved child parent_path should match Archive path")

	// Verify grandchild's path and parent_path updated automatically too
	grandchildMoved, err := database.GetMailboxByName(ctx, accountID, "Archive/Child/Grandchild")
	require.NoError(t, err)

	var grandchildMovedParentPath *string
	err = database.GetReadPool().QueryRow(ctx, "SELECT parent_path FROM mailboxes WHERE id = $1", grandchildMoved.ID).Scan(&grandchildMovedParentPath)
	require.NoError(t, err)
	require.NotNil(t, grandchildMovedParentPath)
	assert.Equal(t, childMoved.Path, *grandchildMovedParentPath, "Grandchild parent_path should update to the new child path")

	// 9. Close database connection before rollback
	database.Close()

	// Rollback again to 37 (tests Down migration)
	err = m.Migrate(37)
	require.NoError(t, err)

	// Reconnect and verify parent_path column is gone
	database, err = NewDatabaseFromConfig(ctx, dbConfig, false, false)
	require.NoError(t, err)

	err = database.GetReadPool().QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns 
			WHERE table_name='mailboxes' AND column_name='parent_path'
		)
	`).Scan(&parentPathColExists)
	require.NoError(t, err)
	assert.False(t, parentPathColExists, "parent_path column should be dropped after down migration")
}

// helper wrapper since BurntSushi/toml uses DecodeFile or Decode
func tomlDecodeFile(fpath string, v interface{}) (toml.MetaData, error) {
	return toml.DecodeFile(fpath, v)
}
