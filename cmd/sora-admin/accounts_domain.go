package main

// accounts_domain.go - Domain-level account operations

import (
	"context"
	"fmt"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/storage"
)

// purgeDomain purges all accounts for a given domain
// It's resumable - accounts already purged are skipped
func purgeDomain(ctx context.Context, cfg AdminConfig, domain string) error {
	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	fmt.Printf("🔍 Scanning for accounts in domain: %s\n\n", domain)

	// Get all accounts for this domain
	accounts, err := rdb.GetAccountsByDomain(ctx, domain)
	if err != nil {
		return fmt.Errorf("failed to get accounts for domain: %w", err)
	}

	if len(accounts) == 0 {
		fmt.Printf("No accounts found for domain: %s\n", domain)
		return nil
	}

	fmt.Printf("Found %d account(s) to purge:\n", len(accounts))
	for i, acct := range accounts {
		fmt.Printf("  %d. %s (ID: %d)\n", i+1, acct.PrimaryEmail, acct.AccountID)
	}
	fmt.Printf("\n")

	// Purge each account using the same logic as single account purge
	successCount := 0
	failedCount := 0
	skippedCount := 0

	for i, acct := range accounts {
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		fmt.Printf("Account %d/%d: %s (ID: %d)\n", i+1, len(accounts), acct.PrimaryEmail, acct.AccountID)
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

		// Check if already purged (account doesn't exist in DB anymore)
		exists, err := rdb.AccountExistsWithRetry(ctx, acct.PrimaryEmail)
		if err != nil {
			fmt.Printf("❌ Error checking account existence: %v\n\n", err)
			failedCount++
			continue
		}

		if !exists {
			fmt.Printf("⏭️  Account already purged, skipping\n\n")
			skippedCount++
			continue
		}

		// Purge this account (reuse the purge logic)
		err = purgeAccount(ctx, cfg, rdb, acct.AccountID, acct.PrimaryEmail)
		if err != nil {
			fmt.Printf("❌ Failed to purge account: %v\n\n", err)
			failedCount++
			continue
		}

		fmt.Printf("✅ Successfully purged account: %s\n\n", acct.PrimaryEmail)
		successCount++
	}

	// Summary
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("SUMMARY\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Total accounts:    %d\n", len(accounts))
	fmt.Printf("✅ Purged:          %d\n", successCount)
	fmt.Printf("⏭️  Already purged:  %d\n", skippedCount)
	fmt.Printf("❌ Failed:          %d\n", failedCount)

	if failedCount > 0 {
		return fmt.Errorf("%d account(s) failed to purge - re-run command to retry", failedCount)
	}

	return nil
}

// purgeAccount purges a single account (extracted from deleteAccount for reuse)
func purgeAccount(ctx context.Context, cfg AdminConfig, rdb *resilient.ResilientDatabase, accountID int64, email string) error {
	return purgeAccountWithStorage(ctx, cfg, rdb, accountID, email, nil)
}

// purgeAccountWithStorage purges a single account with optional pre-configured storage
// If s3Storage is nil, it will be created from cfg
func purgeAccountWithStorage(ctx context.Context, cfg AdminConfig, rdb *resilient.ResilientDatabase, accountID int64, email string, s3Storage objectStorage) error {
	fmt.Printf("Purging all data for account: %s\n", email)

	// Initialize S3 storage if not provided
	if s3Storage == nil {
		useSSL := !cfg.S3.DisableTLS
		realS3, err := storage.New(
			cfg.S3.Endpoint,
			cfg.S3.AccessKey,
			cfg.S3.SecretKey,
			cfg.S3.Bucket,
			useSSL,
			false, // debug mode
		)
		if err != nil {
			return fmt.Errorf("failed to initialize S3 storage: %w", err)
		}

		// Enable encryption if configured
		if cfg.S3.Encrypt {
			if err := realS3.EnableEncryption(cfg.S3.EncryptionKey); err != nil {
				return fmt.Errorf("failed to enable S3 encryption: %w", err)
			}
		}

		s3Storage = realS3
	}

	// Step 1: Mark all messages as expunged (atomic, idempotent)
	// We do this first so we can safely delete them.
	// Even if this returns 0 (already expunged), we proceed to check for any remaining S3 objects.
	fmt.Printf("Step 1: Marking messages as expunged...\n")
	expungedCount, err := rdb.ExpungeAllMessagesForAccount(ctx, accountID)
	if err != nil {
		return fmt.Errorf("failed to expunge messages: %w", err)
	}
	fmt.Printf("✓ Marked %d messages as expunged (or already expunged)\n", expungedCount)

	// Step 2: Delete S3 objects and clean up DB
	// We iterate in batches: Fetch -> Delete S3 -> Delete DB
	fmt.Printf("\nStep 2: Deleting S3 objects and database records...\n")

	totalS3Deletes := 0
	totalDBDeletes := int64(0)
	const batchSize = 1000

	for {
		// Fetch batch of uploaded objects
		// We use GetAllUploadedObjectsForAccount which filters by uploaded=TRUE.
		// Since we delete records in each iteration, this acts as pagination.
		batch, err := rdb.GetAllUploadedObjectsForAccount(ctx, accountID, batchSize)
		if err != nil {
			return fmt.Errorf("failed to scan S3 objects: %w", err)
		}

		if len(batch) == 0 {
			break
		}

		fmt.Printf("  Processing batch of %d objects...\n", len(batch))

		// Build S3 keys
		s3Keys := make([]string, 0, len(batch))
		keyToCandidate := make(map[string]db.UserScopedObjectForCleanup, len(batch))
		for _, candidate := range batch {
			s3Key := helpers.NewS3Key(candidate.S3Domain, candidate.S3Localpart, candidate.ContentHash)
			s3Keys = append(s3Keys, s3Key)
			keyToCandidate[s3Key] = candidate
		}

		// Delete from S3
		var successfulDeletes []db.UserScopedObjectForCleanup
		var failedDeletes int

		if realS3, ok := s3Storage.(*storage.S3Storage); ok {
			// Bulk delete
			errors := realS3.DeleteBulk(s3Keys)
			for _, s3Key := range s3Keys {
				if err, failed := errors[s3Key]; failed {
					fmt.Printf("    Warning: Failed to delete %s: %v\n", s3Key, err)
					failedDeletes++
				} else {
					successfulDeletes = append(successfulDeletes, keyToCandidate[s3Key])
					fmt.Printf("    Deleted S3 key: %s\n", s3Key)
				}
			}
		} else {
			// One-by-one
			for _, s3Key := range s3Keys {
				err := s3Storage.Delete(s3Key)
				if err != nil {
					fmt.Printf("    Warning: Failed to delete %s: %v\n", s3Key, err)
					failedDeletes++
				} else {
					successfulDeletes = append(successfulDeletes, keyToCandidate[s3Key])
					fmt.Printf("    Deleted S3 key: %s\n", s3Key)
				}
			}
		}

		// Update stats
		totalS3Deletes += len(successfulDeletes)

		// Delete from DB (only successful S3 deletions)
		if len(successfulDeletes) > 0 {
			deleted, err := rdb.DeleteExpungedMessagesByS3KeyPartsBatchWithRetry(ctx, successfulDeletes)
			if err != nil {
				return fmt.Errorf("failed to delete messages from DB: %w", err)
			}
			totalDBDeletes += deleted
			fmt.Printf("    ✓ Deleted %d S3 objects and %d DB records this batch\n", len(successfulDeletes), deleted)
		} else if failedDeletes > 0 && len(batch) > 0 {
			// If we found objects but failed to delete ANY of them, we are stuck.
			// The next iteration will find the same objects.
			return fmt.Errorf("failed to delete any S3 objects in current batch (%d failed). Aborting to prevent infinite loop", failedDeletes)
		}
	}

	fmt.Printf("\n✓ Successfully cleaned up %d S3 objects and %d message records\n", totalS3Deletes, totalDBDeletes)

	// Step 3: Delete mailboxes, credentials, account
	fmt.Printf("\nStep 3: Removing account data...\n")

	if err := rdb.PurgeMailboxesForAccount(ctx, accountID); err != nil {
		return fmt.Errorf("failed to purge mailboxes: %w", err)
	}
	fmt.Printf("✓ Deleted mailboxes\n")

	if err := rdb.PurgeCredentialsForAccount(ctx, accountID); err != nil {
		return fmt.Errorf("failed to purge credentials: %w", err)
	}
	fmt.Printf("✓ Deleted credentials\n")

	if err := rdb.PurgeAccount(ctx, accountID); err != nil {
		return fmt.Errorf("failed to purge account: %w", err)
	}
	fmt.Printf("✓ Deleted account\n")

	return nil
}
