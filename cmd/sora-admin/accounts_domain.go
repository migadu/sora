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
	fmt.Printf("Step 1: Marking all messages as expunged...\n")
	expungedCount, err := rdb.ExpungeAllMessagesForAccount(ctx, accountID)
	if err != nil {
		return fmt.Errorf("failed to expunge messages: %w", err)
	}
	if expungedCount > 0 {
		fmt.Printf("✓ Marked %d messages as expunged\n", expungedCount)
	} else {
		fmt.Printf("✓ No messages to expunge (already expunged or none exist)\n")
	}

	// Step 2: Clean up expunged messages in batches (resumable)
	fmt.Printf("\nStep 2: Cleaning up messages from S3 and database (resumable)...\n")
	totalS3Deletes := 0
	totalDBDeletes := int64(0)
	totalFailed := 0
	batchNum := 0
	const batchSize = 100

	for {
		batchNum++

		// Check for context cancellation
		if ctx.Err() != nil {
			return fmt.Errorf("operation cancelled: %w (safe to resume)", ctx.Err())
		}

		// Fetch next batch (grace period = 0 for immediate cleanup)
		candidates, err := rdb.GetUserScopedObjectsForAccount(ctx, accountID, 0, batchSize)
		if err != nil {
			return fmt.Errorf("failed to fetch cleanup batch %d: %w", batchNum, err)
		}

		if len(candidates) == 0 {
			if batchNum == 1 {
				fmt.Printf("✓ No messages to clean up\n")
			} else {
				fmt.Printf("✓ All messages cleaned up (processed %d batches)\n", batchNum-1)
			}
			break
		}

		fmt.Printf("  Batch %d: Processing %d unique S3 objects...\n", batchNum, len(candidates))

		// Delete from S3 first (same pattern as cleanup worker)
		var successfulDeletes []db.UserScopedObjectForCleanup
		for _, candidate := range candidates {
			s3Key := helpers.NewS3Key(candidate.S3Domain, candidate.S3Localpart, candidate.ContentHash)
			err := s3Storage.Delete(s3Key)
			if err != nil {
				fmt.Printf("    Warning: Failed to delete %s: %v (will retry on next run)\n", s3Key, err)
				totalFailed++
				continue
			}
			successfulDeletes = append(successfulDeletes, candidate)
			totalS3Deletes++
		}

		// Delete from DB (only successfully deleted from S3)
		if len(successfulDeletes) > 0 {
			deleted, err := rdb.DeleteExpungedMessagesByS3KeyPartsBatchWithRetry(ctx, successfulDeletes)
			if err != nil {
				return fmt.Errorf("failed to delete messages from DB in batch %d: %w", batchNum, err)
			}
			totalDBDeletes += deleted
			fmt.Printf("    ✓ Deleted %d messages from DB\n", deleted)
		}

		// If full batch was processed, there might be more
		if len(candidates) < batchSize {
			fmt.Printf("✓ All messages cleaned up (processed %d batches)\n", batchNum)
			break
		}
	}

	if totalFailed > 0 {
		fmt.Printf("\n⚠ Warning: %d S3 objects failed to delete. Run command again to retry.\n", totalFailed)
		return fmt.Errorf("incomplete purge: %d S3 objects failed (safe to retry)", totalFailed)
	}

	if totalS3Deletes > 0 || totalDBDeletes > 0 {
		fmt.Printf("\n✓ Successfully cleaned up %d S3 objects and %d message records\n", totalS3Deletes, totalDBDeletes)
	}

	// Step 3: Delete mailboxes, credentials, account (only after all messages cleaned)
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
