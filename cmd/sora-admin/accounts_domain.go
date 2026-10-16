package main

// accounts_domain.go - Domain-level account operations

import (
	"context"
	"fmt"

	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/cleaner"
	"github.com/migadu/sora/storage"
)

// purgeDomain purges all accounts for a given domain
// It's resumable - accounts already purged are skipped
func purgeDomain(ctx context.Context, cfg AdminConfig, domain string) error {
	// Connect to resilient database
	rdb, err := newAdminDatabase(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	return purgeDomainWithStorage(ctx, cfg, rdb, domain, nil)
}

// purgeDomainWithStorage is purgeDomain on a given database and storage. If s3Storage is
// nil, each account's purge creates it from cfg.
func purgeDomainWithStorage(ctx context.Context, cfg AdminConfig, rdb *resilient.ResilientDatabase, domain string, s3Storage objectStorage) error {
	fmt.Printf("Scanning for accounts in domain: %s\n\n", domain)

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
		fmt.Printf("===================================================\n")
		fmt.Printf("Account %d/%d: %s (ID: %d)\n", i+1, len(accounts), acct.PrimaryEmail, acct.AccountID)
		fmt.Printf("===================================================\n\n")

		// Check if already purged (account doesn't exist in DB anymore)
		result, err := rdb.AccountExistsWithRetry(ctx, acct.PrimaryEmail)
		if err != nil {
			fmt.Printf("[FAIL] Error checking account existence: %v\n\n", err)
			failedCount++
			continue
		}

		if !result.Exists {
			fmt.Printf("[SKIP] Account already purged, skipping\n\n")
			skippedCount++
			continue
		}

		// Purge this account (reuse the purge logic)
		err = purgeAccountWithStorage(ctx, cfg, rdb, acct.AccountID, acct.PrimaryEmail, s3Storage)
		if err != nil {
			fmt.Printf("[FAIL] Failed to purge account: %v\n\n", err)
			failedCount++
			continue
		}

		fmt.Printf("[OK] Successfully purged account: %s\n\n", acct.PrimaryEmail)
		successCount++
	}

	// Remove cross-domain aliases for this domain. Accounts whose PRIMARY identity is in the
	// domain were purged above. Any credential still in this domain is a non-primary alias on
	// an account whose primary lives elsewhere — without removal it keeps receiving mail for
	// the (now decommissioned) domain. A credential address is a deliverable address, so this
	// is required to fully offboard the domain.
	aliasAddrs, err := rdb.GetAliasCredentialsByDomain(ctx, domain)
	if err != nil {
		return fmt.Errorf("failed to scan for cross-domain aliases: %w", err)
	}

	aliasDeleted := 0
	aliasFailed := 0
	if len(aliasAddrs) > 0 {
		fmt.Printf("===================================================\n")
		fmt.Printf("Cross-domain aliases in %s (on accounts kept alive)\n", domain)
		fmt.Printf("===================================================\n\n")
		for _, addr := range aliasAddrs {
			if err := rdb.DeleteCredentialWithRetry(ctx, addr); err != nil {
				fmt.Printf("[FAIL] %s: %v\n", addr, err)
				aliasFailed++
				continue
			}
			fmt.Printf("[OK] Removed alias: %s\n", addr)
			aliasDeleted++
		}
		fmt.Printf("\n")
	}

	// Summary
	fmt.Printf("===================================================\n")
	fmt.Printf("SUMMARY\n")
	fmt.Printf("===================================================\n")
	fmt.Printf("Total accounts:    %d\n", len(accounts))
	fmt.Printf("[OK] Purged:          %d\n", successCount)
	fmt.Printf("[SKIP] Already purged:  %d\n", skippedCount)
	fmt.Printf("[FAIL] Failed:          %d\n", failedCount)
	fmt.Printf("[OK] Aliases removed: %d\n", aliasDeleted)
	if aliasFailed > 0 {
		fmt.Printf("[FAIL] Aliases failed:  %d\n", aliasFailed)
	}

	if failedCount > 0 || aliasFailed > 0 {
		return fmt.Errorf("%d account(s) and %d alias(es) failed to purge - re-run command to retry", failedCount, aliasFailed)
	}

	return nil
}

// purgeAccount purges a single account (extracted from deleteAccount for reuse)
func purgeAccount(ctx context.Context, cfg AdminConfig, rdb *resilient.ResilientDatabase, accountID int64, email string) error {
	return purgeAccountWithStorage(ctx, cfg, rdb, accountID, email, nil)
}

// purgeAccountWithStorage purges a single account with the server's own purge (see
// cleaner.PurgeAccount): it takes the account out of service, then deletes its
// mailboxes, messages, S3 objects, search index, credentials and the account itself. A
// failure leaves the account out of service with its address, and running the command
// again resumes it. If s3Storage is nil, it is created from cfg.
func purgeAccountWithStorage(ctx context.Context, cfg AdminConfig, rdb *resilient.ResilientDatabase, accountID int64, email string, s3Storage objectStorage) error {
	fmt.Printf("Purging all data for account: %s\n", email)

	if s3Storage == nil {
		realS3, err := newPurgeStorage(cfg)
		if err != nil {
			return err
		}
		s3Storage = realS3
	}

	// The same mark the Admin API sets: if this run does not finish, a purge worker on
	// a node with object storage does, and the request is visible meanwhile.
	markedID, _, err := rdb.RequestAccountPurgeWithRetry(ctx, email)
	if err != nil {
		return fmt.Errorf("failed to take the account out of service: %w", err)
	}
	if markedID != accountID {
		return fmt.Errorf("%s belongs to account %d, not %d; nothing was purged", email, markedID, accountID)
	}
	fmt.Printf("[OK] Account out of service and marked for purging (no new logins or deliveries); sessions already open stay until kicked: sora-admin connections kick --user %s\n", email)

	stats, err := cleaner.PurgeAccount(ctx, rdb, purgeDeleter(s3Storage), accountID)
	fmt.Printf("Deleted %d S3 objects and %d message records\n", stats.S3Objects, stats.Messages)
	if err != nil {
		return fmt.Errorf("purge incomplete (the account stays out of service and marked; the server's purge worker finishes it, or run the command again): %w", err)
	}
	fmt.Printf("[OK] Account, mailboxes, messages and credentials deleted\n")
	return nil
}

// newPurgeStorage creates the S3 client a purge deletes bodies with, from cfg.
func newPurgeStorage(cfg AdminConfig) (objectStorage, error) {
	s3Timeout, err := cfg.S3.GetTimeout()
	if err != nil {
		return nil, fmt.Errorf("failed to parse S3 timeout: %w", err)
	}
	realS3, err := storage.New(
		cfg.S3.Endpoint,
		cfg.S3.AccessKey,
		cfg.S3.SecretKey,
		cfg.S3.Bucket,
		!cfg.S3.DisableTLS,
		false, // debug mode
		s3Timeout,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize S3 storage: %w", err)
	}
	if cfg.S3.Encrypt {
		if err := realS3.EnableEncryption(cfg.S3.EncryptionKey); err != nil {
			return nil, fmt.Errorf("failed to enable S3 encryption: %w", err)
		}
	}
	return realS3, nil
}

// purgeDeleter adapts the admin tool's storage to the purge: the real S3 client deletes
// in bulk through the same resilient wrapper the server uses; anything else (a test
// double) one key at a time.
func purgeDeleter(st objectStorage) cleaner.S3BulkDeleter {
	if realS3, ok := st.(*storage.S3Storage); ok {
		return resilient.NewResilientS3Storage(realS3)
	}
	return keyByKeyDeleter{st}
}

type keyByKeyDeleter struct{ st objectStorage }

func (d keyByKeyDeleter) DeleteBulkWithRetry(_ context.Context, keys []string) map[string]error {
	failed := make(map[string]error)
	for _, key := range keys {
		if err := d.st.Delete(key); err != nil {
			failed[key] = err
		}
	}
	return failed
}
