package main

// uploader.go - Command handlers for uploader
// Extracted from main.go for better organization

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

func handleUploaderCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printUploaderUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "status":
		handleUploaderStatus(ctx)
	case "resolve":
		handleUploaderResolve(ctx)
	case "help", "--help", "-h":
		printUploaderUsage()
	default:
		fmt.Printf("Unknown uploader subcommand: %s\n\n", subcommand)
		printUploaderUsage()
		os.Exit(1)
	}
}

func handleUploaderStatus(ctx context.Context) {
	// Parse uploader status specific flags
	fs := flag.NewFlagSet("uploader status", flag.ExitOnError)

	showFailed := fs.Bool("show-failed", true, "Show failed uploads details")
	failedLimit := fs.Int("failed-limit", 10, "Maximum number of failed uploads to show")

	fs.Usage = func() {
		fmt.Printf(`Show uploader queue status and failed uploads

Usage:
  sora-admin uploader status [options]

Options:
  --config string        Path to TOML configuration file (required)
  --show-failed         Show failed uploads details (default: true)
  --failed-limit int    Maximum number of failed uploads to show (default: 10)

This command shows:
  - Number of pending uploads and total size
  - Number of failed uploads (reached max attempts)
  - Age of oldest pending upload
  - Details of failed uploads including content hashes and attempt counts

Examples:
  sora-admin uploader status
  sora-admin uploader status --config /path/to/config.toml
  sora-admin uploader status --failed-limit 20
  sora-admin uploader status --show-failed=false
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments

	// Show uploader status
	if err := showUploaderStatus(ctx, globalConfig, *showFailed, *failedLimit); err != nil {
		logger.Fatalf("Failed to show uploader status: %v", err)
	}
}

func handleUploaderResolve(ctx context.Context) {
	fs := flag.NewFlagSet("uploader resolve", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "Show what would be done without making changes")
	limit := fs.Int("limit", 100, "Maximum number of failed uploads to process")

	fs.Usage = func() {
		fmt.Printf(`Resolve failed uploads by checking S3 and repairing or removing stale records.

Usage:
  sora-admin uploader resolve [options]

Options:
  --dry-run     Show what would be done without making changes (default: false)
  --limit int   Maximum number of failed uploads to process (default: 100)

Actions taken per upload:
  [REPAIR] EXISTS in S3        → CompleteS3Upload: marks messages as uploaded=TRUE, removes pending record.
                               Users regain access to their messages immediately.
  [REARM]  body intact here    → ResetUploadAttempts: the staging file is still on this host, so the
                               upload was parked by something other than lost content; the uploader
                               on this host retries it on its next tick.
  [SKIP]   owned by other host → nothing: that host's spool may still hold the body. Run resolve there.
  [SKIP]   file size differs   → nothing: inspect manually.
  [DELETE] MISSING everywhere  → DeleteFailedUpload: removes undeliverable message rows and pending record.
                               Content is in neither S3 nor this host's spool; the message is lost.

Examples:
  sora-admin uploader resolve --dry-run
  sora-admin uploader resolve
  sora-admin uploader resolve --limit 50
`)
	}

	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	if err := resolveFailedUploads(ctx, globalConfig, *dryRun, *limit); err != nil {
		logger.Fatalf("Failed to resolve uploads: %v", err)
	}
}

func resolveFailedUploads(ctx context.Context, cfg AdminConfig, dryRun bool, limit int) error {
	rdb, err := newAdminDatabase(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	s3Timeout, err := cfg.S3.GetTimeout()
	if err != nil {
		return fmt.Errorf("invalid S3 timeout configuration: %w", err)
	}

	s3Storage, err := storage.New(
		cfg.S3.Endpoint,
		cfg.S3.AccessKey,
		cfg.S3.SecretKey,
		cfg.S3.Bucket,
		!cfg.S3.DisableTLS,
		false,
		s3Timeout,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize S3: %w", err)
	}
	if cfg.S3.Encrypt {
		if err := s3Storage.EnableEncryption(cfg.S3.EncryptionKey); err != nil {
			return fmt.Errorf("failed to enable S3 encryption: %w", err)
		}
	}

	failedUploads, err := rdb.GetFailedUploadsWithEmailWithRetry(ctx, cfg.Uploader.MaxAttempts, limit)
	if err != nil {
		return fmt.Errorf("failed to get failed uploads: %w", err)
	}

	if len(failedUploads) == 0 {
		fmt.Println("No failed uploads to resolve.")
		return nil
	}

	if dryRun {
		fmt.Println("DRY RUN - no changes will be made.")
	}

	// Resolve runs on one host, so only that host's spool can be inspected. A parked
	// upload whose body is still in the spool (a provider fault, not lost content —
	// see uploader.processSingleUpload) must be re-armed, never deleted with its message.
	localInstance := cfg.InstanceID()

	var resolved, rearmed, deleted, skipped int

	for _, upload := range failedUploads {
		// The keys come from the message rows, not from the account's current primary
		// address: one upload can stand behind rows keyed under different addresses
		// (the primary at the time each was written, or the address an import ran
		// under), and each key is judged on its own object. Keys whose object exists
		// are finalized right away; the spool decision below sees only the residue.
		keys, err := rdb.PendingUploadKeysWithRetry(ctx, upload.ContentHash, upload.AccountID)
		if err != nil {
			fmt.Printf("  [ERROR]  id=%-10d hash=%.16s... could not resolve storage keys: %v\n", upload.ID, upload.ContentHash, err)
			skipped++
			continue
		}
		var present, missing []string
		checkFailed := false
		for _, key := range keys {
			exists, _, checkErr := s3Storage.Exists(key)
			if checkErr != nil {
				fmt.Printf("  [ERROR]  id=%-10d hash=%.16s... S3 check failed for %s: %v\n", upload.ID, upload.ContentHash, key, checkErr)
				checkFailed = true
				break
			}
			if exists {
				present = append(present, key)
			} else {
				missing = append(missing, key)
			}
		}
		if checkFailed {
			skipped++
			continue
		}
		if len(present) > 0 {
			fmt.Printf("  [REPAIR] id=%-10d account=%-8d hash=%.16s... [OK] EXISTS in S3 under %s → CompleteS3Upload\n",
				upload.ID, upload.AccountID, upload.ContentHash, strings.Join(present, " "))
			if !dryRun {
				if err := rdb.CompleteS3UploadWithRetry(ctx, upload.ContentHash, upload.AccountID, present); err != nil {
					fmt.Printf("            ERROR: %v\n", err)
					skipped++
					continue
				}
			}
		}

		staged := stagedBodyState(uploader.StagingFilePath(cfg.Uploader.Path, upload.ContentHash, upload.AccountID), upload.Size)
		switch decideResolve(len(missing) == 0, upload.InstanceID == localInstance, staged) {
		case resolveRepair:
			// Every key this upload still had to write has its object, or nothing was
			// left to write: finalize what remains and clear the pending row.
			if len(present) == 0 {
				fmt.Printf("  [REPAIR] id=%-10d account=%-8d hash=%.16s... nothing left to write → CompleteS3Upload\n",
					upload.ID, upload.AccountID, upload.ContentHash)
				if !dryRun {
					if err := rdb.CompleteS3UploadWithRetry(ctx, upload.ContentHash, upload.AccountID, nil); err != nil {
						fmt.Printf("            ERROR: %v\n", err)
						skipped++
						continue
					}
				}
			}
			resolved++
		case resolveRearm:
			fmt.Printf("  [REARM]  id=%-10d account=%-8d hash=%.16s... body intact in %s → ResetUploadAttempts\n",
				upload.ID, upload.AccountID, upload.ContentHash, cfg.Uploader.Path)
			if !dryRun {
				if _, err := rdb.ResetUploadAttemptsWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
					fmt.Printf("            ERROR: %v\n", err)
					skipped++
					continue
				}
			}
			rearmed++
		case resolveSkipRemote:
			fmt.Printf("  [SKIP]   id=%-10d account=%-8d hash=%.16s... owned by %s — run resolve on that host\n",
				upload.ID, upload.AccountID, upload.ContentHash, upload.InstanceID)
			skipped++
		case resolveSkipSizeMismatch:
			fmt.Printf("  [SKIP]   id=%-10d account=%-8d hash=%.16s... staged file size differs from the row (%d bytes expected) — inspect manually\n",
				upload.ID, upload.AccountID, upload.ContentHash, upload.Size)
			skipped++
		case resolveDelete:
			// Content is in neither S3 nor this host's spool - the message is lost. Clean up.
			fmt.Printf("  [DELETE] id=%-10d account=%-8d hash=%.16s... [FAIL] MISSING in S3 and in spool → DeleteFailedUpload\n",
				upload.ID, upload.AccountID, upload.ContentHash)
			if !dryRun {
				n, err := rdb.DeleteFailedUploadWithRetry(ctx, upload.ContentHash, upload.AccountID)
				if err != nil {
					fmt.Printf("            ERROR: %v\n", err)
					skipped++
					continue
				}
				fmt.Printf("            Deleted %d message row(s)\n", n)
			}
			deleted++
		}
	}

	fmt.Printf("\nSummary: %d repaired ([OK] EXISTS), %d re-armed (body intact here), %d deleted ([FAIL] MISSING), %d skipped\n", resolved, rearmed, deleted, skipped)
	if dryRun {
		fmt.Println("(dry run - run without --dry-run to apply changes)")
	}
	return nil
}

func printUploaderUsage() {
	fmt.Printf(`Upload Queue Management

Usage:
  sora-admin uploader <subcommand> [options]

Subcommands:
  status   Show uploader queue status and failed uploads
  resolve  Resolve failed uploads: repair [OK] EXISTS entries, delete [FAIL] MISSING entries

Examples:
  sora-admin uploader status
  sora-admin uploader status --show-failed=false
  sora-admin uploader status --failed-limit 20
  sora-admin uploader resolve --dry-run
  sora-admin uploader resolve

Use 'sora-admin uploader <subcommand> --help' for detailed help.
`)
}

func showUploaderStatus(ctx context.Context, cfg AdminConfig, showFailed bool, failedLimit int) error {
	// Connect to database
	rdb, err := newAdminDatabase(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Validate retry interval parsing (for config validation)
	cfg.Uploader.GetRetryIntervalWithDefault()

	// Get uploader statistics
	stats, err := rdb.GetUploaderStatsWithRetry(ctx, cfg.Uploader.MaxAttempts)
	if err != nil {
		return fmt.Errorf("failed to get uploader stats: %w", err)
	}

	// Display uploader status
	fmt.Printf("Uploader Status\n")
	fmt.Printf("===============\n\n")
	fmt.Printf("Configuration:\n")
	fmt.Printf("  Upload path:        %s\n", cfg.Uploader.Path)
	fmt.Printf("  Batch size:         %d\n", cfg.Uploader.BatchSize)
	fmt.Printf("  Concurrency:        %d\n", cfg.Uploader.Concurrency)
	fmt.Printf("  Max attempts:       %d\n", cfg.Uploader.MaxAttempts)
	fmt.Printf("  Retry interval:     %s\n", cfg.Uploader.RetryInterval)
	fmt.Printf("\n")

	fmt.Printf("Queue Status:\n")
	fmt.Printf("  Pending uploads:    %d\n", stats.TotalPending)
	fmt.Printf("  Pending size:       %d bytes (%s)\n", stats.TotalPendingSize, formatBytes(stats.TotalPendingSize))
	fmt.Printf("  Failed uploads:     %d\n", stats.FailedUploads)

	if stats.OldestPending.Valid {
		age := time.Since(stats.OldestPending.Time)
		fmt.Printf("  Oldest pending:     %s (age: %s)\n", stats.OldestPending.Time.Format(time.RFC3339), formatDuration(age))
	} else {
		fmt.Printf("  Oldest pending:     N/A\n")
	}

	// Get per-instance breakdown
	instanceStats, err := rdb.GetPendingUploadsByInstanceWithRetry(ctx)
	if err != nil {
		logger.Warn("Failed to get per-instance breakdown", "error", err)
	} else if len(instanceStats) > 0 {
		fmt.Printf("\nPending Uploads by Instance:\n")
		for _, inst := range instanceStats {
			fmt.Printf("  %-40s %d\n", inst.InstanceID, inst.Count)
		}
	}

	// Show failed uploads if requested
	if showFailed && stats.FailedUploads > 0 {
		// Initialize S3 storage for checking existence
		s3Timeout, err := cfg.S3.GetTimeout()
		if err != nil {
			logger.Warn("Invalid S3 timeout configuration (S3 Status column will show 'N/A')", "error", err)
		}

		var s3Storage *storage.S3Storage
		if err == nil {
			s3Storage, err = storage.New(
				cfg.S3.Endpoint,
				cfg.S3.AccessKey,
				cfg.S3.SecretKey,
				cfg.S3.Bucket,
				!cfg.S3.DisableTLS,
				false,
				s3Timeout,
			)
			if err != nil {
				logger.Warn("Failed to initialize S3 (S3 Status column will show 'N/A')", "error", err)
				s3Storage = nil
			}
		}
		if s3Storage != nil && cfg.S3.Encrypt {
			if err := s3Storage.EnableEncryption(cfg.S3.EncryptionKey); err != nil {
				logger.Warn("Failed to enable S3 encryption (S3 Status column will show 'N/A')", "error", err)
				s3Storage = nil
			}
		}

		fmt.Printf("\nFailed Uploads (showing up to %d):\n", failedLimit)
		fmt.Printf("%-10s %-10s %-64s %-8s %-12s %-12s %-19s %s\n", "ID", "Account ID", "Content Hash", "Size", "Attempts", "S3 Status", "Created", "Instance ID")
		fmt.Printf("%s\n", strings.Repeat("-", 155))

		failedUploads, err := rdb.GetFailedUploadsWithEmailWithRetry(ctx, cfg.Uploader.MaxAttempts, failedLimit)
		if err != nil {
			return fmt.Errorf("failed to get failed uploads: %w", err)
		}

		// Check S3 existence for each upload
		for _, upload := range failedUploads {
			s3Status := "N/A"

			if s3Storage != nil && upload.AccountEmail != "" {
				parts := strings.Split(upload.AccountEmail, "@")
				if len(parts) == 2 {
					s3Key := fmt.Sprintf("%s/%s/%s", parts[1], parts[0], upload.ContentHash)
					exists, _, checkErr := s3Storage.Exists(s3Key)
					if checkErr == nil {
						if exists {
							s3Status = "[OK] EXISTS"
						} else {
							s3Status = "[FAIL] MISSING"
						}
					}
				}
			}

			fmt.Printf("%-10d %-10d %-64s %-8s %-12d %-12s %-19s %s\n",
				upload.ID,
				upload.AccountID,
				upload.ContentHash,
				formatBytes(upload.Size),
				upload.Attempts,
				s3Status,
				upload.CreatedAt.Format("2006-01-02 15:04:05"),
				upload.InstanceID)
		}

		if int64(len(failedUploads)) < stats.FailedUploads {
			fmt.Printf("\n... and %d more failed uploads\n", stats.FailedUploads-int64(len(failedUploads)))
		}
	}

	return nil
}

// resolveOutcome is what `uploader resolve` does with one parked upload.
type resolveOutcome int

const (
	resolveRepair           resolveOutcome = iota // object in S3: finalize the row
	resolveRearm                                  // body intact in this host's spool: let the uploader retry
	resolveSkipRemote                             // owned by another host whose spool cannot be seen from here
	resolveSkipSizeMismatch                       // a file is here but disagrees with the row: a human decides
	resolveDelete                                 // in neither S3 nor this host's spool: the content is lost
)

// stagedBody is what this host's spool holds for an upload.
type stagedBody int

const (
	stagedAbsent       stagedBody = iota
	stagedIntact                  // present with exactly the row's size
	stagedSizeMismatch            // present with a different size
)

// stagedBodyState inspects the spool file for an upload.
func stagedBodyState(path string, expectedSize int64) stagedBody {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return stagedAbsent
	}
	if info.Size() != expectedSize {
		return stagedSizeMismatch
	}
	return stagedIntact
}

// decideResolve picks the action for one parked upload. Deletion is the last resort and
// is only reached for an upload this host owns whose body is provably in neither place:
// a row owned by another host is never deleted from here, because that host's spool —
// which this host cannot see — may still hold the body.
func decideResolve(inS3 bool, ownedHere bool, staged stagedBody) resolveOutcome {
	if inS3 {
		return resolveRepair
	}
	if !ownedHere {
		return resolveSkipRemote
	}
	switch staged {
	case stagedIntact:
		return resolveRearm
	case stagedSizeMismatch:
		return resolveSkipSizeMismatch
	default:
		return resolveDelete
	}
}
