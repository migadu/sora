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

func printUploaderUsage() {
	fmt.Printf(`Upload Queue Management

Usage:
  sora-admin uploader <subcommand> [options]

Subcommands:
  status   Show uploader queue status and failed uploads

Examples:
  sora-admin uploader status
  sora-admin uploader status --show-failed=false
  sora-admin uploader status --failed-limit 20

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

	// Show failed uploads if requested
	if showFailed && stats.FailedUploads > 0 {
		// Initialize S3 storage for checking existence
		s3Storage, err := storage.New(
			cfg.S3.Endpoint,
			cfg.S3.AccessKey,
			cfg.S3.SecretKey,
			cfg.S3.Bucket,
			!cfg.S3.DisableTLS,
			false,
		)
		if err != nil {
			logger.Warn("Failed to initialize S3 (S3 Status column will show 'N/A')", "error", err)
			s3Storage = nil
		} else if cfg.S3.Encrypt {
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
							s3Status = "✓ EXISTS"
						} else {
							s3Status = "✗ MISSING"
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
