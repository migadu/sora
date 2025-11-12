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
	"github.com/migadu/sora/pkg/resilient"
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
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
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
		fmt.Printf("\nFailed Uploads (showing up to %d):\n", failedLimit)
		fmt.Printf("%-10s %-10s %-64s %-8s %-12s %-19s %s\n", "ID", "Account ID", "Content Hash", "Size", "Attempts", "Created", "Instance ID")
		fmt.Printf("%s\n", strings.Repeat("-", 141))

		failedUploads, err := rdb.GetFailedUploadsWithRetry(ctx, cfg.Uploader.MaxAttempts, failedLimit)
		if err != nil {
			return fmt.Errorf("failed to get failed uploads: %w", err)
		}

		for _, upload := range failedUploads {
			fmt.Printf("%-10d %-10d %-64s %-8s %-12d %-19s %s\n",
				upload.ID,
				upload.AccountID,
				upload.ContentHash,
				formatBytes(upload.Size),
				upload.Attempts,
				upload.CreatedAt.Format("2006-01-02 15:04:05"),
				upload.InstanceID)
		}

		if int64(len(failedUploads)) < stats.FailedUploads {
			fmt.Printf("\n... and %d more failed uploads\n", stats.FailedUploads-int64(len(failedUploads)))
		}
	}

	return nil
}
