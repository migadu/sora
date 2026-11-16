package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/storage"
)

// repairHeaderPresenceProgressEvery controls how often "messages repair-header-presence"
// prints progress. Tests set it to 0 for a line after every batch.
var repairHeaderPresenceProgressEvery = 10 * time.Second

// newRepairHeaderPresenceStorage constructs the S3 client used with --from-s3. Tests may
// override this variable to supply an in-memory or file-based mock.
var newRepairHeaderPresenceStorage = func(cfg config.S3Config) (objectStorage, error) {
	s3Timeout, err := cfg.GetTimeout()
	if err != nil {
		return nil, fmt.Errorf("invalid S3 timeout configuration: %w", err)
	}
	s3Storage, err := storage.New(
		cfg.Endpoint,
		cfg.AccessKey,
		cfg.SecretKey,
		cfg.Bucket,
		!cfg.DisableTLS,
		false,
		s3Timeout,
		storage.WithRegion(cfg.Region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize S3 storage: %w", err)
	}
	if cfg.Encrypt {
		if err := s3Storage.EnableEncryption(cfg.EncryptionKey); err != nil {
			return nil, fmt.Errorf("failed to enable S3 encryption: %w", err)
		}
	}
	return s3Storage, nil
}

func handleRepairHeaderPresence(ctx context.Context) {
	fs := flag.NewFlagSet("messages repair-header-presence", flag.ExitOnError)
	apply := fs.Bool("apply", false, "Fill the rows that can be filled (default: report only)")
	fromS3 := fs.Bool("from-s3", false, "Read RFC 5322 headers from S3 for uploaded rows with no database donor")
	batchSize := fs.Int("batch-size", 1000, "Number of message rows read per batch")
	startAfter := fs.Int64("start-after", 0, "Resume after this message id, as printed by an interrupted run")

	fs.Usage = func() {
		fmt.Printf(`Fill in the stored header_presence bitmask of messages that have none

Messages stored before migration 000070 (which added header_presence without a
backfill), and messages copied, moved, or restored from them, have a NULL
header_presence. While NULL, empty SEARCH HEADER From/To/Cc "" and FROM/TO/CC ""
keep their legacy predicates and match messages without the header.

This command scans the messages table in id order in batches. By default it uses
only PostgreSQL, filling live NULL rows from another row with the same body
(content hash) whose header_presence is known. With --from-s3 it also opens the
stored message object in S3 for uploaded rows that have no database donor,
reads only up to the blank line ending the RFC 5322 header block, and computes
their exact header_presence bitmask.

Each batch is read in one statement through the read pool and, with --apply,
updated in one short primary transaction with no session state. Running it
again is safe: filled rows are skipped.

Usage:
  sora-admin messages repair-header-presence --config PATH [--apply] [--from-s3] [--batch-size N] [--start-after ID]

Options:
  --config PATH       Path to TOML configuration file (required)
  --apply             Fill the rows that can be filled (default: dry run, report only)
  --from-s3           Inspect S3 headers for uploaded rows without a database donor
  --batch-size N      Number of message rows read per batch (default: 1000)
  --start-after ID    Resume after this message id, as printed by an interrupted run

Examples:
  # Count live rows without header_presence and how many have a database donor
  sora-admin messages repair-header-presence --config config.toml

  # Fill from database donors and S3 header blocks
  sora-admin messages repair-header-presence --config config.toml --from-s3 --apply
`)
	}

	fs.Parse(os.Args[3:])
	if *batchSize <= 0 {
		fmt.Println("Error: --batch-size must be positive")
		os.Exit(1)
	}
	if *startAfter < 0 {
		fmt.Println("Error: --start-after must not be negative")
		os.Exit(1)
	}

	var s3Store objectStorage
	if *fromS3 {
		var err error
		s3Store, err = newRepairHeaderPresenceStorage(globalConfig.S3)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	}

	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	if err := repairNullHeaderPresence(ctx, rdb, s3Store, *startAfter, *batchSize, *apply); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func repairNullHeaderPresence(ctx context.Context, rdb *resilient.ResilientDatabase, s3Store objectStorage, after int64, batchSize int, apply bool) error {
	start := after
	var scanned, missing, dbFillable, s3Fillable int
	var filled int64
	lastProgress := time.Now()

	for {
		batch, err := rdb.FindNullHeaderPresenceWithRetry(ctx, after, batchSize)
		if err != nil {
			return fmt.Errorf("failed to read messages after id %d (resume with --start-after %d): %w", after, after, err)
		}
		if batch.Scanned == 0 {
			break
		}

		fills := batch.Fills
		dbCount := len(batch.Fills)
		s3Count := 0

		if s3Store != nil && len(batch.NeedsS3) > 0 {
			perBatchCache := make(map[string]int16, len(batch.NeedsS3))
			perBatchFailed := make(map[string]bool)
			for _, cand := range batch.NeedsS3 {
				if !cand.Uploaded || cand.S3Domain == "" || cand.S3Localpart == "" || cand.ContentHash == "" {
					continue
				}
				key := helpers.NewS3Key(cand.S3Domain, cand.S3Localpart, cand.ContentHash)
				if mask, ok := perBatchCache[key]; ok {
					fills = append(fills, db.HeaderPresenceFill{ID: cand.ID, HeaderPresence: mask})
					s3Count++
					continue
				}
				if perBatchFailed[key] {
					continue
				}
				rc, getErr := s3Store.Get(key)
				if getErr != nil {
					logger.Warn("repair-header-presence: failed to open S3 object", "id", cand.ID, "key", key, "error", getErr)
					perBatchFailed[key] = true
					continue
				}
				mask, parseErr := helpers.ExtractRawHeaderPresenceFromReader(rc)
				_ = rc.Close()
				if parseErr != nil || mask == nil {
					logger.Warn("repair-header-presence: failed to read headers from S3 object", "id", cand.ID, "key", key, "error", parseErr)
					perBatchFailed[key] = true
					continue
				}
				perBatchCache[key] = *mask
				fills = append(fills, db.HeaderPresenceFill{ID: cand.ID, HeaderPresence: *mask})
				s3Count++
			}
		}

		if apply && len(fills) > 0 {
			n, err := rdb.FillNullHeaderPresenceWithRetry(ctx, fills)
			if err != nil {
				return fmt.Errorf("failed to fill messages after id %d (resume with --start-after %d): %w", after, after, err)
			}
			filled += n
		}

		scanned += batch.Scanned
		missing += batch.Missing
		dbFillable += dbCount
		s3Fillable += s3Count
		after = batch.LastID

		if time.Since(lastProgress) >= repairHeaderPresenceProgressEvery {
			lastProgress = time.Now()
			fillable := dbFillable + s3Fillable
			line := fmt.Sprintf("Checked up to id %d: %d live row(s) without header_presence, %d can be filled (%d from DB, %d from S3), %d cannot",
				after, missing, fillable, dbFillable, s3Fillable, missing-fillable)
			if apply {
				line += fmt.Sprintf(", %d filled", filled)
			}
			fmt.Printf("%s (resume with --start-after %d)\n", line, after)
		}
	}

	fillable := dbFillable + s3Fillable
	fmt.Printf("Checked %d message row(s) after id %d, up to id %d: %d live row(s) without header_presence; %d can be filled (%d from DB, %d from S3), %d cannot.\n",
		scanned, start, after, missing, fillable, dbFillable, s3Fillable, missing-fillable)
	switch {
	case apply:
		fmt.Printf("Filled %d row(s).\n", filled)
		if skipped := int64(fillable) - filled; skipped > 0 {
			fmt.Printf("%d row(s) were expunged or filled while the repair ran and were left as they are.\n", skipped)
		}
	case fillable > 0:
		fmt.Println("Dry run: nothing was changed. Run again with --apply to fill them.")
	}
	return nil
}
