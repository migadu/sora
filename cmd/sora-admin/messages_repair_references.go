package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/migadu/sora/pkg/resilient"
)

// repairReferencesProgressEvery is how often "messages repair-references" prints where it
// is: a run over a large table reads hundreds of thousands of batches. Tests set it to 0,
// for a line after every batch.
var repairReferencesProgressEvery = 10 * time.Second

// handleRepairReferences counts the live messages whose stored References is NULL and,
// with --apply, fills each from another row with the same body.
func handleRepairReferences(ctx context.Context) {
	fs := flag.NewFlagSet("messages repair-references", flag.ExitOnError)
	apply := fs.Bool("apply", false, "Fill the rows that can be filled (default: report only)")
	batchSize := fs.Int("batch-size", 1000, "Number of message rows read per batch")
	startAfter := fs.Int64("start-after", 0, "Resume after this message id, as printed by an interrupted run")

	fs.Usage = func() {
		fmt.Printf(`Fill in the stored References of messages that have none

Messages copied or moved by older builds, and messages stored before the
References column was added (migration 000036), have no stored References
(NULL). SEARCH HEADER References does not find them, and THREAD links them by
In-Reply-To only. This command reads the messages table in id order, in batches,
and counts the live messages without a stored References. With --apply it fills
each of them with the value stored for another message row with the same body
(content hash), which has the same References header. It uses only the database
and reads nothing from S3, so a message whose body no other row has a value for
cannot be filled: it is counted and left as it is.

Each batch is read from the primary in one statement and, with --apply, filled
in one short transaction on the primary, with no session state. Admin CLI
commands skip configured read replicas; database.read does not redirect this scan. After a batch it prints the id to resume from at most
every 10 seconds; an interrupted run prints it too. Running it again is safe: a
filled row is not counted again.

Usage:
  sora-admin messages repair-references --config PATH [--apply] [--batch-size N] [--start-after ID]

Options:
  --config PATH       Path to TOML configuration file (required)
  --apply             Fill the rows that can be filled (default: dry run, report only)
  --batch-size N      Number of message rows read per batch (default: 1000)
  --start-after ID    Resume after this message id, as printed by an interrupted run

Examples:
  # Count the messages without stored References, and how many can be filled
  sora-admin messages repair-references --config config.toml

  # Fill them
  sora-admin messages repair-references --config config.toml --apply
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

	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	if err := repairNullReferences(ctx, rdb, *startAfter, *batchSize, *apply); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

// repairNullReferences reads the messages after id after, batchSize rows at a time, and
// counts the live rows whose "references" is NULL and those another row with the same
// body holds a value for. With apply it fills those in a transaction per batch
// (db.FillNullReferences), after the batch's read and before the next one, so the resume
// point it prints never skips a batch whose fills were not written.
func repairNullReferences(ctx context.Context, rdb *resilient.ResilientDatabase, after int64, batchSize int, apply bool) error {
	start := after
	var scanned, missing, fillable int
	var filled int64
	lastProgress := time.Now()
	for {
		batch, err := rdb.FindNullReferencesWithRetry(ctx, after, batchSize)
		if err != nil {
			return fmt.Errorf("failed to read messages after id %d (resume with --start-after %d): %w", after, after, err)
		}
		if batch.Scanned == 0 {
			break
		}
		if apply && len(batch.Fills) > 0 {
			n, err := rdb.FillNullReferencesWithRetry(ctx, batch.Fills)
			if err != nil {
				return fmt.Errorf("failed to fill messages after id %d (resume with --start-after %d): %w", after, after, err)
			}
			filled += n
		}
		scanned += batch.Scanned
		missing += batch.Missing
		fillable += len(batch.Fills)
		after = batch.LastID

		if time.Since(lastProgress) >= repairReferencesProgressEvery {
			lastProgress = time.Now()
			line := fmt.Sprintf("Checked up to id %d: %d live row(s) without References, %d can be filled, %d cannot",
				after, missing, fillable, missing-fillable)
			if apply {
				line += fmt.Sprintf(", %d filled", filled)
			}
			fmt.Printf("%s (resume with --start-after %d)\n", line, after)
		}
	}

	fmt.Printf("Checked %d message row(s) after id %d, up to id %d: %d live row(s) without References; %d can be filled from another row with the same body, %d cannot.\n",
		scanned, start, after, missing, fillable, missing-fillable)
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
