package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/migadu/sora/pkg/resilient"
)

// repairStateProgressEvery is how often "messages repair-state" prints where it is: a run
// over a large table reads hundreds of thousands of batches. Tests set it to 0, for a
// line after every batch.
var repairStateProgressEvery = 10 * time.Second

// handleRepairMessageState counts the live messages that have no message_state row and,
// with --apply, gives each of them one with no flags.
func handleRepairMessageState(ctx context.Context) {
	fs := flag.NewFlagSet("messages repair-state", flag.ExitOnError)
	apply := fs.Bool("apply", false, "Give the messages found a state row (default: report only)")
	batchSize := fs.Int("batch-size", 1000, "Number of message rows read per batch")
	startAfter := fs.Int64("start-after", 0, "Resume after this message id, as printed by an interrupted run")

	fs.Usage = func() {
		fmt.Printf(`Give messages without a flag state row one with no flags

Older builds left some live messages without a message_state row, the row that
holds a message's flags and keywords: a database that ran migration 000022
without its copy of the flags, restores of messages whose mailbox had been
purged, and copies or moves of such messages. They are shown with no flags,
but SEARCH UNSEEN and the unseen counts leave them out. This command reads the
messages table in id order, in batches, and counts them. With --apply it gives
each one a row with no flags and no keywords, as it is shown now, and counts the
unseen messages of its mailbox again. It uses only the database and reads
nothing from S3: the flags an older build lost cannot be recovered.

Each batch is read in one statement on the primary and, with --apply, repaired
in one short transaction that locks the batch's mailboxes, with no session
state. After a batch it prints the id to resume from at most every 10 seconds;
an interrupted run prints it too. Running it again is safe: a repaired message
is not counted again.

Usage:
  sora-admin messages repair-state --config PATH [--apply] [--batch-size N] [--start-after ID]

Options:
  --config PATH       Path to TOML configuration file (required)
  --apply             Give the messages found a state row (default: dry run, report only)
  --batch-size N      Number of message rows read per batch (default: 1000)
  --start-after ID    Resume after this message id, as printed by an interrupted run

Examples:
  # Count the messages without a state row
  sora-admin messages repair-state --config config.toml

  # Repair them
  sora-admin messages repair-state --config config.toml --apply
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

	if err := repairMissingMessageState(ctx, rdb, *startAfter, *batchSize, *apply); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func repairMissingMessageState(ctx context.Context, rdb *resilient.ResilientDatabase, after int64, batchSize int, apply bool) error {
	start := after
	var scanned, missing int
	var added int64
	mailboxes := make(map[int64]struct{})
	lastProgress := time.Now()
	for {
		batch, err := rdb.FindMissingMessageStateWithRetry(ctx, after, batchSize)
		if err != nil {
			return fmt.Errorf("failed to read messages after id %d (resume with --start-after %d): %w", after, after, err)
		}
		if batch.Scanned == 0 {
			break
		}
		if apply && len(batch.Missing) > 0 {
			ids := make([]int64, len(batch.Missing))
			for i, m := range batch.Missing {
				ids[i] = m.ID
			}
			repair, err := rdb.AddMissingMessageStateWithRetry(ctx, ids)
			if err != nil {
				return fmt.Errorf("failed to repair messages after id %d (resume with --start-after %d): %w", after, after, err)
			}
			added += repair.Added
		}
		for _, m := range batch.Missing {
			mailboxes[m.MailboxID] = struct{}{}
		}
		scanned += batch.Scanned
		missing += len(batch.Missing)
		after = batch.LastID

		if time.Since(lastProgress) >= repairStateProgressEvery {
			lastProgress = time.Now()
			line := fmt.Sprintf("Checked up to id %d: %d live message(s) without a state row", after, missing)
			if apply {
				line += fmt.Sprintf(", %d repaired", added)
			}
			fmt.Printf("%s (resume with --start-after %d)\n", line, after)
		}
	}

	fmt.Printf("Checked %d message row(s) after id %d, up to id %d: %d live message(s) without a state row, in %d mailbox(es).\n",
		scanned, start, after, missing, len(mailboxes))
	switch {
	case apply:
		fmt.Printf("Gave %d message(s) a state row with no flags and counted the unseen messages of their mailboxes again.\n", added)
		if skipped := int64(missing) - added; skipped > 0 {
			fmt.Printf("%d message(s) were expunged or given a state row while the repair ran and were left as they are.\n", skipped)
		}
	case missing > 0:
		fmt.Println("Dry run: nothing was changed. Run again with --apply to repair them.")
	}
	return nil
}
