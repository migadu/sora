package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/migadu/sora/pkg/resilient"
)

// handleMailboxRepairUnseen reports the mailboxes whose cached unseen count is above the
// number of unseen messages they hold and, with --apply, recomputes them.
func handleMailboxRepairUnseen(ctx context.Context) {
	fs := flag.NewFlagSet("mailbox repair-unseen", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (optional, all accounts if omitted)")
	apply := fs.Bool("apply", false, "Recompute the unseen count of each mailbox found (default: report only)")
	batchSize := fs.Int("batch-size", 200, "Number of mailboxes checked per batch")
	startAfter := fs.Int64("start-after", 0, "Resume after this mailbox id, as printed by an interrupted run")

	fs.Usage = func() {
		fmt.Printf(`Find and repair cached unseen counts that are too high

In older builds, a hard delete of an unseen message (failed-upload cleanup,
uploader resolve, importer rollback) left it counted in the cached unseen count
of its mailbox, which STATUS, LIST and NOTIFY report. This command compares
each mailbox's cached unseen count with the number of unseen messages it holds,
in batches of mailboxes in id order, and reports the mailboxes counted too high.
With --apply it recomputes each of them in its own short transaction under the
mailbox lock, like any flag change.

Usage:
  sora-admin mailbox repair-unseen --config PATH [--email EMAIL] [--apply] [--batch-size N] [--start-after ID]

Options:
  --config PATH       Path to TOML configuration file (required)
  --email EMAIL       Email address of a specific account (optional, all accounts if omitted)
  --apply             Repair the mailboxes found (default: dry run, report only)
  --batch-size N      Number of mailboxes checked per batch (default: 200)
  --start-after ID    Resume after this mailbox id, as printed by an interrupted run

Examples:
  # Report the mailboxes counted too high
  sora-admin mailbox repair-unseen --config config.toml

  # Repair them
  sora-admin mailbox repair-unseen --config config.toml --apply
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

	var accountID int64
	if *email != "" {
		if accountID, err = rdb.GetAccountIDByEmailWithRetry(ctx, *email); err != nil {
			fmt.Printf("Failed to find account: %v\n", err)
			os.Exit(1)
		}
	}

	if err := repairExcessUnseen(ctx, rdb, accountID, *startAfter, *batchSize, *apply); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

// repairExcessUnseen checks the mailboxes of accountID (of every account when it is 0)
// after mailbox id after, batchSize at a time, and prints those whose cached unseen
// count is too high. With apply it recomputes each of them (db.RecomputeMailboxUnseen),
// one transaction per mailbox: the scan holds no lock, and a repair holds only its own
// mailbox's row lock, for the time of one count.
func repairExcessUnseen(ctx context.Context, rdb *resilient.ResilientDatabase, accountID, after int64, batchSize int, apply bool) error {
	var checked, found, repaired int
	var total, largest int64
	for {
		batch, err := rdb.FindExcessUnseenCountsWithRetry(ctx, accountID, after, batchSize)
		if err != nil {
			return fmt.Errorf("failed to check mailboxes after id %d (resume with --start-after %d): %w", after, after, err)
		}
		if batch.Checked == 0 {
			break
		}
		for _, m := range batch.Excess {
			found++
			excess := m.Cached - m.Actual
			total += excess
			largest = max(largest, excess)
			if !apply {
				fmt.Printf("  WOULD REPAIR mailbox_id=%d account_id=%d %q unseen_count %d -> %d\n",
					m.MailboxID, m.AccountID, m.Name, m.Cached, m.Actual)
				continue
			}
			unseen, err := rdb.RecomputeMailboxUnseenWithRetry(ctx, m.MailboxID)
			if err != nil {
				return fmt.Errorf("failed to repair mailbox %d (resume with --start-after %d): %w", m.MailboxID, after, err)
			}
			repaired++
			fmt.Printf("  REPAIRED mailbox_id=%d account_id=%d %q unseen_count %d -> %d\n",
				m.MailboxID, m.AccountID, m.Name, m.Cached, unseen)
		}
		checked += batch.Checked
		after = batch.LastMailboxID
		fmt.Printf("Checked up to mailbox_id %d (resume with --start-after %d)\n", after, after)
	}

	fmt.Printf("Checked %d mailbox(es) with positive cached unseen counts: %d mailbox(es) with unseen_count too high, by %d in total (at most %d in one mailbox).\n",
		checked, found, total, largest)
	switch {
	case apply:
		fmt.Printf("Repaired %d mailbox(es).\n", repaired)
	case found > 0:
		fmt.Println("Dry run: nothing was changed. Run again with --apply to repair them.")
	}
	return nil
}
