package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/migadu/sora/server/relayqueue"
)

func handleRelayCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printRelayUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "stats":
		handleRelayStats(ctx)
	case "list":
		handleRelayList(ctx)
	case "show":
		handleRelayShow(ctx)
	case "delete":
		handleRelayDelete(ctx)
	case "requeue":
		handleRelayRequeue(ctx)
	case "help", "--help", "-h":
		printRelayUsage()
	default:
		fmt.Printf("Unknown relay subcommand: %s\n\n", subcommand)
		printRelayUsage()
		os.Exit(1)
	}
}

// openExistingRelayQueue opens the relay queue at queuePath without creating any of its
// directories. NewDiskQueue creates the missing ones, and created by `sudo sora-admin`
// they would belong to root, where the server, running as its own user, cannot queue:
// these commands only work on a queue the server has made. A missing directory is
// reported as the *fs.PathError from os.Stat.
func openExistingRelayQueue(queuePath string, maxAttempts int) (*relayqueue.DiskQueue, error) {
	for _, dir := range []string{"failed", "pending", "processing"} {
		path := filepath.Join(queuePath, dir)
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("%s is not a directory", path)
		}
	}
	return relayqueue.NewDiskQueue(queuePath, maxAttempts, nil)
}

func handleRelayStats(_ context.Context) {
	flags := flag.NewFlagSet("relay stats", flag.ExitOnError)
	flags.Usage = func() {
		fmt.Printf(`Show relay queue statistics

Usage:
  sora-admin relay stats

Counts the messages in the pending, processing and failed queues of this host.

Examples:
  sora-admin --config config.toml relay stats
`)
	}
	flags.Parse(os.Args[3:])

	// Use global config for relay queue path
	cfg := globalConfig

	if !cfg.Relay.IsQueueEnabled() {
		fmt.Println("Relay is not configured (queue is enabled automatically when relay is configured)")
		os.Exit(1)
	}

	// Open the queue just for stats (no worker). On a node whose server has not created it
	// yet there is nothing to count, so say so, as list does.
	queuePath := cfg.Relay.GetQueuePath()
	queue, err := openExistingRelayQueue(queuePath, cfg.Relay.Queue.MaxAttempts)
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) && errors.Is(err, fs.ErrNotExist) {
		fmt.Printf("Queue directory does not exist: %s\n", pathErr.Path)
		fmt.Println("The server creates the relay queue when it starts with [relay] configured.")
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error accessing relay queue: %v\n", err)
		os.Exit(1)
	}

	// Get stats
	pending, processing, failed, err := queue.GetStats()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting stats: %v\n", err)
		os.Exit(1)
	}

	// Display stats. The settings are the ones the server runs with, defaults included.
	fmt.Println("Relay Queue Statistics")
	fmt.Println("======================")
	fmt.Printf("Queue Path:       %s\n", queuePath)
	fmt.Printf("Pending:          %d\n", pending)
	fmt.Printf("Processing:       %d\n", processing)
	fmt.Printf("Failed:           %d\n", failed)
	fmt.Printf("Total:            %d\n", pending+processing+failed)
	fmt.Printf("Max Attempts:     %d\n", queue.MaxAttempts())
	if interval, err := cfg.Relay.Queue.GetWorkerInterval(); err != nil {
		fmt.Printf("Worker Interval:  invalid (%v)\n", err)
	} else {
		fmt.Printf("Worker Interval:  %s\n", interval)
	}
}

func handleRelayList(_ context.Context) {
	flags := flag.NewFlagSet("relay list", flag.ExitOnError)
	queueType := flags.String("queue", "pending", "Queue to list (pending, processing, failed)")
	limit := flags.Int("limit", 100, "Maximum number of messages to display")
	flags.Usage = func() {
		fmt.Printf(`List messages in a relay queue

Usage:
  sora-admin relay list [options]

Options:
  --queue string  Queue to list: pending, processing, failed (default: pending)
  --limit int     Maximum number of messages to display (default: 100)

Examples:
  sora-admin --config config.toml relay list --queue failed --limit 50
`)
	}
	flags.Parse(os.Args[3:])

	// Use global config
	cfg := globalConfig

	if !cfg.Relay.IsQueueEnabled() {
		fmt.Println("Relay is not configured (queue is enabled automatically when relay is configured)")
		os.Exit(1)
	}

	// Determine queue directory
	var queueDir string
	switch *queueType {
	case "pending":
		queueDir = filepath.Join(cfg.Relay.GetQueuePath(), "pending")
	case "processing":
		queueDir = filepath.Join(cfg.Relay.GetQueuePath(), "processing")
	case "failed":
		queueDir = filepath.Join(cfg.Relay.GetQueuePath(), "failed")
	default:
		fmt.Fprintf(os.Stderr, "Invalid queue type: %s (must be pending, processing, or failed)\n", *queueType)
		os.Exit(1)
	}

	// Read directory
	entries, err := os.ReadDir(queueDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("Queue directory does not exist: %s\n", queueDir)
			fmt.Println("This may indicate the relay queue has never been used.")
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "Error reading queue directory: %v\n", err)
		os.Exit(1)
	}

	// Collect metadata files
	messages := []relayqueue.QueuedMessage{}
	count := 0
	for _, entry := range entries {
		if count >= *limit {
			break
		}
		if filepath.Ext(entry.Name()) == ".json" {
			metadataPath := filepath.Join(queueDir, entry.Name())
			data, err := os.ReadFile(metadataPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Could not read %s: %v\n", entry.Name(), err)
				continue
			}

			var msg relayqueue.QueuedMessage
			if err := json.Unmarshal(data, &msg); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Could not parse %s: %v\n", entry.Name(), err)
				continue
			}

			messages = append(messages, msg)
			count++
		}
	}

	// Display messages
	if len(messages) == 0 {
		fmt.Printf("No messages in %s queue\n", *queueType)
		return
	}

	fmt.Printf("%s Queue (%d messages)\n", *queueType, len(messages))
	fmt.Println(strings.Repeat("=", 80))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTYPE\tFROM\tTO\tATTEMPTS\tQUEUED\tNEXT RETRY")

	for _, msg := range messages {
		queuedStr := msg.QueuedAt.Format("2006-01-02 15:04:05")
		nextRetryStr := msg.NextRetry.Format("2006-01-02 15:04:05")
		if msg.NextRetry.IsZero() {
			nextRetryStr = "N/A"
		}

		// The full ID: show, delete and requeue take nothing shorter.
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			msg.ID, msg.Type, msg.From, msg.To, msg.Attempts, queuedStr, nextRetryStr)
	}
	w.Flush()

	if len(messages) >= *limit {
		fmt.Printf("\n(Showing first %d messages. Use --limit to see more)\n", *limit)
	}
}

func handleRelayShow(_ context.Context) {
	flags := flag.NewFlagSet("relay show", flag.ExitOnError)
	messageID := flags.String("id", "", "Message ID to display (required)")
	queueType := flags.String("queue", "pending", "Queue to search (pending, processing, failed)")
	flags.Usage = func() {
		fmt.Printf(`Show detailed information for a specific relay queue message

Usage:
  sora-admin relay show [options]

Options:
  --id string     Message ID to display (required)
  --queue string  Queue to search: pending, processing, failed (default: pending)

Examples:
  sora-admin --config config.toml relay show --id 3f2b9c1e-8d4a-4f6b-9a7e-2c5d1e0f4b8a --queue failed
`)
	}
	flags.Parse(os.Args[3:])

	if *messageID == "" {
		fmt.Fprintf(os.Stderr, "Error: --id is required\n")
		flags.Usage()
		os.Exit(1)
	}

	// Use global config
	cfg := globalConfig

	if !cfg.Relay.IsQueueEnabled() {
		fmt.Println("Relay is not configured (queue is enabled automatically when relay is configured)")
		os.Exit(1)
	}

	// Try to find the message in the specified queue
	queueDir := filepath.Join(cfg.Relay.GetQueuePath(), *queueType)
	metadataPath := filepath.Join(queueDir, *messageID+".json")
	messagePath := filepath.Join(queueDir, *messageID+".msg")

	// Read metadata
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Message ID %s not found in %s queue\n", *messageID, *queueType)
			fmt.Fprintf(os.Stderr, "Try searching other queues with --queue flag\n")
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Error reading metadata: %v\n", err)
		os.Exit(1)
	}

	var msg relayqueue.QueuedMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing metadata: %v\n", err)
		os.Exit(1)
	}

	// Read message body
	messageBody, err := os.ReadFile(messagePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not read message body: %v\n", err)
		messageBody = []byte("(message body not available)")
	}

	// Display message details
	fmt.Println("Relay Queue Message Details")
	fmt.Println("============================")
	fmt.Printf("ID:           %s\n", msg.ID)
	fmt.Printf("Type:         %s\n", msg.Type)
	fmt.Printf("From:         %s\n", msg.From)
	fmt.Printf("To:           %s\n", msg.To)
	fmt.Printf("Queue:        %s\n", *queueType)
	fmt.Printf("Queued At:    %s\n", msg.QueuedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Attempts:     %d\n", msg.Attempts)
	if !msg.LastAttempt.IsZero() {
		fmt.Printf("Last Attempt: %s\n", msg.LastAttempt.Format("2006-01-02 15:04:05"))
	}
	if !msg.NextRetry.IsZero() {
		fmt.Printf("Next Retry:   %s\n", msg.NextRetry.Format("2006-01-02 15:04:05"))
	}

	if len(msg.Errors) > 0 {
		fmt.Printf("\nError History (%d errors):\n", len(msg.Errors))
		for i, errMsg := range msg.Errors {
			fmt.Printf("  %d. %s\n", i+1, errMsg)
		}
	}

	fmt.Printf("\nMessage Body (%d bytes):\n", len(messageBody))
	fmt.Println("---")
	fmt.Println(string(messageBody))
	fmt.Println("---")
}

func handleRelayDelete(_ context.Context) {
	flags := flag.NewFlagSet("relay delete", flag.ExitOnError)
	messageID := flags.String("id", "", "Message ID to delete (use 'all' to delete all messages)")
	queueType := flags.String("queue", "failed", "Queue to delete from (pending, processing, failed)")
	confirm := flags.Bool("confirm", false, "Confirm deletion (required)")
	flags.Usage = func() {
		fmt.Printf(`Delete a message or all messages from a relay queue

Usage:
  sora-admin relay delete [options]

Options:
  --id string     Message ID to delete, or 'all' to delete all messages (required)
  --queue string  Queue to delete from: pending, processing, failed (default: failed)
  --confirm       Confirm deletion (required); there is no undo

Examples:
  sora-admin --config config.toml relay delete --id 3f2b9c1e-8d4a-4f6b-9a7e-2c5d1e0f4b8a --queue failed --confirm
  sora-admin --config config.toml relay delete --id all --queue failed --confirm
`)
	}
	flags.Parse(os.Args[3:])

	if *messageID == "" {
		fmt.Fprintf(os.Stderr, "Error: --id is required\n")
		flags.Usage()
		os.Exit(1)
	}

	if !*confirm {
		fmt.Fprintf(os.Stderr, "Error: --confirm flag is required for safety\n")
		os.Exit(1)
	}

	// Use global config
	cfg := globalConfig

	if !cfg.Relay.IsQueueEnabled() {
		fmt.Println("Relay is not configured (queue is enabled automatically when relay is configured)")
		os.Exit(1)
	}

	queueDir := filepath.Join(cfg.Relay.GetQueuePath(), *queueType)

	if *messageID == "all" {
		deleted, err := deleteAllMessagesInQueueDir(queueDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading queue directory: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Deleted %d messages from %s queue\n", deleted, *queueType)
	} else {
		queue, err := openExistingRelayQueue(cfg.Relay.GetQueuePath(), cfg.Relay.Queue.MaxAttempts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error accessing relay queue: %v\n", err)
			os.Exit(1)
		}
		if err := queue.Delete(*messageID, *queueType); err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting message %s from %s queue: %v\n", *messageID, *queueType, err)
			os.Exit(1)
		}

		fmt.Printf("Deleted message %s from %s queue\n", *messageID, *queueType)
	}
}

// deleteAllMessagesInQueueDir deletes committed messages through the same lease
// and durable terminal journal as the worker. Busy messages and uncommitted holds
// are left alone; only completed discards contribute to the returned count.
func deleteAllMessagesInQueueDir(queueDir string) (int, error) {
	queueType := filepath.Base(filepath.Clean(queueDir))
	if queueType != "pending" && queueType != "processing" && queueType != "failed" {
		return 0, fmt.Errorf("unknown relay queue %q", queueType)
	}
	queue, err := openExistingRelayQueue(filepath.Dir(filepath.Clean(queueDir)), 10)
	if err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(queueDir)
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if err := queue.Delete(id, queueType); err != nil {
			if !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Warning: Could not delete %s: %v\n", entry.Name(), err)
			}
			continue
		}
		deleted++
	}
	return deleted, nil
}

func handleRelayRequeue(_ context.Context) {
	flags := flag.NewFlagSet("relay requeue", flag.ExitOnError)
	messageID := flags.String("id", "", "Message ID to requeue (use 'all' to requeue all failed messages)")
	confirm := flags.Bool("confirm", false, "Confirm requeue operation (required)")
	flags.Usage = func() {
		fmt.Printf(`Move message(s) from the failed relay queue back to pending

Usage:
  sora-admin relay requeue [options]

Options:
  --id string  Message ID to requeue, or 'all' to requeue all failed messages (required)
  --confirm    Confirm the requeue (required)

Examples:
  sora-admin --config config.toml relay requeue --id 3f2b9c1e-8d4a-4f6b-9a7e-2c5d1e0f4b8a --confirm
  sora-admin --config config.toml relay requeue --id all --confirm
`)
	}
	flags.Parse(os.Args[3:])

	if *messageID == "" {
		fmt.Fprintf(os.Stderr, "Error: --id is required\n")
		flags.Usage()
		os.Exit(1)
	}

	if !*confirm {
		fmt.Fprintf(os.Stderr, "Error: --confirm flag is required for safety\n")
		os.Exit(1)
	}

	// Use global config
	cfg := globalConfig

	if !cfg.Relay.IsQueueEnabled() {
		fmt.Println("Relay is not configured (queue is enabled automatically when relay is configured)")
		os.Exit(1)
	}

	// The queue does the move, so requeue keeps the order its own writers rely on: a
	// running server's worker picks the message up on its next resync of pending/.
	queuePath := cfg.Relay.GetQueuePath()
	queue, err := openExistingRelayQueue(queuePath, cfg.Relay.Queue.MaxAttempts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error accessing relay queue: %v\n", err)
		os.Exit(1)
	}

	if *messageID == "all" {
		// Requeue all failed messages
		entries, err := os.ReadDir(filepath.Join(queuePath, "failed"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading failed queue: %v\n", err)
			os.Exit(1)
		}

		requeued := 0
		for _, entry := range entries {
			name := entry.Name()
			if filepath.Ext(name) == ".json" {
				id := name[:len(name)-5] // Remove .json extension

				// Reset metadata
				if err := queue.Requeue(id); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Could not requeue %s: %v\n", id, err)
				} else {
					requeued++
				}
			}
		}

		fmt.Printf("Requeued %d messages from failed to pending queue\n", requeued)
	} else {
		// Requeue specific message
		if err := queue.Requeue(*messageID); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Requeued message %s from failed to pending queue\n", *messageID)
	}
}

func printRelayUsage() {
	fmt.Printf(`Relay Queue Management

Usage:
  sora-admin relay <subcommand> [options]

Subcommands:
  stats      Show relay queue statistics
  list       List messages in a queue
  show       Show detailed information for a specific message
  delete     Delete a message or all messages from a queue
  requeue    Move message(s) from failed queue back to pending

Examples:
  # Show queue statistics
  sora-admin relay stats --config config.toml

  # List pending messages
  sora-admin relay list --config config.toml --queue pending

  # List failed messages (limit to 50)
  sora-admin relay list --config config.toml --queue failed --limit 50

  # Show details for a specific message
  sora-admin relay show --config config.toml --id 3f2b9c1e-8d4a-4f6b-9a7e-2c5d1e0f4b8a --queue failed

  # Delete a specific failed message
  sora-admin relay delete --config config.toml --id 3f2b9c1e-8d4a-4f6b-9a7e-2c5d1e0f4b8a --queue failed --confirm

  # Delete all failed messages
  sora-admin relay delete --config config.toml --id all --queue failed --confirm

  # Requeue a single failed message
  sora-admin relay requeue --config config.toml --id 3f2b9c1e-8d4a-4f6b-9a7e-2c5d1e0f4b8a --confirm

  # Requeue all failed messages
  sora-admin relay requeue --config config.toml --id all --confirm

Notes:
  - The relay queue is used whenever [relay] is configured (there is no separate switch)
  - Use --confirm flag for destructive operations (delete, requeue)
  - Queue types: pending, processing, failed
  - Requeue resets attempt count and clears error history
`)
}
