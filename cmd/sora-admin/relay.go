package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/migadu/sora/config"
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

func handleRelayStats(ctx context.Context) {
	flags := flag.NewFlagSet("relay stats", flag.ExitOnError)
	configPath := flags.String("config", "config.toml", "Configuration file path")
	flags.Parse(os.Args[3:])

	// Load config to get relay queue path
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	if !cfg.Relay.IsQueueEnabled() {
		fmt.Println("Relay is not configured (queue is enabled automatically when relay is configured)")
		os.Exit(1)
	}

	// Create queue instance (just for stats, doesn't start worker)
	queuePath := cfg.Relay.GetQueuePath()
	queue, err := relayqueue.NewDiskQueue(queuePath, cfg.Relay.Queue.MaxAttempts, nil)
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

	// Display stats
	fmt.Println("Relay Queue Statistics")
	fmt.Println("======================")
	fmt.Printf("Queue Path:       %s\n", queuePath)
	fmt.Printf("Pending:          %d\n", pending)
	fmt.Printf("Processing:       %d\n", processing)
	fmt.Printf("Failed:           %d\n", failed)
	fmt.Printf("Total:            %d\n", pending+processing+failed)
	fmt.Printf("Max Attempts:     %d\n", cfg.Relay.Queue.MaxAttempts)
	fmt.Printf("Worker Interval:  %s\n", cfg.Relay.Queue.WorkerInterval)
}

func handleRelayList(ctx context.Context) {
	flags := flag.NewFlagSet("relay list", flag.ExitOnError)
	configPath := flags.String("config", "config.toml", "Configuration file path")
	queueType := flags.String("queue", "pending", "Queue to list (pending, processing, failed)")
	limit := flags.Int("limit", 100, "Maximum number of messages to display")
	flags.Parse(os.Args[3:])

	// Load config
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

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

		// Truncate ID for display
		idShort := msg.ID
		if len(idShort) > 8 {
			idShort = idShort[:8]
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			idShort, msg.Type, msg.From, msg.To, msg.Attempts, queuedStr, nextRetryStr)
	}
	w.Flush()

	if len(messages) >= *limit {
		fmt.Printf("\n(Showing first %d messages. Use --limit to see more)\n", *limit)
	}
}

func handleRelayShow(ctx context.Context) {
	flags := flag.NewFlagSet("relay show", flag.ExitOnError)
	configPath := flags.String("config", "config.toml", "Configuration file path")
	messageID := flags.String("id", "", "Message ID to display (required)")
	queueType := flags.String("queue", "pending", "Queue to search (pending, processing, failed)")
	flags.Parse(os.Args[3:])

	if *messageID == "" {
		fmt.Fprintf(os.Stderr, "Error: --id is required\n")
		flags.Usage()
		os.Exit(1)
	}

	// Load config
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

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

func handleRelayDelete(ctx context.Context) {
	flags := flag.NewFlagSet("relay delete", flag.ExitOnError)
	configPath := flags.String("config", "config.toml", "Configuration file path")
	messageID := flags.String("id", "", "Message ID to delete (use 'all' to delete all messages)")
	queueType := flags.String("queue", "failed", "Queue to delete from (pending, processing, failed)")
	confirm := flags.Bool("confirm", false, "Confirm deletion (required)")
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

	// Load config
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	if !cfg.Relay.IsQueueEnabled() {
		fmt.Println("Relay is not configured (queue is enabled automatically when relay is configured)")
		os.Exit(1)
	}

	queueDir := filepath.Join(cfg.Relay.GetQueuePath(), *queueType)

	if *messageID == "all" {
		// Delete all messages in the queue
		entries, err := os.ReadDir(queueDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading queue directory: %v\n", err)
			os.Exit(1)
		}

		deleted := 0
		for _, entry := range entries {
			name := entry.Name()
			if filepath.Ext(name) == ".json" || filepath.Ext(name) == ".msg" {
				if err := os.Remove(filepath.Join(queueDir, name)); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Could not delete %s: %v\n", name, err)
				} else {
					if filepath.Ext(name) == ".json" {
						deleted++
					}
				}
			}
		}

		fmt.Printf("Deleted %d messages from %s queue\n", deleted, *queueType)
	} else {
		// Delete specific message
		metadataPath := filepath.Join(queueDir, *messageID+".json")
		messagePath := filepath.Join(queueDir, *messageID+".msg")

		// Check if message exists
		if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Message ID %s not found in %s queue\n", *messageID, *queueType)
			os.Exit(1)
		}

		// Delete both files
		if err := os.Remove(metadataPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting metadata: %v\n", err)
			os.Exit(1)
		}

		if err := os.Remove(messagePath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Error deleting message body: %v\n", err)
		}

		fmt.Printf("Deleted message %s from %s queue\n", *messageID, *queueType)
	}
}

func handleRelayRequeue(ctx context.Context) {
	flags := flag.NewFlagSet("relay requeue", flag.ExitOnError)
	configPath := flags.String("config", "config.toml", "Configuration file path")
	messageID := flags.String("id", "", "Message ID to requeue (use 'all' to requeue all failed messages)")
	confirm := flags.Bool("confirm", false, "Confirm requeue operation (required)")
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

	// Load config
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	if !cfg.Relay.IsQueueEnabled() {
		fmt.Println("Relay is not configured (queue is enabled automatically when relay is configured)")
		os.Exit(1)
	}

	failedDir := filepath.Join(cfg.Relay.GetQueuePath(), "failed")
	pendingDir := filepath.Join(cfg.Relay.GetQueuePath(), "pending")

	if *messageID == "all" {
		// Requeue all failed messages
		entries, err := os.ReadDir(failedDir)
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
				if err := requeueMessage(failedDir, pendingDir, id); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Could not requeue %s: %v\n", id, err)
				} else {
					requeued++
				}
			}
		}

		fmt.Printf("Requeued %d messages from failed to pending queue\n", requeued)
	} else {
		// Requeue specific message
		if err := requeueMessage(failedDir, pendingDir, *messageID); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Requeued message %s from failed to pending queue\n", *messageID)
	}
}

func requeueMessage(failedDir, pendingDir, messageID string) error {
	metadataPath := filepath.Join(failedDir, messageID+".json")
	messagePath := filepath.Join(failedDir, messageID+".msg")

	// Read metadata
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("could not read metadata: %w", err)
	}

	var msg relayqueue.QueuedMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return fmt.Errorf("could not parse metadata: %w", err)
	}

	// Reset for retry
	msg.Attempts = 0
	msg.LastAttempt = time.Time{}
	msg.NextRetry = time.Now() // Ready for immediate processing
	msg.Errors = []string{}

	// Write updated metadata to pending
	updatedData, err := json.MarshalIndent(msg, "", "  ")
	if err != nil {
		return fmt.Errorf("could not marshal metadata: %w", err)
	}

	newMetadataPath := filepath.Join(pendingDir, messageID+".json")
	if err := os.WriteFile(newMetadataPath, updatedData, 0644); err != nil {
		return fmt.Errorf("could not write metadata to pending: %w", err)
	}

	// Copy message body
	messageBody, err := os.ReadFile(messagePath)
	if err != nil {
		// Clean up metadata if body read fails
		os.Remove(newMetadataPath)
		return fmt.Errorf("could not read message body: %w", err)
	}

	newMessagePath := filepath.Join(pendingDir, messageID+".msg")
	if err := os.WriteFile(newMessagePath, messageBody, 0644); err != nil {
		// Clean up metadata if body write fails
		os.Remove(newMetadataPath)
		return fmt.Errorf("could not write message body to pending: %w", err)
	}

	// Delete from failed queue
	os.Remove(metadataPath)
	os.Remove(messagePath)

	return nil
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
  sora-admin relay show --config config.toml --id a1b2c3d4-e5f6 --queue failed

  # Delete a specific failed message
  sora-admin relay delete --config config.toml --id a1b2c3d4-e5f6 --queue failed --confirm

  # Delete all failed messages
  sora-admin relay delete --config config.toml --id all --queue failed --confirm

  # Requeue a single failed message
  sora-admin relay requeue --config config.toml --id a1b2c3d4-e5f6 --confirm

  # Requeue all failed messages
  sora-admin relay requeue --config config.toml --id all --confirm

Notes:
  - The relay queue must be enabled in config.toml
  - Use --confirm flag for destructive operations (delete, requeue)
  - Queue types: pending, processing, failed
  - Requeue resets attempt count and clears error history
`)
}

// loadConfig is a helper to load relay-specific config
func loadConfig(path string) (*config.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg config.Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &cfg, nil
}
