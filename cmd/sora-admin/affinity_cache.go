package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/migadu/sora/logger"
)

func handleAffinityCacheCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printAffinityCacheUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "status":
		handleAffinityCacheStatus(ctx)
	case "help", "--help", "-h":
		printAffinityCacheUsage()
	default:
		fmt.Printf("Unknown affinity-cache subcommand: %s\n\n", subcommand)
		printAffinityCacheUsage()
		os.Exit(1)
	}
}

func handleAffinityCacheStatus(ctx context.Context) {
	fs := flag.NewFlagSet("affinity-cache status", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Printf(`Show affinity cache statistics

Usage:
  sora-admin --config PATH affinity-cache status

Asks the Admin API ([admin_cli] addr and api_key) for the affinity cache's entries and
broadcast queue.
`)
	}
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	client, err := createHTTPAPIClient(globalConfig)
	if err != nil {
		logger.Fatalf("Failed to create HTTP API client: %v", err)
	}

	url := fmt.Sprintf("%s/admin/affinity/stats", globalConfig.HTTPAPIAddr)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		logger.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+globalConfig.HTTPAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		logger.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Fatalf("Failed to read response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		logger.Fatalf("API request failed (status %d): %s", resp.StatusCode, string(body))
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		logger.Fatalf("Failed to parse response: %v", err)
	}

	fmt.Println("Affinity Cache Status")
	fmt.Println("=====================")
	fmt.Println()

	stats, ok := result["stats"].(map[string]any)
	if !ok {
		fmt.Println("Error: Invalid response format")
		return
	}

	enabled, _ := stats["enabled"].(bool)
	if !enabled {
		fmt.Println("Status: DISABLED")
		return
	}

	fmt.Println("Status: ENABLED")
	fmt.Println()

	if v, ok := stats["total_entries"].(float64); ok {
		fmt.Printf("  Cached entries:      %.0f\n", v)
	}
	if v, ok := stats["ttl"].(string); ok {
		fmt.Printf("  TTL:                 %s\n", v)
	}
	if v, ok := stats["cleanup_interval"].(string); ok {
		fmt.Printf("  Cleanup interval:    %s\n", v)
	}

	if protocols, ok := stats["by_protocol"].(map[string]any); ok && len(protocols) > 0 {
		fmt.Println("\n  Entries by protocol:")
		for proto, count := range protocols {
			if v, ok := count.(float64); ok {
				fmt.Printf("    %-12s: %.0f\n", proto, v)
			}
		}
	}

	if mem, ok := stats["memory_usage"].(map[string]any); ok {
		fmt.Println("\n  Memory / Queue Info:")
		if v, ok := mem["broadcast_queue"].(float64); ok {
			line := fmt.Sprintf("%.0f", v)
			if queueMax, ok := mem["broadcast_queue_max"].(float64); ok {
				line += fmt.Sprintf(" / %.0f", queueMax)
			}
			if util, ok := mem["queue_utilization"].(float64); ok {
				line += fmt.Sprintf(" (%.1f%%)", util)
			}
			fmt.Printf("    Broadcast queue:   %s\n", line)
		}
	}
}

func printAffinityCacheUsage() {
	fmt.Printf(`Affinity Cache Management

Usage:
  sora-admin affinity-cache <subcommand> [options]

Subcommands:
  status      Show affinity cache statistics (entries, queue status, etc.)

Examples:
  sora-admin --config config.toml affinity-cache status

Use 'sora-admin affinity-cache <subcommand> --help' for detailed help.
`)
}
