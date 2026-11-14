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

func handleAuthCacheCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printAuthCacheUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "status":
		handleAuthCacheStatus(ctx)
	case "help", "--help", "-h":
		printAuthCacheUsage()
	default:
		fmt.Printf("Unknown auth-cache subcommand: %s\n\n", subcommand)
		printAuthCacheUsage()
		os.Exit(1)
	}
}

func handleAuthCacheStatus(ctx context.Context) {
	fs := flag.NewFlagSet("auth-cache status", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Printf(`Show auth cache statistics

Usage:
  sora-admin --config PATH auth-cache status

Asks the Admin API ([admin_cli] addr and api_key) for the auth cache's entries and hit rate.
`)
	}
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	client, err := createHTTPAPIClient(globalConfig)
	if err != nil {
		logger.Fatalf("Failed to create HTTP API client: %v", err)
	}

	url := fmt.Sprintf("%s/admin/auth-cache/stats", globalConfig.HTTPAPIAddr)

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

	fmt.Println("Auth Cache Status")
	fmt.Println("==================")
	fmt.Println()

	enabled, _ := result["enabled"].(bool)
	if !enabled {
		fmt.Println("Status: DISABLED")
		if note, ok := result["note"].(string); ok {
			fmt.Printf("Note:   %s\n", note)
		}
		return
	}

	fmt.Println("Status: ENABLED")
	fmt.Println()

	if v, ok := result["total_entries"].(float64); ok {
		fmt.Printf("  Cached entries:      %.0f\n", v)
	}
	if v, ok := result["session_hits"].(float64); ok {
		fmt.Printf("  Session hits:        %.0f\n", v)
	}
	if v, ok := result["session_misses"].(float64); ok {
		fmt.Printf("  Session misses:      %.0f\n", v)
	}
	if v, ok := result["hit_rate_percent"].(float64); ok {
		fmt.Printf("  Hit rate:            %.1f%%\n", v)
	}
	if v, ok := result["lifetime_hit_count"].(float64); ok {
		fmt.Printf("  Lifetime hits:       %.0f\n", v)
	}
}

func printAuthCacheUsage() {
	fmt.Printf(`Auth Cache Management

Usage:
  sora-admin auth-cache <subcommand> [options]

Subcommands:
  status      Show auth cache statistics (entries, hit rate, etc.)

Examples:
  sora-admin --config config.toml auth-cache status

Use 'sora-admin auth-cache <subcommand> --help' for detailed help.
`)
}
