package main

// stats.go - Command handlers for stats
// Extracted from main.go for better organization

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/migadu/sora/logger"
)

func handleStatsCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printStatsUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "blocked":
		handleBlockedCommand(ctx)
	case "connection":
		handleConnectionStats(ctx)
	case "help", "--help", "-h":
		printStatsUsage()
	default:
		fmt.Printf("Unknown stats subcommand: %s\n\n", subcommand)
		printStatsUsage()
		os.Exit(1)
	}
}

func handleBlockedCommand(ctx context.Context) {
	// Parse blocked specific flags
	fs := flag.NewFlagSet("stats blocked", flag.ExitOnError)
	protocol := fs.String("protocol", "", "Filter by protocol (imap, pop3, managesieve, imap_proxy, pop3_proxy, managesieve_proxy, userapi)")

	fs.Usage = func() {
		fmt.Printf(`Show blocked IPs and rate-limited addresses

Usage:
  sora-admin stats blocked [options]

Options:
  --config string     Path to TOML configuration file (required)
  --protocol string   Filter by protocol (optional)

Protocols:
  imap, pop3, managesieve          Backend servers
  imap_proxy, pop3_proxy           Proxy servers
  managesieve_proxy, userapi       Other services

Examples:
  sora-admin stats blocked --config config.toml
  sora-admin stats blocked --config config.toml --protocol imap_proxy
  sora-admin stats blocked --config config.toml --protocol pop3
`)
	}

	// Parse the remaining arguments
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Show blocked entries
	if err := showBlockedEntries(ctx, globalConfig, *protocol); err != nil {
		logger.Fatalf("Failed to get blocked entries: %v", err)
	}
}

func handleConnectionStats(ctx context.Context) {
	// Parse connection-stats specific flags
	fs := flag.NewFlagSet("stats connection", flag.ExitOnError)

	userEmail := fs.String("user", "", "Show connections for specific user email")
	showDetail := fs.Bool("detail", true, "Show detailed connection list")

	// Database connection flags (overrides from config file)

	fs.Usage = func() {
		fmt.Printf(`Show active connections and statistics

Usage:
  sora-admin stats connection [options]

Options:
  --user string         Show connections for specific user email
  --detail              Show detailed connection list (default: true)
  --config string       Path to TOML configuration file (required)

NOTE: Connection tracking uses in-memory gossip (cluster mode) or local tracking.
      Statistics are retrieved via HTTP Admin API.

This command shows:
  - Total number of active connections
  - Connections grouped by protocol (IMAP, POP3, ManageSieve, LMTP)
  - Per-user connection counts (local and cluster-wide totals)
  - Option to filter by specific user

Examples:
  sora-admin stats connection --config config.toml
  sora-admin stats connection --config config.toml --user user@example.com
  sora-admin stats connection --config config.toml --detail
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments

	// Show connection statistics
	if err := showConnectionStats(ctx, globalConfig, *userEmail, *showDetail); err != nil {
		logger.Fatalf("Failed to show connection stats: %v", err)
	}
}

func printStatsUsage() {
	fmt.Printf(`System Statistics

Usage:
  sora-admin stats <subcommand> [options]

Subcommands:
  blocked     Show blocked IPs and rate-limited addresses
  connection  Show active proxy connections and statistics

Examples:
  sora-admin stats blocked --config config.toml
  sora-admin stats blocked --config config.toml --protocol imap_proxy
  sora-admin stats connection --user user@example.com

Use 'sora-admin stats <subcommand> --help' for detailed help.
`)
}

func showBlockedEntries(ctx context.Context, cfg AdminConfig, protocol string) error {
	// Create HTTP API client
	client, err := createHTTPAPIClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create HTTP API client: %w", err)
	}

	// Build URL with optional protocol filter
	url := fmt.Sprintf("%s/admin/auth/blocked", cfg.HTTPAPIAddr)
	if protocol != "" {
		url = fmt.Sprintf("%s?protocol=%s", url, protocol)
	}

	// Make request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+cfg.HTTPAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var result struct {
		BlockedEntries []struct {
			IP           string    `json:"ip"`
			Username     string    `json:"username,omitempty"`
			BlockedUntil time.Time `json:"blocked_until"`
			FailureCount int       `json:"failure_count"`
			FirstFailure time.Time `json:"first_failure"`
			LastFailure  time.Time `json:"last_failure"`
			Protocol     string    `json:"protocol"`
			Type         string    `json:"type"`
		} `json:"blocked_entries"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Display results
	fmt.Println("Blocked IPs and Rate-Limited Addresses")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()

	if result.Count == 0 {
		fmt.Println("No blocked entries found.")
		return nil
	}

	fmt.Printf("Total blocked entries: %d\n\n", result.Count)

	// Group by type for better display
	ipUsernameBlocks := []int{}
	ipBlocks := []int{}
	for i, entry := range result.BlockedEntries {
		if entry.Type == "ip_username" {
			ipUsernameBlocks = append(ipUsernameBlocks, i)
		} else {
			ipBlocks = append(ipBlocks, i)
		}
	}

	// Display IP+username blocks
	if len(ipUsernameBlocks) > 0 {
		fmt.Printf("IP+Username Blocks (%d):\n", len(ipUsernameBlocks))
		fmt.Println(strings.Repeat("-", 70))
		for _, i := range ipUsernameBlocks {
			entry := result.BlockedEntries[i]
			fmt.Printf("  IP:           %s\n", entry.IP)
			fmt.Printf("  Username:     %s\n", entry.Username)
			fmt.Printf("  Protocol:     %s\n", entry.Protocol)
			fmt.Printf("  Blocked until: %s (%s remaining)\n",
				entry.BlockedUntil.Format("2006-01-02 15:04:05 MST"),
				time.Until(entry.BlockedUntil).Round(time.Second))
			fmt.Printf("  Failures:     %d (first: %s, last: %s)\n",
				entry.FailureCount,
				entry.FirstFailure.Format("15:04:05"),
				entry.LastFailure.Format("15:04:05"))
			fmt.Println()
		}
	}

	// Display IP-only blocks
	if len(ipBlocks) > 0 {
		fmt.Printf("IP-Only Blocks (%d):\n", len(ipBlocks))
		fmt.Println(strings.Repeat("-", 70))
		for _, i := range ipBlocks {
			entry := result.BlockedEntries[i]
			fmt.Printf("  IP:           %s\n", entry.IP)
			fmt.Printf("  Protocol:     %s\n", entry.Protocol)
			fmt.Printf("  Blocked until: %s (%s remaining)\n",
				entry.BlockedUntil.Format("2006-01-02 15:04:05 MST"),
				time.Until(entry.BlockedUntil).Round(time.Second))
			fmt.Printf("  Failures:     %d (first: %s, last: %s)\n",
				entry.FailureCount,
				entry.FirstFailure.Format("15:04:05"),
				entry.LastFailure.Format("15:04:05"))
			fmt.Println()
		}
	}

	return nil
}

func showConnectionStats(ctx context.Context, cfg AdminConfig, userEmail string, showDetail bool) error {
	// Create HTTP API client
	client, err := createHTTPAPIClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create HTTP API client: %w", err)
	}

	// Build URL based on whether user email is specified
	var endpoint string
	if userEmail != "" {
		// One path segment: a "/" in the local part goes as %2F (RFC 3986 §2.2).
		endpoint = fmt.Sprintf("%s/admin/connections/user/%s", cfg.HTTPAPIAddr, url.PathEscape(userEmail))
	} else {
		endpoint = fmt.Sprintf("%s/admin/connections/stats", cfg.HTTPAPIAddr)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+cfg.HTTPAPIKey)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get connection stats: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response based on endpoint
	if userEmail != "" {
		// User-specific connections
		var result struct {
			Email       string `json:"email"`
			Connections []struct {
				Protocol   string    `json:"protocol"`
				Instance   string    `json:"instance"` // tracker key
				AccountID  int64     `json:"account_id"`
				Email      string    `json:"email"`
				LocalCount int       `json:"local_count"`
				TotalCount int       `json:"total_count"`
				LastUpdate time.Time `json:"last_update"`
			} `json:"connections"`
			Count  int    `json:"count"`
			Source string `json:"source,omitempty"`
			Note   string `json:"note,omitempty"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		if result.Note != "" {
			fmt.Printf("Note: %s\n\n", result.Note)
		}

		if result.Count == 0 {
			fmt.Printf("No active connections found for user: %s\n", userEmail)
			return nil
		}

		fmt.Printf("Active Connections for User: %s\n", userEmail)
		fmt.Printf("==========================================\n\n")
		// Group by protocol. result.Count is the number of entries (one per tracker that
		// knows the account), not of connections. An entry's total is its tracker's own
		// sessions plus those other nodes report for the protocol, so the sessions on
		// other nodes are in every entry for that account and protocol: count them
		// once. An address reused by another account can still match the old account's
		// open sessions, so remote counts of different account IDs stay separate.
		type protocolCount struct{ local, remote int }
		type accountProtocol struct {
			accountID int64
			protocol  string
		}
		counts := make(map[accountProtocol]protocolCount)
		for _, conn := range result.Connections {
			key := accountProtocol{conn.AccountID, conn.Protocol}
			c := counts[key]
			c.local += conn.LocalCount
			c.remote = max(c.remote, conn.TotalCount-conn.LocalCount)
			counts[key] = c
		}
		protocolCounts := make(map[string]int)
		for key, c := range counts {
			protocolCounts[key.protocol] += c.local + c.remote
		}
		protocols := make([]string, 0, len(protocolCounts))
		total := 0
		for protocol, c := range protocolCounts {
			protocols = append(protocols, protocol)
			total += c
		}
		sort.Strings(protocols)
		fmt.Printf("Total connections: %d\n\n", total)

		fmt.Println("By Protocol:")
		for _, protocol := range protocols {
			fmt.Printf("  %-12s %d\n", protocol+":", protocolCounts[protocol])
		}
		fmt.Println()

		if showDetail {
			fmt.Println("Details:")
			fmt.Printf("%-12s %-30s %-12s %-12s %-20s\n", "Protocol", "Instance", "Local", "Total", "Last Update")
			fmt.Printf("%-12s %-30s %-12s %-12s %-20s\n", "--------", "--------", "-----", "-----", "-----------")
			for _, conn := range result.Connections {
				fmt.Printf("%-12s %-30s %-12d %-12d %-20s\n",
					conn.Protocol,
					trackerInstance(conn.Instance),
					conn.LocalCount,
					conn.TotalCount,
					conn.LastUpdate.Format("2006-01-02 15:04:05"))
			}
			fmt.Println()
		}

		if result.Source != "" {
			fmt.Printf("Source: %s\n", result.Source)
		}

	} else {
		// Overall statistics
		var result struct {
			TotalConnections      int            `json:"total_connections"`
			ConnectionsByProtocol map[string]int `json:"connections_by_protocol"`
			Source                string         `json:"source,omitempty"`
			Note                  string         `json:"note,omitempty"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		if result.Note != "" {
			fmt.Printf("Note: %s\n\n", result.Note)
		}

		if result.TotalConnections == 0 {
			fmt.Println("No active connections found.")
			return nil
		}

		fmt.Printf("Active Connections\n")
		fmt.Printf("==================\n\n")
		fmt.Printf("Summary:\n")
		fmt.Printf("  Total connections: %d\n\n", result.TotalConnections)

		if len(result.ConnectionsByProtocol) > 0 {
			fmt.Printf("By Protocol:\n")

			// Sort protocols alphabetically
			protocols := make([]string, 0, len(result.ConnectionsByProtocol))
			for protocol := range result.ConnectionsByProtocol {
				protocols = append(protocols, protocol)
			}
			sort.Strings(protocols)

			for _, protocol := range protocols {
				count := result.ConnectionsByProtocol[protocol]
				fmt.Printf("  %-12s %d\n", protocol+":", count)
			}
			fmt.Println()
		}

		if result.Source != "" {
			fmt.Printf("Source: %s\n", result.Source)
		}
	}

	return nil
}
