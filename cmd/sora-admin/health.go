package main

// health.go - Command handlers for health
// Extracted from main.go for better organization

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
)

func handleHealthCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printHealthUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "status":
		handleHealthStatus(ctx)
	case "--help", "-h":
		printHealthUsage()
	default:
		fmt.Printf("Unknown health subcommand: %s\n\n", subcommand)
		printHealthUsage()
		os.Exit(1)
	}
}

func handleHealthStatus(ctx context.Context) {
	fs := flag.NewFlagSet("health", flag.ExitOnError)

	// Command-specific flags
	hostname := fs.String("hostname", "", "Show health status for specific hostname")
	component := fs.String("component", "", "Show health status for specific component")
	detailed := fs.Bool("detailed", false, "Show detailed health information including metadata")
	jsonOutput := fs.Bool("json", false, "Output in JSON format")
	showBackends := fs.Bool("backends", false, "Show proxy backend health status (requires Admin API)")

	// Configuration

	fs.Usage = func() {
		fmt.Printf(`Show system health status and component monitoring

Usage:
  sora-admin health status [options]

Options:
  --hostname string     Show health status for specific hostname
  --component string    Show health status for specific component
  --detailed            Show detailed health information including metadata
  --json                Output in JSON format
  --backends            Show proxy backend health status (requires Admin API)
  --config string        Path to TOML configuration file (required)

This command shows:
  - Overall system health status
  - Component health status (database, S3, circuit breakers)
  - Server-specific health information
  - Component failure rates and error details
  - Proxy backend health status (with --backends flag)

Examples:
  sora-admin health status
  sora-admin health status --hostname server1.example.com
  sora-admin health status --component database --detailed
  sora-admin health status --backends
  sora-admin health status --json
`)
	}

	// Parse command arguments (skip program name, command name, and subcommand name)
	args := os.Args[3:]
	if err := fs.Parse(args); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// If showing backends, use Admin API instead of database
	if *showBackends {
		// Check that HTTP API is configured
		if globalConfig.HTTPAPIAddr == "" {
			logger.Fatalf("HTTP API address not configured (set http_api_addr in config)")
		}
		if globalConfig.HTTPAPIKey == "" {
			logger.Fatalf("HTTP API key not configured (set http_api_key in config)")
		}
		if *jsonOutput {
			if err := showBackendHealthJSON(ctx, globalConfig); err != nil {
				logger.Fatalf("Failed to show backend health: %v", err)
			}
		} else {
			if err := showBackendHealth(ctx, globalConfig); err != nil {
				logger.Fatalf("Failed to show backend health: %v", err)
			}
		}
		return
	}

	// Connect to resilient database
	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		logger.Fatalf("Failed to initialize resilient database: %v", err)
	}
	defer rdb.Close()

	if *jsonOutput {
		if err := showHealthStatusJSON(ctx, rdb, *hostname, *component, *detailed); err != nil {
			logger.Fatalf("Failed to show health status: %v", err)
		}
	} else {
		if err := showHealthStatus(ctx, rdb, *hostname, *component, *detailed); err != nil {
			logger.Fatalf("Failed to show health status: %v", err)
		}
	}
}

func printHealthUsage() {
	fmt.Printf(`System Health Management

Usage:
  sora-admin health <subcommand> [options]

Subcommands:
  status   Show system health status and component monitoring

Examples:
  sora-admin health status
  sora-admin health status --hostname server1.example.com
  sora-admin health status --component database
  sora-admin health status --detailed --json

Use 'sora-admin health <subcommand> --help' for detailed help.
`)
}

func showHealthStatus(ctx context.Context, rdb *resilient.ResilientDatabase, hostname, component string, detailed bool) error {
	// Show overview first
	overview, err := rdb.GetSystemHealthOverviewWithRetry(ctx, hostname)
	if err != nil {
		return fmt.Errorf("failed to get system health overview: %w", err)
	}

	// Display system overview
	fmt.Printf("System Health Overview\n")
	fmt.Printf("======================\n\n")

	statusColor := getStatusColor(overview.OverallStatus)
	fmt.Printf("Overall Status: %s%s%s\n", statusColor, strings.ToUpper(string(overview.OverallStatus)), "\033[0m")
	fmt.Printf("Last Updated: %s\n", overview.LastUpdated.Format("2006-01-02 15:04:05 UTC"))
	if hostname != "" {
		fmt.Printf("Hostname: %s\n", hostname)
	}
	fmt.Printf("\n")

	// Component summary
	fmt.Printf("Component Summary:\n")
	fmt.Printf("  Total Components: %d\n", overview.ComponentCount)
	if overview.ComponentCount > 0 {
		fmt.Printf("  Healthy: %s%d%s\n", "\033[32m", overview.HealthyCount, "\033[0m")
		if overview.DegradedCount > 0 {
			fmt.Printf("  Degraded: %s%d%s\n", "\033[33m", overview.DegradedCount, "\033[0m")
		}
		if overview.UnhealthyCount > 0 {
			fmt.Printf("  Unhealthy: %s%d%s\n", "\033[31m", overview.UnhealthyCount, "\033[0m")
		}
		if overview.UnreachableCount > 0 {
			fmt.Printf("  Unreachable: %s%d%s\n", "\033[35m", overview.UnreachableCount, "\033[0m")
		}
	}
	fmt.Printf("\n")

	// Get detailed component status
	statuses, err := rdb.GetAllHealthStatusesWithRetry(ctx, hostname)
	if err != nil {
		return fmt.Errorf("failed to get health statuses: %w", err)
	}

	if len(statuses) == 0 {
		fmt.Printf("No health data available.\n")
		if hostname != "" {
			fmt.Printf("Note: No health data found for hostname '%s'.\n", hostname)
		} else {
			fmt.Printf("Note: Health monitoring may not be active or data may have been cleaned up.\n")
		}
		return nil
	}

	// Filter by component if specified
	if component != "" {
		filteredStatuses := []*db.HealthStatus{}
		for _, status := range statuses {
			if status.ComponentName == component {
				filteredStatuses = append(filteredStatuses, status)
			}
		}
		statuses = filteredStatuses

		if len(statuses) == 0 {
			fmt.Printf("No health data found for component '%s'", component)
			if hostname != "" {
				fmt.Printf(" on hostname '%s'", hostname)
			}
			fmt.Printf(".\n")
			return nil
		}
	}

	// Display component details
	fmt.Printf("Component Health Details\n")
	fmt.Printf("========================\n\n")

	// Group by server hostname for better organization
	serverGroups := make(map[string][]*db.HealthStatus)
	for _, status := range statuses {
		serverGroups[status.ServerHostname] = append(serverGroups[status.ServerHostname], status)
	}

	for serverName, serverStatuses := range serverGroups {
		if len(serverGroups) > 1 {
			fmt.Printf("Server: %s\n", serverName)
			fmt.Printf("%s\n", strings.Repeat("-", len(serverName)+8))
		}

		for _, status := range serverStatuses {
			statusColor := getStatusColor(status.Status)
			fmt.Printf("%-20s %s%-12s%s", status.ComponentName, statusColor, strings.ToUpper(string(status.Status)), "\033[0m")

			// Calculate failure rate
			failureRate := 0.0
			if status.CheckCount > 0 {
				failureRate = float64(status.FailCount) / float64(status.CheckCount) * 100
			}

			fmt.Printf(" (%.1f%% failure rate)\n", failureRate)

			if detailed {
				fmt.Printf("  Last Check: %s\n", status.LastCheck.Format("2006-01-02 15:04:05 UTC"))
				fmt.Printf("  Checks: %d total, %d failed\n", status.CheckCount, status.FailCount)

				if status.LastError != nil {
					fmt.Printf("  Last Error: %s\n", *status.LastError)
				}

				if len(status.Metadata) > 0 {
					fmt.Printf("  Metadata:\n")
					for key, value := range status.Metadata {
						fmt.Printf("    %s: %v\n", key, value)
					}
				}
				fmt.Printf("\n")
			}
		}

		if len(serverGroups) > 1 {
			fmt.Printf("\n")
		}
	}

	return nil
}

func showHealthStatusJSON(ctx context.Context, rdb *resilient.ResilientDatabase, hostname, component string, detailed bool) error {
	type JSONHealthOutput struct {
		Overview   *db.SystemHealthOverview `json:"overview"`
		Components []*db.HealthStatus       `json:"components,omitempty"`
		Timestamp  time.Time                `json:"timestamp"`
		Filter     map[string]string        `json:"filter,omitempty"`
	}

	output := JSONHealthOutput{
		Timestamp: time.Now(),
		Filter:    make(map[string]string),
	}

	if hostname != "" {
		output.Filter["hostname"] = hostname
	}
	if component != "" {
		output.Filter["component"] = component
	}

	// Get overview
	overview, err := rdb.GetSystemHealthOverviewWithRetry(ctx, hostname)
	if err != nil {
		return fmt.Errorf("failed to get system health overview: %w", err)
	}
	output.Overview = overview

	// Get current component status
	statuses, err := rdb.GetAllHealthStatusesWithRetry(ctx, hostname)
	if err != nil {
		return fmt.Errorf("failed to get health statuses: %w", err)
	}

	// Filter by component if specified
	if component != "" {
		filteredStatuses := []*db.HealthStatus{}
		for _, status := range statuses {
			if status.ComponentName == component {
				filteredStatuses = append(filteredStatuses, status)
			}
		}
		statuses = filteredStatuses
	}

	output.Components = statuses

	// Remove metadata if not detailed mode
	if !detailed {
		for _, status := range output.Components {
			status.Metadata = nil
		}
	}

	// Output JSON
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func showBackendHealth(ctx context.Context, cfg AdminConfig) error {
	// Create HTTP API client
	client, err := createHTTPAPIClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create HTTP API client: %w", err)
	}

	// Build URL
	url := fmt.Sprintf("%s/admin/proxy/backends", cfg.HTTPAPIAddr)

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+cfg.HTTPAPIKey)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get backend health: %w", err)
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

	// Parse response
	var result struct {
		Proxies []struct {
			ProxyName string `json:"proxy_name"`
			Backends  []struct {
				Address            string    `json:"address"`
				IsHealthy          bool      `json:"is_healthy"`
				FailureCount       int       `json:"failure_count"`
				ConsecutiveFails   int       `json:"consecutive_fails"`
				LastFailure        time.Time `json:"last_failure,omitempty"`
				LastSuccess        time.Time `json:"last_success,omitempty"`
				HealthCheckEnabled bool      `json:"health_check_enabled"`
				IsRemoteLookup     bool      `json:"is_remote_lookup"`
			} `json:"backends"`
		} `json:"proxies"`
		Timestamp time.Time `json:"timestamp"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Display results only if proxies are found
	if len(result.Proxies) == 0 {
		fmt.Printf("No proxy servers configured on this instance.\n")
		return nil
	}

	fmt.Printf("Proxy Backend Health Status\n")
	fmt.Printf("============================\n\n")
	fmt.Printf("Timestamp: %s\n\n", result.Timestamp.Format("2006-01-02 15:04:05 UTC"))

	for _, proxy := range result.Proxies {
		fmt.Printf("Proxy: %s\n", proxy.ProxyName)
		fmt.Printf("%s\n", strings.Repeat("-", len(proxy.ProxyName)+7))

		if len(proxy.Backends) == 0 {
			fmt.Printf("  No backends configured\n\n")
			continue
		}

		for _, backend := range proxy.Backends {
			healthStatus := "HEALTHY"
			statusColor := "\033[32m" // green
			if !backend.IsHealthy {
				healthStatus = "UNHEALTHY"
				statusColor = "\033[31m" // red
			}

			backendType := ""
			if backend.IsRemoteLookup {
				backendType = " [remote_lookup]"
			}

			fmt.Printf("  %-25s %s%-12s\033[0m%s", backend.Address, statusColor, healthStatus, backendType)

			if !backend.HealthCheckEnabled {
				fmt.Printf(" (health checks disabled)")
			} else {
				fmt.Printf(" (failures: %d/%d)", backend.ConsecutiveFails, backend.FailureCount)
			}
			fmt.Printf("\n")

			if !backend.LastSuccess.IsZero() {
				fmt.Printf("    Last Success: %s\n", backend.LastSuccess.Format("2006-01-02 15:04:05 UTC"))
			}
			if !backend.LastFailure.IsZero() {
				fmt.Printf("    Last Failure: %s\n", backend.LastFailure.Format("2006-01-02 15:04:05 UTC"))
			}
		}
		fmt.Printf("\n")
	}

	return nil
}

func showBackendHealthJSON(ctx context.Context, cfg AdminConfig) error {
	// Create HTTP API client
	client, err := createHTTPAPIClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create HTTP API client: %w", err)
	}

	// Build URL
	url := fmt.Sprintf("%s/admin/proxy/backends", cfg.HTTPAPIAddr)

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+cfg.HTTPAPIKey)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get backend health: %w", err)
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

	// Output raw JSON
	fmt.Println(string(body))
	return nil
}
