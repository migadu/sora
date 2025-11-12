package main

// cache.go - Command handlers for cache
// Extracted from main.go for better organization

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
)

func handleCacheCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printCacheUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "stats":
		handleCacheStats(ctx)
	case "metrics":
		handleCacheMetrics(ctx)
	case "purge":
		handleCachePurge(ctx)
	case "help", "--help", "-h":
		printCacheUsage()
	default:
		fmt.Printf("Unknown cache subcommand: %s\n\n", subcommand)
		printCacheUsage()
		os.Exit(1)
	}
}

func handleCacheStats(ctx context.Context) {
	// Parse cache-stats specific flags
	fs := flag.NewFlagSet("cache stats", flag.ExitOnError)

	fs.Usage = func() {
		fmt.Printf(`Show local cache size and object count

Usage:
  sora-admin cache-stats [options]

Options:
  --config string        Path to TOML configuration file (required)

This command shows:
  - Cache directory path
  - Number of cached objects
  - Total cache size in bytes and human-readable format
  - Cache capacity and maximum object size

Examples:
  sora-admin cache-stats
  sora-admin cache-stats --config /path/to/config.toml
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments

	// Show cache stats
	if err := showCacheStats(ctx, globalConfig); err != nil {
		logger.Fatalf("Failed to show cache stats: %v", err)
	}
}

func handleCachePurge(ctx context.Context) {
	// Parse cache-purge specific flags
	fs := flag.NewFlagSet("cache purge", flag.ExitOnError)

	confirm := fs.Bool("confirm", false, "Confirm cache purge without interactive prompt")

	fs.Usage = func() {
		fmt.Printf(`Clear all cached objects

Usage:
  sora-admin cache-purge [options]

Options:
  --config string        Path to TOML configuration file (required)
  --confirm            Confirm cache purge without interactive prompt

This command removes all cached objects from the local cache directory
and clears the cache index database. This action cannot be undone.

Examples:
  sora-admin cache-purge
  sora-admin cache-purge --confirm
  sora-admin cache-purge --config /path/to/config.toml --confirm
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments

	// Purge cache
	if err := purgeCacheWithConfirmation(ctx, globalConfig, *confirm); err != nil {
		logger.Fatalf("Failed to purge cache: %v", err)
	}
}

func handleCacheMetrics(ctx context.Context) {
	// Parse cache-metrics specific flags
	fs := flag.NewFlagSet("cache metrics", flag.ExitOnError)

	instanceID := fs.String("instance", "", "Show metrics for specific instance ID")
	since := fs.String("since", "24h", "Time window for historical metrics (e.g., 1h, 24h, 7d)")
	showHistory := fs.Bool("history", false, "Show historical metrics instead of just latest")
	limit := fs.Int("limit", 50, "Maximum number of historical records to show")
	jsonOutput := fs.Bool("json", false, "Output in JSON format")

	fs.Usage = func() {
		fmt.Printf(`Show cache hit/miss ratios and performance metrics

Usage:
  sora-admin cache metrics [options]

Options:
  --instance string    Show metrics for specific instance ID
  --since string       Time window for historical metrics (default: 24h)
  --history            Show historical metrics instead of just latest
  --limit int          Maximum number of historical records to show (default: 50)
  --json               Output in JSON format
  --config string        Path to TOML configuration file (required)

This command shows:
  - Cache hit/miss ratios for each instance
  - Total cache operations and performance trends
  - Instance uptime and performance over time
  - Historical trends when using --history flag

Examples:
  sora-admin cache metrics
  sora-admin cache metrics --instance server1-cache
  sora-admin cache metrics --history --since 7d
  sora-admin cache metrics --json
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	// Parse since duration
	sinceDuration, err := helpers.ParseDuration(*since)
	if err != nil {
		logger.Fatalf("Invalid time format for --since '%s'. Use a duration string like '1h', '24h', or '7d'.", *since)
	}

	// Show cache metrics
	if err := showCacheMetrics(ctx, globalConfig, *instanceID, sinceDuration, *showHistory, *limit, *jsonOutput); err != nil {
		logger.Fatalf("Failed to show cache metrics: %v", err)
	}
}

func printCacheUsage() {
	fmt.Printf(`Cache Management

Usage:
  sora-admin cache <subcommand> [options]

Subcommands:
  stats    Show local cache size and object count
  metrics  Show cache hit/miss ratios and performance metrics
  purge    Clear all cached objects

Examples:
  sora-admin cache stats
  sora-admin cache metrics --since 1h
  sora-admin cache purge

Use 'sora-admin cache <subcommand> --help' for detailed help.
`)
}

func showCacheStats(ctx context.Context, cfg AdminConfig) error {
	// Parse cache configuration using defaulting methods
	capacityBytes := cfg.LocalCache.GetCapacityWithDefault()
	maxObjectSizeBytes := cfg.LocalCache.GetMaxObjectSizeWithDefault()
	purgeInterval := cfg.LocalCache.GetPurgeIntervalWithDefault()
	orphanCleanupAge := cfg.LocalCache.GetOrphanCleanupAgeWithDefault()

	// Connect to minimal database instance for cache initialization
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Initialize cache
	cacheInstance, err := cache.New(cfg.LocalCache.Path, capacityBytes, maxObjectSizeBytes, purgeInterval, orphanCleanupAge, rdb)
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}
	defer cacheInstance.Close()

	// Get cache statistics
	stats, err := cacheInstance.GetStats()
	if err != nil {
		return fmt.Errorf("failed to get cache statistics: %w", err)
	}

	// Display stats
	fmt.Printf("Cache Statistics\n")
	fmt.Printf("================\n\n")
	fmt.Printf("Cache path:         %s\n", cfg.LocalCache.Path)
	fmt.Printf("Object count:       %d\n", stats.ObjectCount)
	fmt.Printf("Total size:         %d bytes (%s)\n", stats.TotalSize, formatBytes(stats.TotalSize))
	fmt.Printf("Capacity:           %d bytes (%s)\n", capacityBytes, cfg.LocalCache.Capacity)
	fmt.Printf("Max object size:    %d bytes (%s)\n", maxObjectSizeBytes, cfg.LocalCache.MaxObjectSize)
	fmt.Printf("Utilization:        %.1f%%\n", float64(stats.TotalSize)/float64(capacityBytes)*100)

	return nil
}

func purgeCacheWithConfirmation(ctx context.Context, cfg AdminConfig, autoConfirm bool) error {
	if !autoConfirm {
		fmt.Printf("This will remove ALL cached objects from %s\n", cfg.LocalCache.Path)
		fmt.Printf("This action cannot be undone. Are you sure? (y/N): ")

		var response string
		if _, err := fmt.Scanln(&response); err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
			fmt.Println("Cache purge cancelled.")
			return nil
		}
	}

	// Parse cache configuration using defaulting methods
	capacityBytes := cfg.LocalCache.GetCapacityWithDefault()
	maxObjectSizeBytes := cfg.LocalCache.GetMaxObjectSizeWithDefault()
	purgeInterval := cfg.LocalCache.GetPurgeIntervalWithDefault()
	orphanCleanupAge := cfg.LocalCache.GetOrphanCleanupAgeWithDefault()

	// Connect to minimal database instance for cache initialization
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Initialize cache
	cacheInstance, err := cache.New(cfg.LocalCache.Path, capacityBytes, maxObjectSizeBytes, purgeInterval, orphanCleanupAge, rdb)
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}
	defer cacheInstance.Close()

	// Get current stats before purging
	stats, err := cacheInstance.GetStats()
	if err != nil {
		return fmt.Errorf("failed to get cache statistics before purge: %w", err)
	}

	fmt.Printf("Purging %d objects (%s) from cache...\n", stats.ObjectCount, formatBytes(stats.TotalSize))

	// Purge all cached objects
	if err := cacheInstance.PurgeAll(ctx); err != nil {
		return fmt.Errorf("failed to purge cache: %w", err)
	}

	fmt.Printf("Cache purged successfully.\n")
	return nil
}

func showCacheMetrics(ctx context.Context, cfg AdminConfig, instanceID string, sinceDuration time.Duration, showHistory bool, limit int, jsonOutput bool) error {
	// Connect to database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	if showHistory {
		return showHistoricalCacheMetrics(ctx, rdb, instanceID, sinceDuration, limit, jsonOutput)
	}

	return showLatestCacheMetrics(ctx, rdb, instanceID, jsonOutput)
}

func showLatestCacheMetrics(ctx context.Context, rdb *resilient.ResilientDatabase, instanceID string, jsonOutput bool) error {
	var metrics []*db.CacheMetricsRecord
	var err error

	if instanceID != "" {
		// Get metrics for specific instance
		// Get the single most recent metric for the instance, regardless of age.
		metrics, err = rdb.GetCacheMetricsWithRetry(ctx, instanceID, time.Time{}, 1)
	} else {
		// Get latest metrics for all instances
		metrics, err = rdb.GetLatestCacheMetricsWithRetry(ctx)
	}

	if err != nil {
		return fmt.Errorf("failed to get cache metrics: %w", err)
	}

	if jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(map[string]any{
			"metrics":   metrics,
			"timestamp": time.Now(),
		})
	}

	if len(metrics) == 0 {
		fmt.Println("No cache metrics available.")
		fmt.Println("\nNote: Cache metrics are collected when the cache is actively used.")
		fmt.Println("Start the Sora server and perform some operations to generate metrics.")
		return nil
	}

	// Display metrics in table format
	fmt.Printf("Cache Performance Metrics (Latest)\n")
	fmt.Printf("==================================\n\n")

	fmt.Printf("%-20s %-15s %-8s %-8s %-8s %-12s %-10s %-19s\n",
		"Instance ID", "Server", "Hits", "Misses", "Hit Rate", "Total Ops", "Uptime", "Recorded At")
	fmt.Printf("%s\n", strings.Repeat("-", 110))

	for _, m := range metrics {
		uptimeDuration := time.Duration(m.UptimeSeconds) * time.Second
		fmt.Printf("%-20s %-15s %-8d %-8d %-7.1f%% %-12d %-10s %-19s\n",
			truncateString(m.InstanceID, 20),
			truncateString(m.ServerHostname, 15),
			m.Hits,
			m.Misses,
			m.HitRate,
			m.TotalOperations,
			formatDuration(uptimeDuration),
			m.RecordedAt.Format("2006-01-02 15:04:05"))
	}

	// Show summary statistics
	if len(metrics) > 1 {
		var totalHits, totalMisses, totalOps int64
		for _, m := range metrics {
			totalHits += m.Hits
			totalMisses += m.Misses
			totalOps += m.TotalOperations
		}

		overallHitRate := 0.0
		if totalOps > 0 {
			overallHitRate = float64(totalHits) / float64(totalOps) * 100
		}

		fmt.Printf("\nSummary Across All Instances:\n")
		fmt.Printf("  Total Instances: %d\n", len(metrics))
		fmt.Printf("  Combined Hits:   %d\n", totalHits)
		fmt.Printf("  Combined Misses: %d\n", totalMisses)
		fmt.Printf("  Overall Hit Rate: %.1f%%\n", overallHitRate)
	}

	return nil
}

func showHistoricalCacheMetrics(ctx context.Context, rdb *resilient.ResilientDatabase, instanceID string, sinceDuration time.Duration, limit int, jsonOutput bool) error {
	since := time.Now().Add(-sinceDuration)
	metrics, err := rdb.GetCacheMetricsWithRetry(ctx, instanceID, since, limit)
	if err != nil {
		return fmt.Errorf("failed to get cache metrics: %w", err)
	}

	if jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(map[string]any{
			"metrics":   metrics,
			"since":     since,
			"timestamp": time.Now(),
		})
	}

	if len(metrics) == 0 {
		fmt.Printf("No cache metrics available for the last %s.\n", sinceDuration)
		return nil
	}

	fmt.Printf("Cache Performance Metrics (Historical - Last %s)\n", sinceDuration)
	fmt.Printf("=================================================\n\n")

	// Group by instance for better display
	instanceGroups := make(map[string][]*db.CacheMetricsRecord)
	for _, m := range metrics {
		instanceGroups[m.InstanceID] = append(instanceGroups[m.InstanceID], m)
	}

	for instance, instanceMetrics := range instanceGroups {
		fmt.Printf("Instance: %s\n", instance)
		fmt.Printf("%s\n", strings.Repeat("-", len(instance)+10))

		fmt.Printf("%-8s %-8s %-8s %-12s %-10s %-19s\n",
			"Hits", "Misses", "Hit Rate", "Total Ops", "Uptime", "Recorded At")
		fmt.Printf("%s\n", strings.Repeat("-", 75))

		for _, m := range instanceMetrics {
			uptimeDuration := time.Duration(m.UptimeSeconds) * time.Second
			fmt.Printf("%-8d %-8d %-7.1f%% %-12d %-10s %-19s\n",
				m.Hits,
				m.Misses,
				m.HitRate,
				m.TotalOperations,
				formatDuration(uptimeDuration),
				m.RecordedAt.Format("2006-01-02 15:04:05"))
		}
		fmt.Printf("\n")
	}

	return nil
}
