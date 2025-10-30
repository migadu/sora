package metrics

import (
	"context"
	"time"

	"github.com/migadu/sora/logger"
)

// MetricsStats holds aggregate statistics returned by the database
type MetricsStats struct {
	TotalAccounts  int64
	TotalMailboxes int64
	TotalMessages  int64
}

// StatsProvider is an interface for retrieving metrics statistics
type StatsProvider interface {
	GetMetricsStatsWithRetry(ctx context.Context) (*MetricsStats, error)
}

// CacheStatsProvider is an interface for cache statistics
type CacheStatsProvider interface {
	GetStats() (objectCount int64, totalSize int64, err error)
}

// Collector periodically collects and updates database-backed metrics
type Collector struct {
	provider      StatsProvider
	cacheProvider CacheStatsProvider
	interval      time.Duration
	stopCh        chan struct{}
}

// NewCollector creates a new metrics collector
func NewCollector(provider StatsProvider, interval time.Duration) *Collector {
	if interval == 0 {
		interval = 60 * time.Second // Default to 60 seconds
	}

	return &Collector{
		provider: provider,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// NewCollectorWithCache creates a new metrics collector with cache support
func NewCollectorWithCache(provider StatsProvider, cacheProvider CacheStatsProvider, interval time.Duration) *Collector {
	if interval == 0 {
		interval = 60 * time.Second // Default to 60 seconds
	}

	return &Collector{
		provider:      provider,
		cacheProvider: cacheProvider,
		interval:      interval,
		stopCh:        make(chan struct{}),
	}
}

// Start begins the metrics collection loop
func (c *Collector) Start(ctx context.Context) {
	// Collect immediately on start
	c.collect(ctx)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	logger.Info("MetricsCollector started", "interval", c.interval)

	for {
		select {
		case <-ctx.Done():
			logger.Info("MetricsCollector stopping due to context cancellation")
			return
		case <-c.stopCh:
			logger.Info("MetricsCollector stopping due to stop signal")
			return
		case <-ticker.C:
			c.collect(ctx)
		}
	}
}

// Stop signals the collector to stop
func (c *Collector) Stop() {
	close(c.stopCh)
}

// collect retrieves and updates all metrics
func (c *Collector) collect(ctx context.Context) {
	stats, err := c.provider.GetMetricsStatsWithRetry(ctx)
	if err != nil {
		logger.Error("MetricsCollector: error collecting metrics", "error", err)
		return
	}

	// Update Prometheus gauges
	AccountsTotal.Set(float64(stats.TotalAccounts))
	MailboxesTotal.Set(float64(stats.TotalMailboxes))
	// Note: MessagesTotal is per-mailbox, so we only update the total here
	// Individual mailbox metrics would require more complex queries
	// For now, we'll skip the per-mailbox metric

	logger.Info("MetricsCollector: updated DB metrics", "accounts", stats.TotalAccounts,
		"mailboxes", stats.TotalMailboxes, "messages", stats.TotalMessages)

	// Update cache metrics if cache provider is available
	if c.cacheProvider != nil {
		objectCount, totalSize, err := c.cacheProvider.GetStats()
		if err != nil {
			logger.Error("MetricsCollector: error collecting cache metrics", "error", err)
		} else {
			CacheObjectsTotal.Set(float64(objectCount))
			CacheSizeBytes.Set(float64(totalSize))
			logger.Info("MetricsCollector: updated cache metrics", "objects", objectCount,
				"size_bytes", totalSize)
		}
	}
}
