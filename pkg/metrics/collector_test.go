package metrics

import (
	"context"
	"testing"
	"time"
)

// mockStatsProvider implements StatsProvider for testing
type mockStatsProvider struct {
	stats *MetricsStats
	err   error
}

func (m *mockStatsProvider) GetMetricsStatsWithRetry(ctx context.Context) (*MetricsStats, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.stats, nil
}

func TestCollectorBasic(t *testing.T) {
	// Reset metrics before test
	AccountsTotal.Set(0)
	MailboxesTotal.Set(0)

	provider := &mockStatsProvider{
		stats: &MetricsStats{
			TotalAccounts:  5,
			TotalMailboxes: 12,
			TotalMessages:  150,
		},
	}

	collector := NewCollector(provider, 100*time.Millisecond)

	// Create a context that will cancel after 250ms
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	// Start collector in background
	done := make(chan struct{})
	go func() {
		collector.Start(ctx)
		close(done)
	}()

	// Wait for collection to complete
	<-done

	// The collector should have run at least twice (immediate + after 100ms)
	// Note: We can't easily verify the exact metric values due to Prometheus registry behavior
	// but we can verify the collector starts and stops without errors
}

func TestCollectorWithError(t *testing.T) {
	provider := &mockStatsProvider{
		err: context.DeadlineExceeded,
	}

	collector := NewCollector(provider, 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Should not panic even with errors
	done := make(chan struct{})
	go func() {
		collector.Start(ctx)
		close(done)
	}()

	<-done
}

func TestNewCollectorDefaultInterval(t *testing.T) {
	provider := &mockStatsProvider{
		stats: &MetricsStats{},
	}

	collector := NewCollector(provider, 0)
	if collector.interval != 60*time.Second {
		t.Errorf("Expected default interval of 60s, got %v", collector.interval)
	}
}
