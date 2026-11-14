package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestDBTransactionMetricsBasic(t *testing.T) {
	// Reset metrics
	DBTransactionsTotal.Reset()

	t.Run("db_transactions_total", func(t *testing.T) {
		statuses := []string{"commit", "rollback"}

		for _, status := range statuses {
			DBTransactionsTotal.WithLabelValues(status).Add(10)
		}

		commitCount := testutil.ToFloat64(DBTransactionsTotal.WithLabelValues("commit"))
		rollbackCount := testutil.ToFloat64(DBTransactionsTotal.WithLabelValues("rollback"))

		if commitCount != 10 {
			t.Errorf("Expected 10 commit transactions, got %f", commitCount)
		}
		if rollbackCount != 10 {
			t.Errorf("Expected 10 rollback transactions, got %f", rollbackCount)
		}
	})

	t.Run("db_transaction_duration_histogram", func(t *testing.T) {
		// Test histogram accepts observations
		durations := []float64{0.005, 0.01, 0.1, 1.0, 5.0}

		for _, duration := range durations {
			DBTransactionDuration.Observe(duration)
		}

		// If we got here without panic, histogram is working
	})
}

func TestDBConnectionPoolMetricsBasic(t *testing.T) {
	// Reset metrics
	DBPoolTotalConns.Reset()
	DBPoolIdleConns.Reset()
	DBPoolInUseConns.Reset()

	t.Run("db_pool_gauges", func(t *testing.T) {

		DBPoolTotalConns.WithLabelValues("read").Set(20)
		DBPoolTotalConns.WithLabelValues("write").Set(10)
		DBPoolIdleConns.WithLabelValues("read").Set(15)
		DBPoolIdleConns.WithLabelValues("write").Set(5)
		DBPoolInUseConns.WithLabelValues("read").Set(5)
		DBPoolInUseConns.WithLabelValues("write").Set(5)

		readTotal := testutil.ToFloat64(DBPoolTotalConns.WithLabelValues("read"))
		writeTotal := testutil.ToFloat64(DBPoolTotalConns.WithLabelValues("write"))
		readIdle := testutil.ToFloat64(DBPoolIdleConns.WithLabelValues("read"))
		writeIdle := testutil.ToFloat64(DBPoolIdleConns.WithLabelValues("write"))
		readInUse := testutil.ToFloat64(DBPoolInUseConns.WithLabelValues("read"))
		writeInUse := testutil.ToFloat64(DBPoolInUseConns.WithLabelValues("write"))

		if readTotal != 20 {
			t.Errorf("Expected 20 read connections, got %f", readTotal)
		}
		if writeTotal != 10 {
			t.Errorf("Expected 10 write connections, got %f", writeTotal)
		}
		if readIdle != 15 {
			t.Errorf("Expected 15 idle read connections, got %f", readIdle)
		}
		if writeIdle != 5 {
			t.Errorf("Expected 5 idle write connections, got %f", writeIdle)
		}
		if readInUse != 5 {
			t.Errorf("Expected 5 in-use read connections, got %f", readInUse)
		}
		if writeInUse != 5 {
			t.Errorf("Expected 5 in-use write connections, got %f", writeInUse)
		}

		// Test consistency: total should equal idle + in-use for read pool
		if readTotal != readIdle+readInUse {
			t.Errorf("Read pool total (%f) should equal idle (%f) + in-use (%f)", readTotal, readIdle, readInUse)
		}

		// Test consistency: total should equal idle + in-use for write pool
		if writeTotal != writeIdle+writeInUse {
			t.Errorf("Write pool total (%f) should equal idle (%f) + in-use (%f)", writeTotal, writeIdle, writeInUse)
		}
	})
}

func TestDBPoolExhaustionMetricsBasic(t *testing.T) {
	DBPoolExhaustion.Reset()

	DBPoolExhaustion.WithLabelValues("read").Add(2)
	DBPoolExhaustion.WithLabelValues("write").Add(1)

	if got := testutil.ToFloat64(DBPoolExhaustion.WithLabelValues("read")); got != 2 {
		t.Errorf("Expected 2 read exhaustions, got %f", got)
	}
	if got := testutil.ToFloat64(DBPoolExhaustion.WithLabelValues("write")); got != 1 {
		t.Errorf("Expected 1 write exhaustion, got %f", got)
	}
}

func TestDBMetricsLabels(t *testing.T) {
	t.Run("transaction_status_labels", func(t *testing.T) {
		DBTransactionsTotal.Reset()

		validStatuses := []string{"commit", "rollback"}

		for _, status := range validStatuses {
			DBTransactionsTotal.WithLabelValues(status).Inc()
		}

		for _, status := range validStatuses {
			count := testutil.ToFloat64(DBTransactionsTotal.WithLabelValues(status))
			if count != 1 {
				t.Errorf("Expected 1 transaction for status %s, got %f", status, count)
			}
		}
	})

	t.Run("role_labels", func(t *testing.T) {
		DBPoolTotalConns.Reset()

		validRoles := []string{"read", "write"}

		for _, role := range validRoles {
			DBPoolTotalConns.WithLabelValues(role).Set(10)
		}

		for _, role := range validRoles {
			poolCount := testutil.ToFloat64(DBPoolTotalConns.WithLabelValues(role))

			if poolCount != 10 {
				t.Errorf("Expected 10 total connections for %s role, got %f", role, poolCount)
			}
		}
	})
}

func TestDBMetricsIntegration(t *testing.T) {
	// Reset all DB metrics
	DBTransactionsTotal.Reset()
	DBPoolTotalConns.Reset()
	DBPoolIdleConns.Reset()
	DBPoolInUseConns.Reset()
	DBPoolExhaustion.Reset()

	t.Run("healthy_scenario", func(t *testing.T) {
		// Start with healthy pool state
		DBPoolTotalConns.WithLabelValues("write").Set(10)
		DBPoolIdleConns.WithLabelValues("write").Set(8)
		DBPoolInUseConns.WithLabelValues("write").Set(2)

		// Execute successful transactions
		DBTransactionDuration.Observe(0.025)
		DBTransactionsTotal.WithLabelValues("commit").Inc()

		// Verify the transaction was recorded
		commitCount := testutil.ToFloat64(DBTransactionsTotal.WithLabelValues("commit"))
		if commitCount != 1 {
			t.Errorf("Expected 1 commit, got %f", commitCount)
		}
	})

	t.Run("unhealthy_scenario", func(t *testing.T) {
		// Simulate unhealthy state
		DBPoolExhaustion.WithLabelValues("write").Inc()

		// Failed transactions
		DBTransactionsTotal.WithLabelValues("rollback").Add(3)

		// Verify metrics
		exhaustionCount := testutil.ToFloat64(DBPoolExhaustion.WithLabelValues("write"))
		if exhaustionCount != 1 {
			t.Errorf("Expected 1 pool exhaustion, got %f", exhaustionCount)
		}

		rollbackCount := testutil.ToFloat64(DBTransactionsTotal.WithLabelValues("rollback"))
		if rollbackCount != 3 {
			t.Errorf("Expected 3 rollbacks, got %f", rollbackCount)
		}
	})
}
