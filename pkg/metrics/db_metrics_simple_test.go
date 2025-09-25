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

func TestDBCircuitBreakerMetricsBasic(t *testing.T) {
	// Reset metrics
	DBCircuitBreakerState.Reset()
	DBCircuitBreakerFailures.Reset()
	DBConnectionAcquireTimeout.Reset()
	DBPoolExhaustion.Reset()

	t.Run("db_circuit_breaker_state", func(t *testing.T) {
		// Test setting circuit breaker state (typically only one would be active)
		DBCircuitBreakerState.WithLabelValues("closed").Set(1)
		DBCircuitBreakerState.WithLabelValues("open").Set(0)
		DBCircuitBreakerState.WithLabelValues("half_open").Set(0)

		closedState := testutil.ToFloat64(DBCircuitBreakerState.WithLabelValues("closed"))
		openState := testutil.ToFloat64(DBCircuitBreakerState.WithLabelValues("open"))
		halfOpenState := testutil.ToFloat64(DBCircuitBreakerState.WithLabelValues("half_open"))

		if closedState != 1 {
			t.Errorf("Expected closed state to be 1, got %f", closedState)
		}
		if openState != 0 {
			t.Errorf("Expected open state to be 0, got %f", openState)
		}
		if halfOpenState != 0 {
			t.Errorf("Expected half_open state to be 0, got %f", halfOpenState)
		}
	})

	t.Run("db_circuit_breaker_failures", func(t *testing.T) {
		roles := []string{"read", "write"}

		for _, role := range roles {
			DBCircuitBreakerFailures.WithLabelValues(role).Add(5)
		}

		readFailures := testutil.ToFloat64(DBCircuitBreakerFailures.WithLabelValues("read"))
		writeFailures := testutil.ToFloat64(DBCircuitBreakerFailures.WithLabelValues("write"))

		if readFailures != 5 {
			t.Errorf("Expected 5 read failures, got %f", readFailures)
		}
		if writeFailures != 5 {
			t.Errorf("Expected 5 write failures, got %f", writeFailures)
		}
	})

	t.Run("db_connection_timeouts_and_exhaustion", func(t *testing.T) {
		DBConnectionAcquireTimeout.WithLabelValues("read").Add(3)
		DBConnectionAcquireTimeout.WithLabelValues("write").Add(7)
		DBPoolExhaustion.WithLabelValues("read").Add(2)
		DBPoolExhaustion.WithLabelValues("write").Add(1)

		readTimeouts := testutil.ToFloat64(DBConnectionAcquireTimeout.WithLabelValues("read"))
		writeTimeouts := testutil.ToFloat64(DBConnectionAcquireTimeout.WithLabelValues("write"))
		readExhaustion := testutil.ToFloat64(DBPoolExhaustion.WithLabelValues("read"))
		writeExhaustion := testutil.ToFloat64(DBPoolExhaustion.WithLabelValues("write"))

		if readTimeouts != 3 {
			t.Errorf("Expected 3 read timeouts, got %f", readTimeouts)
		}
		if writeTimeouts != 7 {
			t.Errorf("Expected 7 write timeouts, got %f", writeTimeouts)
		}
		if readExhaustion != 2 {
			t.Errorf("Expected 2 read exhaustions, got %f", readExhaustion)
		}
		if writeExhaustion != 1 {
			t.Errorf("Expected 1 write exhaustion, got %f", writeExhaustion)
		}
	})
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
		DBCircuitBreakerFailures.Reset()

		validRoles := []string{"read", "write"}

		for _, role := range validRoles {
			DBPoolTotalConns.WithLabelValues(role).Set(10)
			DBCircuitBreakerFailures.WithLabelValues(role).Inc()
		}

		for _, role := range validRoles {
			poolCount := testutil.ToFloat64(DBPoolTotalConns.WithLabelValues(role))
			failureCount := testutil.ToFloat64(DBCircuitBreakerFailures.WithLabelValues(role))

			if poolCount != 10 {
				t.Errorf("Expected 10 total connections for %s role, got %f", role, poolCount)
			}
			if failureCount != 1 {
				t.Errorf("Expected 1 failure for %s role, got %f", role, failureCount)
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
	DBCircuitBreakerState.Reset()
	DBCircuitBreakerFailures.Reset()

	t.Run("healthy_scenario", func(t *testing.T) {
		// Start with healthy pool state
		DBPoolTotalConns.WithLabelValues("write").Set(10)
		DBPoolIdleConns.WithLabelValues("write").Set(8)
		DBPoolInUseConns.WithLabelValues("write").Set(2)
		DBCircuitBreakerState.WithLabelValues("closed").Set(1)
		DBCircuitBreakerState.WithLabelValues("open").Set(0)

		// Execute successful transactions
		DBTransactionDuration.Observe(0.025)
		DBTransactionsTotal.WithLabelValues("commit").Inc()

		// Verify the transaction was recorded
		commitCount := testutil.ToFloat64(DBTransactionsTotal.WithLabelValues("commit"))
		if commitCount != 1 {
			t.Errorf("Expected 1 commit, got %f", commitCount)
		}

		closedState := testutil.ToFloat64(DBCircuitBreakerState.WithLabelValues("closed"))
		if closedState != 1 {
			t.Errorf("Expected circuit breaker to be closed, got %f", closedState)
		}
	})

	t.Run("unhealthy_scenario", func(t *testing.T) {
		// Simulate unhealthy state
		DBCircuitBreakerFailures.WithLabelValues("write").Add(5)
		DBPoolExhaustion.WithLabelValues("write").Inc()

		// Circuit breaker opens
		DBCircuitBreakerState.WithLabelValues("closed").Set(0)
		DBCircuitBreakerState.WithLabelValues("open").Set(1)

		// Failed transactions
		DBTransactionsTotal.WithLabelValues("rollback").Add(3)

		// Verify metrics
		failureCount := testutil.ToFloat64(DBCircuitBreakerFailures.WithLabelValues("write"))
		if failureCount != 5 {
			t.Errorf("Expected 5 circuit breaker failures, got %f", failureCount)
		}

		openState := testutil.ToFloat64(DBCircuitBreakerState.WithLabelValues("open"))
		if openState != 1 {
			t.Errorf("Expected circuit breaker to be open, got %f", openState)
		}

		rollbackCount := testutil.ToFloat64(DBTransactionsTotal.WithLabelValues("rollback"))
		if rollbackCount != 3 {
			t.Errorf("Expected 3 rollbacks, got %f", rollbackCount)
		}
	})
}
