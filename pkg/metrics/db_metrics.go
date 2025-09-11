package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Database transaction metrics
var (
	DBTransactionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_db_transactions_total",
			Help: "Total number of database transactions.",
		},
		[]string{"status"}, // status: "commit", "rollback"
	)

	DBTransactionDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sora_db_transaction_duration_seconds",
			Help:    "Duration of database transactions in seconds.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
	)
)

// Database connection pool metrics
var (
	DBPoolTotalConns = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_db_pool_total_conns",
			Help: "Total number of connections in the pool.",
		},
		[]string{"role"}, // role: "read", "write"
	)
	DBPoolIdleConns = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_db_pool_idle_conns",
			Help: "Number of idle connections in the pool.",
		},
		[]string{"role"},
	)
	DBPoolInUseConns = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_db_pool_in_use_conns",
			Help: "Number of connections currently in use.",
		},
		[]string{"role"},
	)
)

// Database circuit breaker metrics
var (
	DBCircuitBreakerState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_db_circuit_breaker_state",
			Help: "State of database circuit breaker (1=active, 0=inactive).",
		},
		[]string{"state"}, // state: "open", "closed", "half_open"
	)

	DBCircuitBreakerFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_db_circuit_breaker_failures_total",
			Help: "Total number of circuit breaker failures.",
		},
		[]string{"role"}, // role: "read", "write"
	)

	DBConnectionAcquireTimeout = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_db_connection_acquire_timeout_total",
			Help: "Total number of database connection acquire timeouts.",
		},
		[]string{"role"}, // role: "read", "write"
	)

	DBPoolExhaustion = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_db_pool_exhaustion_total",
			Help: "Total number of times the database connection pool was exhausted.",
		},
		[]string{"role"}, // role: "read", "write"
	)
)
