package metrics

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Critical operational metrics that are actually needed for production monitoring

// Resource contention metrics - CRITICAL for identifying bottlenecks
var (
	// Database connection pool saturation
	DBConnectionPoolWaitTime = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sora_db_connection_pool_wait_seconds",
			Help:    "Time spent waiting for a database connection from pool",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0},
		},
	)

	DBConnectionPoolExhausted = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "sora_db_connection_pool_exhausted_total",
			Help: "Total number of times connection pool was exhausted",
		},
	)

	// Mailbox lock contention
	MailboxLockWaitTime = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sora_mailbox_lock_wait_seconds",
			Help:    "Time spent waiting to acquire mailbox lock",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
		},
		[]string{"mailbox_type"}, // INBOX, Sent, etc.
	)

	MailboxLockDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sora_mailbox_lock_duration_seconds",
			Help:    "Time spent acquiring mailbox locks",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0},
		},
		[]string{"protocol", "lock_type", "result"}, // protocol: imap/pop3, lock_type: read/write, result: success/timeout
	)

	MailboxLockTimeouts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_mailbox_lock_timeouts_total",
			Help: "Total number of mailbox lock acquisition timeouts",
		},
		[]string{"protocol", "lock_type"}, // protocol: imap/pop3, lock_type: read/write
	)
)

// Error classification metrics - CRITICAL for debugging production issues
var (
	ProtocolErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_protocol_errors_total",
			Help: "Protocol errors by type and severity",
		},
		[]string{"protocol", "command", "error_type", "severity"},
	)
	// error_type: "timeout", "invalid_state", "quota_exceeded", "storage_error", "auth_failed"
	// severity: "client_error", "server_error", "critical"
)

// Storage operation health - CRITICAL for S3 reliability
var (
	StorageOperationErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_storage_errors_total",
			Help: "Storage operation errors by type",
		},
		[]string{"operation", "error_type"},
	)
	// error_type: "timeout", "not_found", "access_denied", "network_error", "throttled"

	StorageRetries = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_storage_retries_total",
			Help: "Storage operation retry attempts",
		},
		[]string{"operation"},
	)
)

// Generic command metrics
var (
	CommandsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_commands_total",
			Help: "Total number of commands processed by protocol",
		},
		[]string{"protocol", "command", "status"},
	)

	CommandDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sora_command_duration_seconds",
			Help:    "Duration of commands by protocol in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0},
		},
		[]string{"protocol", "command"},
	)

	// Command timeout metrics
	// Note: label names are protocol and reason (reason describes why the timeout occurred,
	// e.g. "idle", "slow_throughput", "session_max", "tls_on_plain_port").
	CommandTimeoutsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_command_timeouts_total",
			Help: "Total number of commands that exceeded timeout threshold",
		},
		[]string{"protocol", "reason"},
	)

	CommandTimeoutThresholdSeconds = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_command_timeout_threshold_seconds",
			Help: "Configured command timeout threshold in seconds by protocol",
		},
		[]string{"protocol"},
	)
)

// Throughput metrics - CRITICAL for capacity planning
var (
	MessageThroughput = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_messages_throughput_total",
			Help: "Total messages processed",
		},
		[]string{"protocol", "operation", "status"}, // operation: delivered, fetched, deleted, appended, retrieved. status: success/failure
	)

	BytesThroughput = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_bytes_throughput_total",
			Help: "Total bytes transferred",
		},
		[]string{"protocol", "direction"}, // direction: "in", "out"
	)

	MessageSizeBytes = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sora_message_size_bytes",
			Help:    "Size of messages processed by protocol in bytes",
			Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600}, // 1KB to 100MB
		},
		[]string{"protocol"},
	)
)

// Sieve metrics
var (
	SieveExecutions = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_sieve_executions_total",
			Help: "Total number of SIEVE script executions by protocol",
		},
		[]string{"protocol", "result"},
	)
)

// Queue depth metrics - CRITICAL for backpressure detection
var (
	QueueDepth = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_queue_depth",
			Help: "Current queue depth by queue type",
		},
		[]string{"queue_type"}, // "s3_upload", "deletion", "indexing"
	)

	QueueProcessingLag = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_queue_processing_lag_seconds",
			Help: "Age of oldest item in queue",
		},
		[]string{"queue_type"},
	)
)

// Slow operations tracker - Only for operations that matter
var (
	SlowOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_slow_operations_total",
			Help: "Operations exceeding latency threshold",
		},
		[]string{"operation", "threshold"}, // threshold: "100ms", "1s", "5s"
	)

	// Only track duration for known-slow operations
	CriticalOperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sora_critical_operation_duration_seconds",
			Help:    "Duration of critical operations known to be slow",
			Buckets: []float64{0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0},
		},
		[]string{"operation"},
		// operations: "search_full_text", "expunge_bulk", "append_large", "fetch_body"
	)
)

// Proxy metrics - CRITICAL for proxy server health monitoring
var (
	ProxyBackendConnections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_proxy_backend_connections_total",
			Help: "Total backend connections attempted by proxy servers",
		},
		[]string{"protocol", "result"}, // protocol: imap/lmtp/pop3/managesieve, result: success/failure
	)

	ProxyRequestsForwarded = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_proxy_requests_forwarded_total",
			Help: "Total requests forwarded to backend servers",
		},
		[]string{"protocol", "result"}, // result: success/failure
	)

	ProxyBackendLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sora_proxy_backend_latency_seconds",
			Help:    "Latency of backend responses through proxy",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0},
		},
		[]string{"protocol"},
	)

	ProxyRoutingMethod = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_proxy_routing_method_total",
			Help: "Total number of backend connections by routing method.",
		},
		[]string{"protocol", "method"}, // e.g., protocol="imap", method="prelookup"
	)

	PrelookupResult = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_prelookup_result_total",
			Help: "Total number of prelookup results by outcome type.",
		},
		[]string{"protocol", "result"}, // protocol: imap/lmtp/pop3/managesieve, result: success/user_not_found_fallback/transient_error_fallback/transient_error_rejected
	)
)

// Business metrics - Actually useful for operations
var (
	ActiveMailboxes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sora_active_mailboxes",
			Help: "Number of mailboxes with recent activity",
		},
	)

	MessageAge = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sora_message_age_at_fetch_seconds",
			Help:    "Age of messages when fetched (indicates how fresh data needs to be)",
			Buckets: []float64{60, 300, 3600, 86400, 604800}, // 1m, 5m, 1h, 1d, 1w
		},
	)
)

// User and domain metrics - CRITICAL for identifying heavy users and abuse patterns
// WARNING: High cardinality metrics - use with caution in large deployments
var (
	// Domain-level metrics (lower cardinality, safer for large deployments)
	DomainCommandCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_domain_commands_total",
			Help: "Total commands executed per domain",
		},
		[]string{"protocol", "domain", "command"}, // protocol: imap/pop3/lmtp, domain: example.com, command: SELECT/FETCH/etc
	)

	DomainConnectionCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_domain_connections_total",
			Help: "Total connections per domain",
		},
		[]string{"protocol", "domain"}, // protocol: imap/pop3/lmtp/managesieve, domain: example.com
	)

	DomainBytesTransferred = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_domain_bytes_total",
			Help: "Total bytes transferred per domain",
		},
		[]string{"protocol", "domain", "direction"}, // direction: in/out
	)

	DomainMessageCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_domain_messages_total",
			Help: "Total messages processed per domain",
		},
		[]string{"protocol", "domain", "operation"}, // operation: delivered/fetched/deleted/appended
	)

	// Top users metrics (configurable cardinality limit)
	TopUserCommandCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_top_user_commands_total",
			Help: "Commands by top users (limited cardinality for heavy users only)",
		},
		[]string{"protocol", "user_hash", "command"}, // user_hash: SHA256 hash for privacy
	)

	TopUserConnectionCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_top_user_connections_total",
			Help: "Connections by top users (limited cardinality)",
		},
		[]string{"protocol", "user_hash"},
	)

	// Heavy user detection (only track users above thresholds)
	HeavyUserOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_heavy_user_operations_total",
			Help: "Operations by users exceeding usage thresholds",
		},
		[]string{"protocol", "user_hash", "operation_type"}, // operation_type: commands/connections/bytes
	)
)

// Configuration for user metrics (to be set from config)
var (
	EnableUserMetrics    bool = false // Enable high-cardinality user metrics
	EnableDomainMetrics  bool = true  // Enable domain-level metrics (safer)
	UserMetricsThreshold int  = 1000  // Only track users above this command/connection threshold
	MaxTrackedUsers      int  = 1000  // Maximum number of users to track (prevent cardinality explosion)
	HashUsernames        bool = true  // Hash usernames for privacy (SHA256)
)

// User tracking for heavy user detection
var (
	userStats        = sync.Map{} // map[string]*UserStats
	trackedUsers     = sync.Map{} // map[string]bool
	trackedUserCount atomic.Int64
)

type UserStats struct {
	CommandCount    atomic.Int64
	ConnectionCount atomic.Int64
	BytesIn         atomic.Int64
	BytesOut        atomic.Int64
}

// Configure metrics from config values
func Configure(enableUser, enableDomain bool, threshold, maxUsers int, hashNames bool) {
	EnableUserMetrics = enableUser
	EnableDomainMetrics = enableDomain
	UserMetricsThreshold = threshold
	MaxTrackedUsers = maxUsers
	HashUsernames = hashNames
}

// Hash username for privacy if enabled
func hashUsername(username string) string {
	if !HashUsernames {
		return username
	}
	h := sha256.New()
	h.Write([]byte(username))
	return fmt.Sprintf("%x", h.Sum(nil))[:16] // First 16 chars of hash
}

// Track domain-level command
func TrackDomainCommand(protocol, domain, command string) {
	if !EnableDomainMetrics {
		return
	}
	DomainCommandCount.WithLabelValues(protocol, domain, command).Inc()
}

// Track domain-level connection
func TrackDomainConnection(protocol, domain string) {
	if !EnableDomainMetrics {
		return
	}
	DomainConnectionCount.WithLabelValues(protocol, domain).Inc()
}

// Track domain-level bytes
func TrackDomainBytes(protocol, domain, direction string, bytes int64) {
	if !EnableDomainMetrics {
		return
	}
	DomainBytesTransferred.WithLabelValues(protocol, domain, direction).Add(float64(bytes))
}

// Track domain-level messages
func TrackDomainMessage(protocol, domain, operation string) {
	if !EnableDomainMetrics {
		return
	}
	DomainMessageCount.WithLabelValues(protocol, domain, operation).Inc()
}

// Track user activity and promote to individual tracking if heavy
func TrackUserActivity(protocol, username, activity string, count int) {
	if !EnableUserMetrics {
		return
	}

	// Load or store user stats without a global lock
	statsVal, _ := userStats.LoadOrStore(username, &UserStats{})
	stats := statsVal.(*UserStats)

	var totalActivity int64

	switch activity {
	case "command":
		stats.CommandCount.Add(int64(count))
	case "connection":
		stats.ConnectionCount.Add(int64(count))
	}

	totalActivity = stats.CommandCount.Load() + stats.ConnectionCount.Load()

	// Check if user should be promoted to individual tracking
	if _, alreadyTracked := trackedUsers.Load(username); !alreadyTracked {
		if totalActivity >= int64(UserMetricsThreshold) {
			// Check if we're under the tracking limit before promoting
			if trackedUserCount.Load() < int64(MaxTrackedUsers) {
				// Promote user
				if _, loaded := trackedUsers.LoadOrStore(username, true); !loaded {
					trackedUserCount.Add(1)
					userHash := hashUsername(username)

					// Initialize metrics for this heavy user
					TopUserConnectionCount.WithLabelValues(protocol, userHash).Add(float64(stats.ConnectionCount.Load()))
					TopUserCommandCount.WithLabelValues(protocol, userHash, "total").Add(float64(stats.CommandCount.Load()))
					HeavyUserOperations.WithLabelValues(protocol, userHash, "connection").Add(float64(stats.ConnectionCount.Load()))
					HeavyUserOperations.WithLabelValues(protocol, userHash, "command").Add(float64(stats.CommandCount.Load()))
				}
			}
		}
	} else {
		// User already tracked, update metrics
		userHash := hashUsername(username)
		HeavyUserOperations.WithLabelValues(protocol, userHash, activity).Add(float64(count))
	}
}
