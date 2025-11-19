package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Connection metrics
var (
	ConnectionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_connections_total",
			Help: "Total number of connections established",
		},
		[]string{"protocol"},
	)

	ConnectionsCurrent = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_connections_current",
			Help: "Current number of active connections",
		},
		[]string{"protocol"},
	)

	AuthenticatedConnectionsCurrent = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_authenticated_connections_current",
			Help: "Current number of authenticated connections",
		},
		[]string{"protocol"},
	)

	ConnectionDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sora_connection_duration_seconds",
			Help:    "Duration of connections in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"protocol"},
	)

	AuthenticationAttempts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_authentication_attempts_total",
			Help: "Total number of authentication attempts",
		},
		[]string{"protocol", "result"},
	)
)

// Database performance metrics
var (
	DBQueriesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_db_queries_total",
			Help: "Total number of database queries executed",
		},
		[]string{"operation", "status", "role"},
	)

	DBQueryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sora_db_query_duration_seconds",
			Help:    "Duration of database queries in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0},
		},
		[]string{"operation", "role"},
	)

	MailboxesTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sora_mailboxes_total",
			Help: "Total number of mailboxes",
		},
	)

	AccountsTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sora_accounts_total",
			Help: "Total number of accounts",
		},
	)
)

// Storage metrics
var (
	S3OperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_s3_operations_total",
			Help: "Total number of S3 operations",
		},
		[]string{"operation", "status"},
	)

	S3OperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sora_s3_operation_duration_seconds",
			Help:    "Duration of S3 operations in seconds",
			Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0},
		},
		[]string{"operation"},
	)

	S3UploadAttempts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_s3_upload_attempts_total",
			Help: "Total number of S3 upload attempts",
		},
		[]string{"result"},
	)
)

// Cache metrics (S3 object cache)
var (
	CacheOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_cache_operations_total",
			Help: "Total number of cache operations",
		},
		[]string{"operation", "result"},
	)

	CacheSizeBytes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sora_cache_size_bytes",
			Help: "Current cache size in bytes",
		},
	)

	CacheObjectsTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sora_cache_objects_total",
			Help: "Current number of objects in cache",
		},
	)
)

// Authentication cache metrics
var (
	LookupCacheHitsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "sora_lookup_cache_hits_total",
			Help: "Total number of authentication cache hits",
		},
	)

	LookupCacheMissesTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "sora_lookup_cache_misses_total",
			Help: "Total number of authentication cache misses",
		},
	)

	LookupCacheEntriesTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sora_lookup_cache_entries_total",
			Help: "Current number of entries in authentication cache",
		},
	)

	LookupCacheHitRate = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sora_lookup_cache_hit_rate",
			Help: "Authentication cache hit rate percentage (0-100)",
		},
	)

	LookupCacheSharedFetchesTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "sora_lookup_cache_shared_fetches_total",
			Help: "Total number of shared fetches (thundering herd prevented)",
		},
	)
)

// Protocol-specific metrics that don't fit a generic model
var (
	// LMTP-specific
	LMTPExternalRelay = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_lmtp_external_relay_total",
			Help: "Total number of external relay attempts",
		},
		[]string{"result"},
	)

	// Relay queue metrics
	RelayQueueDepth = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_relay_queue_depth",
			Help: "Number of messages in relay queue by state",
		},
		[]string{"state"}, // pending, processing, failed
	)

	RelayDelivery = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_relay_delivery_total",
			Help: "Total number of relay delivery attempts",
		},
		[]string{"type", "result"}, // type: redirect, vacation; result: success, failure, no_handler
	)

	RelayDeliveryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sora_relay_delivery_duration_seconds",
			Help:    "Duration of relay delivery attempts",
			Buckets: []float64{0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0},
		},
		[]string{"type", "result"}, // type: redirect, vacation; result: success, failure
	)

	RelayQueueAge = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sora_relay_queue_age_seconds",
			Help:    "Age of messages in relay queue when processed",
			Buckets: []float64{1, 5, 10, 30, 60, 300, 600, 1800, 3600, 7200, 14400, 28800, 86400}, // 1s to 1 day
		},
		[]string{"type"}, // type: redirect, vacation
	)

	// Relay queue operation metrics
	RelayQueueOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_relay_queue_operations_total",
			Help: "Total number of relay queue operations",
		},
		[]string{"operation", "result"}, // operation: enqueue, acquire, mark_success, mark_failure; result: success, error
	)

	RelayQueueOperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sora_relay_queue_operation_duration_seconds",
			Help:    "Duration of relay queue operations",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
		},
		[]string{"operation"}, // operation: enqueue, acquire, mark_success, mark_failure
	)

	// IMAP-specific
	IMAPIdleConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sora_imap_idle_connections_current",
			Help: "Current number of IMAP connections in IDLE state",
		},
	)

	// ManageSieve-specific
	ManageSieveScriptsUploaded = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "sora_managesieve_scripts_uploaded_total",
			Help: "Total number of SIEVE scripts uploaded",
		},
	)

	ManageSieveScriptsActivated = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "sora_managesieve_scripts_activated_total",
			Help: "Total number of SIEVE scripts activated",
		},
	)
)

// Background worker metrics
var (
	UploadWorkerJobs = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_upload_worker_jobs_total",
			Help: "Total number of upload worker jobs processed",
		},
		[]string{"result"},
	)

	UploadWorkerDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sora_upload_worker_duration_seconds",
			Help:    "Duration of upload worker jobs in seconds",
			Buckets: []float64{0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0},
		},
	)
)

// Health status metrics
var (
	ComponentHealthStatus = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_component_health_status",
			Help: "Health status of components (0=unreachable, 1=unhealthy, 2=degraded, 3=healthy)",
		},
		[]string{"component", "hostname"},
	)

	ComponentHealthChecks = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_component_health_checks_total",
			Help: "Total number of health checks performed",
		},
		[]string{"component", "hostname", "status"},
	)

	ComponentHealthCheckDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sora_component_health_check_duration_seconds",
			Help:    "Duration of health checks in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0},
		},
		[]string{"component", "hostname"},
	)
)

// Session memory metrics
var (
	SessionMemoryPeakBytes = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sora_session_memory_peak_bytes",
			Help:    "Peak memory allocated by session during its lifetime in bytes",
			Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 52428800, 104857600}, // 1KB to 100MB
		},
		[]string{"protocol"},
	)

	SessionMemoryLimitExceeded = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_session_memory_limit_exceeded_total",
			Help: "Total number of times session memory limit was exceeded",
		},
		[]string{"protocol"},
	)
)

// Timeout scheduler metrics
var (
	TimeoutSchedulerConnectionsTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_timeout_scheduler_connections_total",
			Help: "Total number of connections registered with timeout scheduler",
		},
		[]string{"shard"},
	)

	TimeoutSchedulerCheckDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sora_timeout_scheduler_check_duration_seconds",
			Help:    "Duration of timeout check cycles per shard",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
		},
		[]string{"shard"},
	)

	// Connection timeout events (different from command timeouts)
	ConnectionTimeoutsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_connection_timeouts_total",
			Help: "Total number of connection timeouts by protocol and reason",
		},
		[]string{"protocol", "reason"}, // reason: idle, slow_throughput, session_max, tls_on_plain_port
	)
)

// Memory usage metrics for internal caches and maps
var (
	// Auth rate limiter memory usage
	AuthRateLimiterIPUsernameEntries = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_auth_rate_limiter_ip_username_entries",
			Help: "Number of IP+username entries in auth rate limiter",
		},
		[]string{"protocol"},
	)

	AuthRateLimiterIPEntries = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_auth_rate_limiter_ip_entries",
			Help: "Number of IP failure entries in auth rate limiter",
		},
		[]string{"protocol"},
	)

	AuthRateLimiterUsernameEntries = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_auth_rate_limiter_username_entries",
			Help: "Number of username failure entries in auth rate limiter",
		},
		[]string{"protocol"},
	)

	AuthRateLimiterBlockedIPs = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_auth_rate_limiter_blocked_ips",
			Help: "Number of blocked IPs in auth rate limiter",
		},
		[]string{"protocol"},
	)

	// Connection tracker memory usage (proxy mode)
	ConnectionTrackerUsers = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_connection_tracker_users",
			Help: "Number of users tracked in connection tracker",
		},
		[]string{"protocol"},
	)

	ConnectionTrackerInstanceIDs = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_connection_tracker_instance_ids",
			Help: "Number of instance IDs tracked across all users",
		},
		[]string{"protocol"},
	)

	ConnectionTrackerIPs = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_connection_tracker_ips",
			Help: "Number of IPs tracked across all users",
		},
		[]string{"protocol"},
	)

	ConnectionTrackerBroadcastQueue = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_connection_tracker_broadcast_queue_size",
			Help: "Size of connection tracker broadcast queue",
		},
		[]string{"protocol"},
	)

	// Affinity manager memory usage
	AffinityManagerEntries = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sora_affinity_manager_entries",
			Help: "Number of affinity entries in affinity manager",
		},
	)

	AffinityManagerBroadcastQueue = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sora_affinity_manager_broadcast_queue_size",
			Help: "Size of affinity manager broadcast queue",
		},
	)

	// Auth cache metrics
	CacheSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_cache_entries",
			Help: "Number of entries in cache by type",
		},
		[]string{"type"}, // auth, etc
	)

	CacheHitRatio = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_cache_hit_ratio",
			Help: "Cache hit ratio (0-1) by type",
		},
		[]string{"type"},
	)
)
