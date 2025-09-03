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

	MessagesTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sora_messages_total",
			Help: "Total number of messages stored",
		},
		[]string{"mailbox"},
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

// Cache metrics
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

	// IMAP-specific
	IMAPSearchDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sora_imap_search_duration_seconds",
			Help:    "Duration of IMAP search operations in seconds",
			Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0},
		},
	)

	IMAPIdleConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sora_imap_idle_connections_current",
			Help: "Current number of IMAP connections in IDLE state",
		},
	)

	IMAPMailboxOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sora_imap_mailbox_operations_total",
			Help: "Total number of IMAP mailbox operations",
		},
		[]string{"operation"},
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

	CleanerMessagesDeleted = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "sora_cleaner_messages_deleted_total",
			Help: "Total number of messages deleted by cleaner",
		},
	)

	CleanerRuntime = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sora_cleaner_runtime_seconds",
			Help:    "Duration of cleaner runs in seconds",
			Buckets: []float64{1.0, 5.0, 10.0, 30.0, 60.0, 300.0},
		},
	)
)
