package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestResourceContentionMetricsBasic(t *testing.T) {
	// Reset metrics
	MailboxLockTimeouts.Reset()

	t.Run("db_connection_pool_exhausted", func(t *testing.T) {
		DBConnectionPoolExhausted.Add(3)

		count := testutil.ToFloat64(DBConnectionPoolExhausted)
		if count != 3 {
			t.Errorf("Expected 3 pool exhaustions, got %f", count)
		}
	})

	t.Run("mailbox_lock_timeouts", func(t *testing.T) {
		MailboxLockTimeouts.WithLabelValues("imap", "write").Add(2)
		MailboxLockTimeouts.WithLabelValues("pop3", "read").Inc()

		imapTimeouts := testutil.ToFloat64(MailboxLockTimeouts.WithLabelValues("imap", "write"))
		pop3Timeouts := testutil.ToFloat64(MailboxLockTimeouts.WithLabelValues("pop3", "read"))

		if imapTimeouts != 2 {
			t.Errorf("Expected 2 IMAP write timeouts, got %f", imapTimeouts)
		}
		if pop3Timeouts != 1 {
			t.Errorf("Expected 1 POP3 read timeout, got %f", pop3Timeouts)
		}
	})

	t.Run("histograms_work", func(t *testing.T) {
		// Test that histograms accept observations without error
		DBConnectionPoolWaitTime.Observe(0.05)
		MailboxLockWaitTime.WithLabelValues("INBOX").Observe(0.01)
		MailboxLockDuration.WithLabelValues("imap", "read", "success").Observe(0.02)
		CommandDuration.WithLabelValues("imap", "SELECT").Observe(0.1)
		MessageSizeBytes.WithLabelValues("imap").Observe(1024)
		CriticalOperationDuration.WithLabelValues("search_full_text").Observe(2.0)
		ProxyBackendLatency.WithLabelValues("imap").Observe(0.01)
		MessageAge.Observe(3600)

		// If we got here without panic, histograms are working
	})
}

func TestErrorClassificationMetrics(t *testing.T) {
	// Reset metrics
	ProtocolErrors.Reset()

	t.Run("protocol_errors", func(t *testing.T) {
		protocols := []string{"imap", "pop3"}
		commands := []string{"SELECT", "RETR"}
		errorTypes := []string{"timeout", "invalid_state"}
		severities := []string{"client_error", "server_error"}

		for _, protocol := range protocols {
			for _, command := range commands {
				for _, errorType := range errorTypes {
					for _, severity := range severities {
						ProtocolErrors.WithLabelValues(protocol, command, errorType, severity).Inc()
					}
				}
			}
		}

		// Verify some combinations were recorded
		count := testutil.ToFloat64(ProtocolErrors.WithLabelValues("imap", "SELECT", "timeout", "client_error"))
		if count != 1 {
			t.Errorf("Expected 1 error for imap-SELECT-timeout-client_error, got %f", count)
		}
	})
}

func TestStorageOperationHealth(t *testing.T) {
	// Reset metrics
	StorageOperationErrors.Reset()
	StorageRetries.Reset()

	t.Run("storage_operation_errors", func(t *testing.T) {
		operations := []string{"PUT", "GET"}
		errorTypes := []string{"timeout", "not_found"}

		for _, operation := range operations {
			for _, errorType := range errorTypes {
				StorageOperationErrors.WithLabelValues(operation, errorType).Inc()
			}
		}

		putTimeoutCount := testutil.ToFloat64(StorageOperationErrors.WithLabelValues("PUT", "timeout"))
		getNotFoundCount := testutil.ToFloat64(StorageOperationErrors.WithLabelValues("GET", "not_found"))

		if putTimeoutCount != 1 {
			t.Errorf("Expected 1 PUT timeout error, got %f", putTimeoutCount)
		}
		if getNotFoundCount != 1 {
			t.Errorf("Expected 1 GET not_found error, got %f", getNotFoundCount)
		}
	})

	t.Run("storage_retries", func(t *testing.T) {
		StorageRetries.WithLabelValues("PUT").Add(5)
		StorageRetries.WithLabelValues("GET").Add(3)

		putRetries := testutil.ToFloat64(StorageRetries.WithLabelValues("PUT"))
		getRetries := testutil.ToFloat64(StorageRetries.WithLabelValues("GET"))

		if putRetries != 5 {
			t.Errorf("Expected 5 PUT retries, got %f", putRetries)
		}
		if getRetries != 3 {
			t.Errorf("Expected 3 GET retries, got %f", getRetries)
		}
	})
}

func TestCommandMetrics(t *testing.T) {
	// Reset metrics
	CommandsTotal.Reset()

	t.Run("commands_total", func(t *testing.T) {
		protocols := []string{"imap", "pop3"}
		commands := []string{"SELECT", "RETR"}
		statuses := []string{"success", "failure"}

		for _, protocol := range protocols {
			for _, command := range commands {
				for _, status := range statuses {
					CommandsTotal.WithLabelValues(protocol, command, status).Inc()
				}
			}
		}

		selectSuccessCount := testutil.ToFloat64(CommandsTotal.WithLabelValues("imap", "SELECT", "success"))
		retrFailureCount := testutil.ToFloat64(CommandsTotal.WithLabelValues("pop3", "RETR", "failure"))

		if selectSuccessCount != 1 {
			t.Errorf("Expected 1 SELECT success, got %f", selectSuccessCount)
		}
		if retrFailureCount != 1 {
			t.Errorf("Expected 1 RETR failure, got %f", retrFailureCount)
		}
	})
}

func TestThroughputMetrics(t *testing.T) {
	// Reset metrics
	MessageThroughput.Reset()
	BytesThroughput.Reset()

	t.Run("message_throughput", func(t *testing.T) {
		protocols := []string{"imap", "lmtp"}
		operations := []string{"delivered", "fetched"}
		statuses := []string{"success", "failure"}

		for _, protocol := range protocols {
			for _, operation := range operations {
				for _, status := range statuses {
					MessageThroughput.WithLabelValues(protocol, operation, status).Add(10)
				}
			}
		}

		deliveredCount := testutil.ToFloat64(MessageThroughput.WithLabelValues("lmtp", "delivered", "success"))
		if deliveredCount != 10 {
			t.Errorf("Expected 10 delivered messages, got %f", deliveredCount)
		}
	})

	t.Run("bytes_throughput", func(t *testing.T) {
		protocols := []string{"imap", "pop3"}
		directions := []string{"in", "out"}

		for _, protocol := range protocols {
			for _, direction := range directions {
				BytesThroughput.WithLabelValues(protocol, direction).Add(1024000) // 1MB
			}
		}

		bytesIn := testutil.ToFloat64(BytesThroughput.WithLabelValues("imap", "in"))
		if bytesIn != 1024000 {
			t.Errorf("Expected 1024000 bytes in, got %f", bytesIn)
		}
	})
}

func TestQueueMetrics(t *testing.T) {
	t.Run("queue_depth", func(t *testing.T) {
		queueTypes := []string{"s3_upload", "deletion"}

		for i, queueType := range queueTypes {
			QueueDepth.WithLabelValues(queueType).Set(float64(100 * (i + 1)))
		}

		uploadQueueDepth := testutil.ToFloat64(QueueDepth.WithLabelValues("s3_upload"))
		deletionQueueDepth := testutil.ToFloat64(QueueDepth.WithLabelValues("deletion"))

		if uploadQueueDepth != 100 {
			t.Errorf("Expected upload queue depth 100, got %f", uploadQueueDepth)
		}
		if deletionQueueDepth != 200 {
			t.Errorf("Expected deletion queue depth 200, got %f", deletionQueueDepth)
		}
	})

	t.Run("queue_processing_lag", func(t *testing.T) {
		QueueProcessingLag.WithLabelValues("s3_upload").Set(30.5)

		lag := testutil.ToFloat64(QueueProcessingLag.WithLabelValues("s3_upload"))
		if lag != 30.5 {
			t.Errorf("Expected processing lag 30.5, got %f", lag)
		}
	})
}

func TestSlowOperations(t *testing.T) {
	// Reset metrics
	SlowOperations.Reset()

	t.Run("slow_operations", func(t *testing.T) {
		operations := []string{"search_full_text", "expunge_bulk"}
		thresholds := []string{"100ms", "1s"}

		for _, operation := range operations {
			for _, threshold := range thresholds {
				SlowOperations.WithLabelValues(operation, threshold).Inc()
			}
		}

		searchSlowCount := testutil.ToFloat64(SlowOperations.WithLabelValues("search_full_text", "1s"))
		if searchSlowCount != 1 {
			t.Errorf("Expected 1 slow search operation, got %f", searchSlowCount)
		}
	})
}

func TestProxyMetrics(t *testing.T) {
	// Reset metrics
	ProxyBackendConnections.Reset()
	ProxyRequestsForwarded.Reset()
	ProxyRoutingMethod.Reset()

	t.Run("proxy_backend_connections", func(t *testing.T) {
		protocols := []string{"imap", "pop3"}
		results := []string{"success", "failure"}

		for _, protocol := range protocols {
			for _, result := range results {
				ProxyBackendConnections.WithLabelValues(protocol, result).Add(10)
			}
		}

		successCount := testutil.ToFloat64(ProxyBackendConnections.WithLabelValues("imap", "success"))
		if successCount != 10 {
			t.Errorf("Expected 10 successful connections, got %f", successCount)
		}
	})

	t.Run("proxy_routing_method", func(t *testing.T) {
		methods := []string{"prelookup", "dynamic"}

		for _, method := range methods {
			ProxyRoutingMethod.WithLabelValues("imap", method).Add(50)
		}

		prelookupCount := testutil.ToFloat64(ProxyRoutingMethod.WithLabelValues("imap", "prelookup"))
		if prelookupCount != 50 {
			t.Errorf("Expected 50 prelookup routings, got %f", prelookupCount)
		}
	})
}

func TestBusinessMetrics(t *testing.T) {
	t.Run("active_mailboxes", func(t *testing.T) {
		ActiveMailboxes.Set(250)

		count := testutil.ToFloat64(ActiveMailboxes)
		if count != 250 {
			t.Errorf("Expected 250 active mailboxes, got %f", count)
		}
	})
}

func TestSieveMetrics(t *testing.T) {
	// Reset metrics
	SieveExecutions.Reset()

	protocols := []string{"lmtp", "managesieve"}
	results := []string{"success", "failure"}

	for _, protocol := range protocols {
		for _, result := range results {
			SieveExecutions.WithLabelValues(protocol, result).Add(5)
		}
	}

	successCount := testutil.ToFloat64(SieveExecutions.WithLabelValues("lmtp", "success"))
	if successCount != 5 {
		t.Errorf("Expected 5 successful executions, got %f", successCount)
	}
}
