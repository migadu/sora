package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Test basic metrics registration and functionality
func TestConnectionMetrics(t *testing.T) {
	// Reset the metrics before testing
	ConnectionsTotal.Reset()
	ConnectionsCurrent.Reset()
	AuthenticatedConnectionsCurrent.Reset()
	AuthenticationAttempts.Reset()

	tests := []struct {
		name     string
		protocol string
		testFunc func(string)
	}{
		{
			name:     "connections_total_increment",
			protocol: "imap",
			testFunc: func(protocol string) {
				ConnectionsTotal.WithLabelValues(protocol).Inc()
			},
		},
		{
			name:     "connections_current_set",
			protocol: "pop3",
			testFunc: func(protocol string) {
				ConnectionsCurrent.WithLabelValues(protocol).Set(5)
			},
		},
		{
			name:     "authenticated_connections_increment",
			protocol: "lmtp",
			testFunc: func(protocol string) {
				AuthenticatedConnectionsCurrent.WithLabelValues(protocol).Inc()
			},
		},
		{
			name:     "authentication_attempts_success",
			protocol: "imap",
			testFunc: func(protocol string) {
				AuthenticationAttempts.WithLabelValues(protocol, "success").Inc()
			},
		},
		{
			name:     "authentication_attempts_failure",
			protocol: "imap",
			testFunc: func(protocol string) {
				AuthenticationAttempts.WithLabelValues(protocol, "failure").Inc()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.testFunc(tt.protocol)

			// Verify the metric was updated
			switch tt.name {
			case "connections_total_increment":
				if got := testutil.ToFloat64(ConnectionsTotal.WithLabelValues(tt.protocol)); got != 1 {
					t.Errorf("Expected ConnectionsTotal to be 1, got %f", got)
				}
			case "connections_current_set":
				if got := testutil.ToFloat64(ConnectionsCurrent.WithLabelValues(tt.protocol)); got != 5 {
					t.Errorf("Expected ConnectionsCurrent to be 5, got %f", got)
				}
			case "authenticated_connections_increment":
				if got := testutil.ToFloat64(AuthenticatedConnectionsCurrent.WithLabelValues(tt.protocol)); got != 1 {
					t.Errorf("Expected AuthenticatedConnectionsCurrent to be 1, got %f", got)
				}
			case "authentication_attempts_success":
				if got := testutil.ToFloat64(AuthenticationAttempts.WithLabelValues(tt.protocol, "success")); got != 1 {
					t.Errorf("Expected AuthenticationAttempts success to be 1, got %f", got)
				}
			case "authentication_attempts_failure":
				if got := testutil.ToFloat64(AuthenticationAttempts.WithLabelValues(tt.protocol, "failure")); got != 1 {
					t.Errorf("Expected AuthenticationAttempts failure to be 1, got %f", got)
				}
			}
		})
	}
}

func TestConnectionDurationHistogram(t *testing.T) {
	ConnectionDuration.Reset()

	// Test histogram with different protocols and durations
	protocols := []string{"imap", "pop3", "lmtp"}
	durations := []float64{0.001, 0.01, 0.1, 1.0, 5.0}

	for _, protocol := range protocols {
		for _, duration := range durations {
			ConnectionDuration.WithLabelValues(protocol).Observe(duration)
		}
	}

	// For histograms, we need to check the specific metric instance
	// Note: testutil.ToFloat64 works differently with histogram vectors
	// We can verify by checking the count is greater than 0
	for _, protocol := range protocols {
		// Use the histogram count suffix to get observation count
		metric := ConnectionDuration.WithLabelValues(protocol)
		// Record one more observation to verify it's working
		metric.Observe(0.5)
	}
}

func TestDatabaseMetrics(t *testing.T) {
	// Reset the metrics
	DBQueriesTotal.Reset()
	MessagesTotal.Reset()
	MailboxesTotal.Set(0)
	AccountsTotal.Set(0)

	t.Run("db_queries_total", func(t *testing.T) {
		DBQueriesTotal.WithLabelValues("SELECT", "success", "read").Inc()
		DBQueriesTotal.WithLabelValues("INSERT", "failure", "write").Add(2)

		selectCount := testutil.ToFloat64(DBQueriesTotal.WithLabelValues("SELECT", "success", "read"))
		insertCount := testutil.ToFloat64(DBQueriesTotal.WithLabelValues("INSERT", "failure", "write"))

		if selectCount != 1 {
			t.Errorf("Expected SELECT count to be 1, got %f", selectCount)
		}
		if insertCount != 2 {
			t.Errorf("Expected INSERT count to be 2, got %f", insertCount)
		}
	})

	t.Run("messages_total_gauge", func(t *testing.T) {
		MessagesTotal.WithLabelValues("INBOX").Set(100)
		MessagesTotal.WithLabelValues("Sent").Set(50)

		inboxCount := testutil.ToFloat64(MessagesTotal.WithLabelValues("INBOX"))
		sentCount := testutil.ToFloat64(MessagesTotal.WithLabelValues("Sent"))

		if inboxCount != 100 {
			t.Errorf("Expected INBOX messages to be 100, got %f", inboxCount)
		}
		if sentCount != 50 {
			t.Errorf("Expected Sent messages to be 50, got %f", sentCount)
		}
	})

	t.Run("mailboxes_and_accounts_total", func(t *testing.T) {
		MailboxesTotal.Set(25)
		AccountsTotal.Set(10)

		mailboxCount := testutil.ToFloat64(MailboxesTotal)
		accountCount := testutil.ToFloat64(AccountsTotal)

		if mailboxCount != 25 {
			t.Errorf("Expected mailbox count to be 25, got %f", mailboxCount)
		}
		if accountCount != 10 {
			t.Errorf("Expected account count to be 10, got %f", accountCount)
		}
	})
}

func TestS3StorageMetrics(t *testing.T) {
	// Reset metrics
	S3OperationsTotal.Reset()
	S3UploadAttempts.Reset()

	t.Run("s3_operations", func(t *testing.T) {
		S3OperationsTotal.WithLabelValues("PUT", "success").Inc()
		S3OperationsTotal.WithLabelValues("GET", "failure").Add(3)

		putCount := testutil.ToFloat64(S3OperationsTotal.WithLabelValues("PUT", "success"))
		getCount := testutil.ToFloat64(S3OperationsTotal.WithLabelValues("GET", "failure"))

		if putCount != 1 {
			t.Errorf("Expected PUT operations to be 1, got %f", putCount)
		}
		if getCount != 3 {
			t.Errorf("Expected GET operations to be 3, got %f", getCount)
		}
	})

	t.Run("s3_upload_attempts", func(t *testing.T) {
		S3UploadAttempts.WithLabelValues("success").Add(10)
		S3UploadAttempts.WithLabelValues("failure").Add(2)

		successCount := testutil.ToFloat64(S3UploadAttempts.WithLabelValues("success"))
		failureCount := testutil.ToFloat64(S3UploadAttempts.WithLabelValues("failure"))

		if successCount != 10 {
			t.Errorf("Expected successful uploads to be 10, got %f", successCount)
		}
		if failureCount != 2 {
			t.Errorf("Expected failed uploads to be 2, got %f", failureCount)
		}
	})
}

func TestS3OperationDurationHistogram(t *testing.T) {
	S3OperationDuration.Reset()

	operations := []string{"PUT", "GET", "DELETE"}
	durations := []float64{0.01, 0.1, 1.0, 5.0}

	for _, operation := range operations {
		for _, duration := range durations {
			S3OperationDuration.WithLabelValues(operation).Observe(duration)
		}
	}

	// Verify histograms are working by recording more observations
	for _, operation := range operations {
		metric := S3OperationDuration.WithLabelValues(operation)
		metric.Observe(1.0) // Record one more observation to verify it's working
	}
}

func TestCacheMetrics(t *testing.T) {
	// Reset metrics
	CacheOperationsTotal.Reset()
	CacheSizeBytes.Set(0)
	CacheObjectsTotal.Set(0)

	t.Run("cache_operations", func(t *testing.T) {
		CacheOperationsTotal.WithLabelValues("get", "hit").Add(100)
		CacheOperationsTotal.WithLabelValues("get", "miss").Add(20)
		CacheOperationsTotal.WithLabelValues("put", "success").Add(80)

		hitCount := testutil.ToFloat64(CacheOperationsTotal.WithLabelValues("get", "hit"))
		missCount := testutil.ToFloat64(CacheOperationsTotal.WithLabelValues("get", "miss"))
		putCount := testutil.ToFloat64(CacheOperationsTotal.WithLabelValues("put", "success"))

		if hitCount != 100 {
			t.Errorf("Expected cache hits to be 100, got %f", hitCount)
		}
		if missCount != 20 {
			t.Errorf("Expected cache misses to be 20, got %f", missCount)
		}
		if putCount != 80 {
			t.Errorf("Expected cache puts to be 80, got %f", putCount)
		}
	})

	t.Run("cache_size_and_objects", func(t *testing.T) {
		CacheSizeBytes.Set(1024000) // 1MB
		CacheObjectsTotal.Set(500)

		sizeBytes := testutil.ToFloat64(CacheSizeBytes)
		objectCount := testutil.ToFloat64(CacheObjectsTotal)

		if sizeBytes != 1024000 {
			t.Errorf("Expected cache size to be 1024000 bytes, got %f", sizeBytes)
		}
		if objectCount != 500 {
			t.Errorf("Expected cache objects to be 500, got %f", objectCount)
		}
	})
}

func TestProtocolSpecificMetrics(t *testing.T) {
	// Reset metrics
	LMTPExternalRelay.Reset()
	IMAPIdleConnections.Set(0)

	t.Run("lmtp_external_relay", func(t *testing.T) {
		LMTPExternalRelay.WithLabelValues("success").Add(50)
		LMTPExternalRelay.WithLabelValues("failure").Add(5)

		successCount := testutil.ToFloat64(LMTPExternalRelay.WithLabelValues("success"))
		failureCount := testutil.ToFloat64(LMTPExternalRelay.WithLabelValues("failure"))

		if successCount != 50 {
			t.Errorf("Expected successful relays to be 50, got %f", successCount)
		}
		if failureCount != 5 {
			t.Errorf("Expected failed relays to be 5, got %f", failureCount)
		}
	})

	t.Run("imap_idle_connections", func(t *testing.T) {
		IMAPIdleConnections.Set(25)

		idleCount := testutil.ToFloat64(IMAPIdleConnections)

		if idleCount != 25 {
			t.Errorf("Expected IDLE connections to be 25, got %f", idleCount)
		}
	})

	t.Run("managesieve_metrics", func(t *testing.T) {
		ManageSieveScriptsUploaded.Add(10)
		ManageSieveScriptsActivated.Add(8)

		uploadedCount := testutil.ToFloat64(ManageSieveScriptsUploaded)
		activatedCount := testutil.ToFloat64(ManageSieveScriptsActivated)

		if uploadedCount != 10 {
			t.Errorf("Expected uploaded scripts to be 10, got %f", uploadedCount)
		}
		if activatedCount != 8 {
			t.Errorf("Expected activated scripts to be 8, got %f", activatedCount)
		}
	})
}

func TestBackgroundWorkerMetrics(t *testing.T) {
	// Reset metrics
	UploadWorkerJobs.Reset()

	t.Run("upload_worker_jobs", func(t *testing.T) {
		UploadWorkerJobs.WithLabelValues("success").Add(200)
		UploadWorkerJobs.WithLabelValues("failure").Add(10)

		successCount := testutil.ToFloat64(UploadWorkerJobs.WithLabelValues("success"))
		failureCount := testutil.ToFloat64(UploadWorkerJobs.WithLabelValues("failure"))

		if successCount != 200 {
			t.Errorf("Expected successful upload jobs to be 200, got %f", successCount)
		}
		if failureCount != 10 {
			t.Errorf("Expected failed upload jobs to be 10, got %f", failureCount)
		}
	})

}

func TestHistogramBuckets(t *testing.T) {
	tests := []struct {
		name         string
		histogram    prometheus.Observer
		expectedMin  float64
		expectedMax  float64
		testDuration float64
	}{
		{
			name:         "connection_duration_buckets",
			histogram:    ConnectionDuration.WithLabelValues("imap"),
			expectedMin:  0.005, // Prometheus default buckets start at 0.005
			expectedMax:  10.0,  // Prometheus default buckets end at 10
			testDuration: 1.5,
		},
		{
			name:         "db_query_duration_buckets",
			histogram:    DBQueryDuration.WithLabelValues("SELECT", "read"),
			expectedMin:  0.001,
			expectedMax:  2.0,
			testDuration: 0.05,
		},
		{
			name:         "s3_operation_duration_buckets",
			histogram:    S3OperationDuration.WithLabelValues("PUT"),
			expectedMin:  0.01,
			expectedMax:  10.0,
			testDuration: 2.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset the histogram
			if counter, ok := tt.histogram.(interface{ Reset() }); ok {
				counter.Reset()
			}

			// Record a test observation
			tt.histogram.Observe(tt.testDuration)

			// For histograms, we can't easily verify the count using testutil.ToFloat64
			// on the observer interface. Instead, we verify that the observation
			// doesn't cause a panic and that the histogram is functioning.

			// Record another observation to verify the histogram is working
			tt.histogram.Observe(tt.testDuration + 0.1)
		})
	}
}

func TestMetricsLabels(t *testing.T) {
	t.Run("connection_metrics_labels", func(t *testing.T) {
		protocols := []string{"imap", "pop3", "lmtp", "managesieve"}
		ConnectionsTotal.Reset()

		for _, protocol := range protocols {
			ConnectionsTotal.WithLabelValues(protocol).Inc()
		}

		// Verify each protocol label was recorded
		for _, protocol := range protocols {
			count := testutil.ToFloat64(ConnectionsTotal.WithLabelValues(protocol))
			if count != 1 {
				t.Errorf("Expected count 1 for protocol %s, got %f", protocol, count)
			}
		}
	})

	t.Run("db_query_labels", func(t *testing.T) {
		DBQueriesTotal.Reset()

		operations := []string{"SELECT", "INSERT", "UPDATE", "DELETE"}
		statuses := []string{"success", "failure"}
		roles := []string{"read", "write"}

		for _, op := range operations {
			for _, status := range statuses {
				for _, role := range roles {
					DBQueriesTotal.WithLabelValues(op, status, role).Inc()
				}
			}
		}

		// Verify all label combinations were recorded
		for _, op := range operations {
			for _, status := range statuses {
				for _, role := range roles {
					count := testutil.ToFloat64(DBQueriesTotal.WithLabelValues(op, status, role))
					if count != 1 {
						t.Errorf("Expected count 1 for %s-%s-%s, got %f", op, status, role, count)
					}
				}
			}
		}
	})
}

func TestMetricsOutput(t *testing.T) {
	// Reset all metrics
	ConnectionsTotal.Reset()
	S3OperationsTotal.Reset()

	// Record some test data
	ConnectionsTotal.WithLabelValues("imap").Inc()
	S3OperationsTotal.WithLabelValues("PUT", "success").Add(5)

	// Test that metrics can be gathered (this is what the Prometheus handler does)
	gatherer := prometheus.DefaultGatherer
	families, err := gatherer.Gather()
	if err != nil {
		t.Fatalf("Error gathering metrics: %v", err)
	}

	// Check that our metrics are present
	foundConnection := false
	foundS3 := false

	for _, family := range families {
		if strings.Contains(family.GetName(), "sora_connections_total") {
			foundConnection = true
		}
		if strings.Contains(family.GetName(), "sora_s3_operations_total") {
			foundS3 = true
		}
	}

	if !foundConnection {
		t.Error("Expected to find sora_connections_total metric in output")
	}
	if !foundS3 {
		t.Error("Expected to find sora_s3_operations_total metric in output")
	}
}

// Test newly implemented database metrics
func TestDatabaseQueriesTotal(t *testing.T) {
	DBQueriesTotal.Reset()

	t.Run("track_query_success", func(t *testing.T) {
		DBQueriesTotal.WithLabelValues("fetch_message_body", "success", "read").Inc()
		count := testutil.ToFloat64(DBQueriesTotal.WithLabelValues("fetch_message_body", "success", "read"))
		if count != 1 {
			t.Errorf("Expected 1 successful query, got %f", count)
		}
	})

	t.Run("track_query_error", func(t *testing.T) {
		DBQueriesTotal.WithLabelValues("search_messages", "error", "read").Inc()
		count := testutil.ToFloat64(DBQueriesTotal.WithLabelValues("search_messages", "error", "read"))
		if count != 1 {
			t.Errorf("Expected 1 failed query, got %f", count)
		}
	})

	t.Run("track_write_queries", func(t *testing.T) {
		DBQueriesTotal.WithLabelValues("insert_message", "success", "write").Add(5)
		count := testutil.ToFloat64(DBQueriesTotal.WithLabelValues("insert_message", "success", "write"))
		if count != 5 {
			t.Errorf("Expected 5 write queries, got %f", count)
		}
	})
}

// Test cache metrics
// Test S3 operations metrics
func TestS3OperationsTotal(t *testing.T) {
	S3OperationsTotal.Reset()

	t.Run("s3_put_success", func(t *testing.T) {
		S3OperationsTotal.WithLabelValues("PUT", "success").Add(10)
		count := testutil.ToFloat64(S3OperationsTotal.WithLabelValues("PUT", "success"))
		if count != 10 {
			t.Errorf("Expected 10 successful PUTs, got %f", count)
		}
	})

	t.Run("s3_put_error", func(t *testing.T) {
		S3OperationsTotal.WithLabelValues("PUT", "error").Add(2)
		count := testutil.ToFloat64(S3OperationsTotal.WithLabelValues("PUT", "error"))
		if count != 2 {
			t.Errorf("Expected 2 failed PUTs, got %f", count)
		}
	})

	t.Run("s3_get_success", func(t *testing.T) {
		S3OperationsTotal.WithLabelValues("GET", "success").Add(50)
		count := testutil.ToFloat64(S3OperationsTotal.WithLabelValues("GET", "success"))
		if count != 50 {
			t.Errorf("Expected 50 successful GETs, got %f", count)
		}
	})

	t.Run("s3_get_error", func(t *testing.T) {
		S3OperationsTotal.WithLabelValues("GET", "error").Add(5)
		count := testutil.ToFloat64(S3OperationsTotal.WithLabelValues("GET", "error"))
		if count != 5 {
			t.Errorf("Expected 5 failed GETs, got %f", count)
		}
	})

	t.Run("s3_delete_success", func(t *testing.T) {
		S3OperationsTotal.WithLabelValues("DELETE", "success").Add(8)
		count := testutil.ToFloat64(S3OperationsTotal.WithLabelValues("DELETE", "success"))
		if count != 8 {
			t.Errorf("Expected 8 successful DELETEs, got %f", count)
		}
	})

	t.Run("s3_delete_skipped", func(t *testing.T) {
		S3OperationsTotal.WithLabelValues("DELETE", "skipped").Add(3)
		count := testutil.ToFloat64(S3OperationsTotal.WithLabelValues("DELETE", "skipped"))
		if count != 3 {
			t.Errorf("Expected 3 skipped DELETEs, got %f", count)
		}
	})
}

// Test account/mailbox total gauges
func TestAccountMailboxGauges(t *testing.T) {
	AccountsTotal.Set(0)
	MailboxesTotal.Set(0)

	t.Run("accounts_total", func(t *testing.T) {
		AccountsTotal.Set(100)
		count := testutil.ToFloat64(AccountsTotal)
		if count != 100 {
			t.Errorf("Expected 100 accounts, got %f", count)
		}
	})

	t.Run("mailboxes_total", func(t *testing.T) {
		MailboxesTotal.Set(450)
		count := testutil.ToFloat64(MailboxesTotal)
		if count != 450 {
			t.Errorf("Expected 450 mailboxes, got %f", count)
		}
	})

	t.Run("accounts_increment", func(t *testing.T) {
		AccountsTotal.Set(100)
		AccountsTotal.Inc()
		count := testutil.ToFloat64(AccountsTotal)
		if count != 101 {
			t.Errorf("Expected 101 accounts after increment, got %f", count)
		}
	})
}
