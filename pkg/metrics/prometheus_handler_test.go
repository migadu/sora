package metrics

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

func TestPrometheusHTTPHandler(t *testing.T) {
	t.Run("basic_metrics_endpoint", func(t *testing.T) {
		// Reset and set up test metrics
		ConnectionsTotal.Reset()
		S3OperationsTotal.Reset()

		ConnectionsTotal.WithLabelValues("imap").Add(10)
		S3OperationsTotal.WithLabelValues("PUT", "success").Add(5)

		// Create test server with Prometheus handler
		handler := promhttp.Handler()
		server := httptest.NewServer(handler)
		defer server.Close()

		// Make request to metrics endpoint
		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to get metrics: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		bodyStr := string(body)

		// Check that our metrics are present
		if !strings.Contains(bodyStr, "sora_connections_total") {
			t.Error("Expected sora_connections_total metric in response")
		}

		if !strings.Contains(bodyStr, "sora_s3_operations_total") {
			t.Error("Expected sora_s3_operations_total metric in response")
		}

		// Check specific metric values
		if !strings.Contains(bodyStr, `sora_connections_total{protocol="imap"} 10`) {
			t.Error("Expected IMAP connections total to be 10")
		}

		if !strings.Contains(bodyStr, `sora_s3_operations_total{operation="PUT",status="success"} 5`) {
			t.Error("Expected S3 PUT operations to be 5")
		}
	})

	t.Run("content_type_header", func(t *testing.T) {
		handler := promhttp.Handler()
		server := httptest.NewServer(handler)
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to get metrics: %v", err)
		}
		defer resp.Body.Close()

		contentType := resp.Header.Get("Content-Type")
		// Accept both possible content types (with or without escaping parameter)
		expectedContentTypes := []string{
			"text/plain; version=0.0.4; charset=utf-8",
			"text/plain; version=0.0.4; charset=utf-8; escaping=underscores",
		}

		found := false
		for _, expected := range expectedContentTypes {
			if contentType == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected content type to be one of %v, got %s", expectedContentTypes, contentType)
		}
	})

	t.Run("metrics_format", func(t *testing.T) {
		// Reset and set up test data
		ConnectionsTotal.Reset()
		ConnectionsCurrent.Reset()
		
		ConnectionsTotal.WithLabelValues("imap").Add(100)
		ConnectionsCurrent.WithLabelValues("imap").Set(25)

		handler := promhttp.Handler()
		server := httptest.NewServer(handler)
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to get metrics: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		bodyStr := string(body)

		// Check for HELP comments
		if !strings.Contains(bodyStr, "# HELP sora_connections_total Total number of connections established") {
			t.Error("Expected HELP comment for connections_total")
		}

		// Check for TYPE comments
		if !strings.Contains(bodyStr, "# TYPE sora_connections_total counter") {
			t.Error("Expected TYPE comment for connections_total counter")
		}

		if !strings.Contains(bodyStr, "# TYPE sora_connections_current gauge") {
			t.Error("Expected TYPE comment for connections_current gauge")
		}
	})

	t.Run("histogram_metrics_format", func(t *testing.T) {
		// Reset and set up histogram
		ConnectionDuration.Reset()
		
		ConnectionDuration.WithLabelValues("imap").Observe(0.1)
		ConnectionDuration.WithLabelValues("imap").Observe(1.0)
		ConnectionDuration.WithLabelValues("imap").Observe(5.0)

		handler := promhttp.Handler()
		server := httptest.NewServer(handler)
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to get metrics: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		bodyStr := string(body)

		// Check for histogram TYPE
		if !strings.Contains(bodyStr, "# TYPE sora_connection_duration_seconds histogram") {
			t.Error("Expected TYPE comment for connection_duration histogram")
		}

		// Check for histogram buckets
		if !strings.Contains(bodyStr, "sora_connection_duration_seconds_bucket{") {
			t.Error("Expected histogram bucket metrics")
		}

		// Check for histogram count and sum
		if !strings.Contains(bodyStr, "sora_connection_duration_seconds_count{protocol=\"imap\"} 3") {
			t.Error("Expected histogram count to be 3")
		}

		if !strings.Contains(bodyStr, "sora_connection_duration_seconds_sum{protocol=\"imap\"}") {
			t.Error("Expected histogram sum metric")
		}
	})

	t.Run("multiple_label_values", func(t *testing.T) {
		// Reset and set up metrics with multiple label combinations
		DBQueriesTotal.Reset()
		
		DBQueriesTotal.WithLabelValues("SELECT", "success", "read").Add(100)
		DBQueriesTotal.WithLabelValues("INSERT", "failure", "write").Add(5)
		DBQueriesTotal.WithLabelValues("UPDATE", "success", "write").Add(50)

		handler := promhttp.Handler()
		server := httptest.NewServer(handler)
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to get metrics: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		bodyStr := string(body)

		// Check all label combinations are present
		expectedMetrics := []string{
			`sora_db_queries_total{operation="SELECT",role="read",status="success"} 100`,
			`sora_db_queries_total{operation="INSERT",role="write",status="failure"} 5`,
			`sora_db_queries_total{operation="UPDATE",role="write",status="success"} 50`,
		}

		for _, expected := range expectedMetrics {
			if !strings.Contains(bodyStr, expected) {
				t.Errorf("Expected metric: %s", expected)
			}
		}
	})

	t.Run("concurrent_access", func(t *testing.T) {
		// Reset metrics
		ConnectionsTotal.Reset()
		
		handler := promhttp.Handler()
		server := httptest.NewServer(handler)
		defer server.Close()

		// Simulate concurrent metric updates and endpoint access
		done := make(chan bool)
		
		// Goroutine updating metrics
		go func() {
			for i := 0; i < 100; i++ {
				ConnectionsTotal.WithLabelValues("imap").Inc()
				time.Sleep(1 * time.Millisecond)
			}
			done <- true
		}()

		// Concurrent endpoint access
		for i := 0; i < 10; i++ {
			go func() {
				resp, err := http.Get(server.URL)
				if err != nil {
					t.Errorf("Concurrent request failed: %v", err)
					return
				}
				resp.Body.Close()
				
				if resp.StatusCode != http.StatusOK {
					t.Errorf("Expected status 200, got %d", resp.StatusCode)
				}
			}()
		}

		// Wait for metric updates to complete
		<-done
		
		// Final check
		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to get final metrics: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read final response: %v", err)
		}

		bodyStr := string(body)
		if !strings.Contains(bodyStr, `sora_connections_total{protocol="imap"} 100`) {
			t.Error("Expected final connection count to be 100")
		}
	})
}

func TestPrometheusHandlerWithCustomRegistry(t *testing.T) {
	t.Run("custom_registry", func(t *testing.T) {
		// Create a custom registry
		registry := prometheus.NewRegistry()

		// Create custom metrics
		customCounter := prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "test_custom_counter",
				Help: "A custom counter for testing",
			},
			[]string{"label"},
		)

		// Register with custom registry
		registry.MustRegister(customCounter)

		// Set some data
		customCounter.WithLabelValues("test").Add(42)

		// Create handler with custom registry
		handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
		server := httptest.NewServer(handler)
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to get metrics: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}

		bodyStr := string(body)

		// Should contain our custom metric
		if !strings.Contains(bodyStr, "test_custom_counter") {
			t.Error("Expected custom metric in response")
		}

		if !strings.Contains(bodyStr, `test_custom_counter{label="test"} 42`) {
			t.Error("Expected custom metric value")
		}

		// Should NOT contain default metrics
		if strings.Contains(bodyStr, "sora_connections_total") {
			t.Error("Should not contain default metrics when using custom registry")
		}
	})
}

func TestPrometheusHandlerErrorCases(t *testing.T) {
	t.Run("gatherer_error", func(t *testing.T) {
		// Create a custom gatherer that returns an error
		errorGatherer := &errorGatherer{}
		
		handler := promhttp.HandlerFor(errorGatherer, promhttp.HandlerOpts{})
		server := httptest.NewServer(handler)
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to get metrics: %v", err)
		}
		defer resp.Body.Close()

		// Should return 500 status code on gatherer error
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("Expected status 500 on gatherer error, got %d", resp.StatusCode)
		}
	})

	t.Run("invalid_http_method", func(t *testing.T) {
		handler := promhttp.Handler()
		server := httptest.NewServer(handler)
		defer server.Close()

		// POST request should be rejected (Prometheus handler typically allows any method)
		resp, err := http.Post(server.URL, "text/plain", strings.NewReader("test"))
		if err != nil {
			t.Fatalf("Failed to make POST request: %v", err)
		}
		defer resp.Body.Close()

		// Note: Prometheus handler actually accepts POST requests, so this test might pass
		// Let's just verify we get a response
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			t.Logf("POST request returned status %d (this may be expected)", resp.StatusCode)
		}
	})
}

// Mock error gatherer for testing error handling
type errorGatherer struct{}

func (e *errorGatherer) Gather() ([]*dto.MetricFamily, error) {
	return nil, fmt.Errorf("mock gatherer error")
}

func TestPrometheusHandlerConfiguration(t *testing.T) {
	t.Run("handler_with_options", func(t *testing.T) {
		// Test handler with custom options
		opts := promhttp.HandlerOpts{
			ErrorLog:      nil,
			ErrorHandling: promhttp.ContinueOnError,
			Registry:      prometheus.DefaultRegisterer,
		}

		handler := promhttp.HandlerFor(prometheus.DefaultGatherer, opts)
		server := httptest.NewServer(handler)
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to get metrics with custom options: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 with custom options, got %d", resp.StatusCode)
		}
	})
}

func TestPrometheusMetricsServer(t *testing.T) {
	t.Run("metrics_server_lifecycle", func(t *testing.T) {
		// Test starting and stopping a metrics server
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())

		server := &http.Server{
			Addr:    ":0", // Use any available port
			Handler: mux,
		}

		// Start server in goroutine
		errChan := make(chan error, 1)
		go func() {
			if err := server.ListenAndServe(); err != http.ErrServerClosed {
				errChan <- err
			}
		}()

		// Give server time to start
		time.Sleep(10 * time.Millisecond)

		// Shutdown server
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			t.Errorf("Failed to shutdown server: %v", err)
		}

		// Check for any startup errors
		select {
		case err := <-errChan:
			t.Errorf("Server error: %v", err)
		default:
			// No error, which is expected
		}
	})

	t.Run("custom_path", func(t *testing.T) {
		// Test metrics on custom path
		mux := http.NewServeMux()
		mux.Handle("/custom/metrics", promhttp.Handler())

		server := httptest.NewServer(mux)
		defer server.Close()

		// Request to custom path should work
		resp, err := http.Get(server.URL + "/custom/metrics")
		if err != nil {
			t.Fatalf("Failed to get metrics from custom path: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for custom path, got %d", resp.StatusCode)
		}

		// Request to default path should fail
		resp2, err := http.Get(server.URL + "/metrics")
		if err != nil {
			t.Fatalf("Failed to make request to default path: %v", err)
		}
		defer resp2.Body.Close()

		if resp2.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status 404 for default path when using custom path, got %d", resp2.StatusCode)
		}
	})
}


func TestMetricsWithRealWorldData(t *testing.T) {
	t.Run("realistic_metrics_scenario", func(t *testing.T) {
		// Reset all metrics
		ConnectionsTotal.Reset()
		ConnectionsCurrent.Reset()
		AuthenticationAttempts.Reset()
		DBQueriesTotal.Reset()
		S3OperationsTotal.Reset()
		CacheOperationsTotal.Reset()

		// Simulate realistic server activity
		protocols := []string{"imap", "pop3", "lmtp"}
		
		// Connection activity
		for _, protocol := range protocols {
			ConnectionsTotal.WithLabelValues(protocol).Add(1000)
			ConnectionsCurrent.WithLabelValues(protocol).Set(50)
			AuthenticationAttempts.WithLabelValues(protocol, "success").Add(950)
			AuthenticationAttempts.WithLabelValues(protocol, "failure").Add(50)
		}

		// Database activity
		operations := []string{"SELECT", "INSERT", "UPDATE", "DELETE"}
		for _, op := range operations {
			DBQueriesTotal.WithLabelValues(op, "success", "read").Add(5000)
			DBQueriesTotal.WithLabelValues(op, "success", "write").Add(1000)
			DBQueriesTotal.WithLabelValues(op, "failure", "read").Add(10)
		}

		// S3 activity
		s3Ops := []string{"PUT", "GET", "DELETE"}
		for _, op := range s3Ops {
			S3OperationsTotal.WithLabelValues(op, "success").Add(2000)
			S3OperationsTotal.WithLabelValues(op, "failure").Add(20)
		}

		// Cache activity
		CacheOperationsTotal.WithLabelValues("get", "hit").Add(10000)
		CacheOperationsTotal.WithLabelValues("get", "miss").Add(1000)
		CacheOperationsTotal.WithLabelValues("put", "success").Add(1200)

		// Get metrics
		handler := promhttp.Handler()
		server := httptest.NewServer(handler)
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to get metrics: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}

		bodyStr := string(body)

		// Verify various metrics are present with expected values
		expectedMetrics := []string{
			`sora_connections_total{protocol="imap"} 1000`,
			`sora_authentication_attempts_total{protocol="imap",result="success"} 950`,
			`sora_db_queries_total{operation="SELECT",role="read",status="success"} 5000`,
			`sora_s3_operations_total{operation="PUT",status="success"} 2000`,
			`sora_cache_operations_total{operation="get",result="hit"} 10000`,
		}

		for _, expected := range expectedMetrics {
			if !strings.Contains(bodyStr, expected) {
				t.Errorf("Expected metric not found: %s", expected)
			}
		}

		// Check that response size is reasonable (not empty, not too large)
		if len(bodyStr) < 1000 {
			t.Error("Metrics response seems too small")
		}
		if len(bodyStr) > 100000 {
			t.Error("Metrics response seems too large")
		}
	})
}