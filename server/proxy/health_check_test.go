package proxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// MockUserRoutingLookup is a mock implementation of UserRoutingLookup
type MockUserRoutingLookup struct {
	serverAddress string
}

func (m *MockUserRoutingLookup) LookupUserRouteWithClientIP(ctx context.Context, email, password, clientIP string, routeOnly bool) (*UserRoutingInfo, AuthResult, error) {
	return &UserRoutingInfo{
		ServerAddress: m.serverAddress,
	}, AuthSuccess, nil
}

func (m *MockUserRoutingLookup) LookupUserRouteWithOptions(ctx context.Context, email, password string, routeOnly bool) (*UserRoutingInfo, AuthResult, error) {
	return m.LookupUserRouteWithClientIP(ctx, email, password, "", routeOnly)
}

// TestHealthCheckOnContextCancellation verifies that backend health is not affected
// when the connection fails due to context cancellation/timeout
func TestHealthCheckOnContextCancellation(t *testing.T) {
	// Create a dummy listener to simulate a healthy backend
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer ln.Close()

	backendAddr := ln.Addr().String()

	// Initialize connection manager with the backend
	cm, err := NewConnectionManager([]string{backendAddr}, 0, false, false, false, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	// Verify initial health status
	if !cm.IsBackendHealthy(backendAddr) {
		t.Errorf("Backend should be initially healthy")
	}

	// Case 1: Context canceled before connection attempt
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _, err = cm.ConnectWithProxy(ctx, "", "", 0, "", 0, nil)
	if err == nil {
		t.Error("Expected error due to canceled context, got nil")
	}

	// Verify backend is still healthy (should ignore failure due to canceled context)
	if !cm.IsBackendHealthy(backendAddr) {
		t.Errorf("Backend marked unhealthy after context cancellation failure")
	}

	// Verify failure count didn't increase
	cm.healthMu.RLock()
	health := cm.backendHealth[backendAddr]
	cm.healthMu.RUnlock()
	if health.FailureCount > 0 {
		t.Errorf("Failure count increased despite canceled context: %d", health.FailureCount)
	}

	// Case 2: Context timeout
	// Use a very short timeout that is shorter than connection timeout
	ctxTimeout, cancelTimeout := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancelTimeout()

	// Wait a tiny bit to ensure context is expired
	time.Sleep(1 * time.Millisecond)

	_, _, err = cm.ConnectWithProxy(ctxTimeout, "", "", 0, "", 0, nil)
	if err == nil {
		t.Error("Expected error due to timeout, got nil")
	}

	// Verify backend is still healthy
	if !cm.IsBackendHealthy(backendAddr) {
		t.Errorf("Backend marked unhealthy after context timeout failure")
	}

	// Case 3: Actual connection failure (listener closed)
	ln.Close()

	// Attempt connection with valid context
	ctxValid := context.Background()
	_, _, err = cm.ConnectWithProxy(ctxValid, "", "", 0, "", 0, nil)
	if err == nil {
		t.Error("Expected error due to closed listener, got nil")
	}

	// Verify failure count increased
	cm.healthMu.RLock()
	health = cm.backendHealth[backendAddr]
	cm.healthMu.RUnlock()
	if health.FailureCount == 0 {
		t.Errorf("Failure count should have increased for actual connection failure")
	}
}

// TestHealthCheckWithRemoteLookup verifies behavior when RemoteLookup backend fails
// causing context timeout for other backends
func TestHealthCheckWithRemoteLookup(t *testing.T) {
	// Create a listener for a "healthy" backend
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer ln.Close()
	backendAddr := ln.Addr().String()

	// Setup ConnectionManager
	cm, err := NewConnectionManager([]string{backendAddr}, 0, false, false, false, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	// Verify initial health
	if !cm.IsBackendHealthy(backendAddr) {
		t.Fatalf("Backend should be healthy initially")
	}

	// Simulate a scenario where we have a very short deadline left due to
	// previous operations (like slow RemoteLookup)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(1 * time.Millisecond) // Ensure timeout

	// Try to connect to the healthy backend with expired context
	_, _, err = cm.ConnectWithProxy(ctx, "", "", 0, "", 0, nil)

	// Should fail
	if err == nil {
		t.Error("Expected connection failure due to timeout")
	} else if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		// Note: exact error might vary depending on where it's caught,
		// but we care that it failed.
	}

	// CRITICAL CHECK: The healthy backend should NOT be marked as unhealthy
	// or have failure count increased because the failure was due to context timeout
	cm.healthMu.RLock()
	health := cm.backendHealth[backendAddr]
	cm.healthMu.RUnlock()

	if health.FailureCount > 0 {
		t.Errorf("Healthy backend was penalized for context timeout! FailureCount: %d", health.FailureCount)
	}

	if !cm.IsBackendHealthy(backendAddr) {
		t.Errorf("Healthy backend marked unhealthy due to context timeout")
	}
}

// TestPreferredAddressHealthCheck verifies that failing to connect to a preferred address
// due to context cancellation doesn't mark it as unhealthy
func TestPreferredAddressHealthCheck(t *testing.T) {
	// Create a listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer ln.Close()
	backendAddr := ln.Addr().String()

	cm, err := NewConnectionManager([]string{backendAddr}, 0, false, false, false, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	// Context canceled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Try to connect to specific preferred address
	conn, _, err, _ := cm.tryPreferredAddress(ctx, backendAddr, "", 0, "", 0, nil)
	if conn != nil {
		conn.Close()
	}

	// Should fail, and fallback should be true (or false depending on error type,
	// but mostly we care about health status)
	if err == nil {
		t.Error("Expected error, got nil")
	}

	// Check health
	cm.healthMu.RLock()
	health := cm.backendHealth[backendAddr]
	cm.healthMu.RUnlock()

	if health.FailureCount > 0 {
		t.Errorf("Preferred backend penalized for context cancellation! FailureCount: %d", health.FailureCount)
	}
}

// TestMultipleContextTimeouts verifies that repeated context timeouts don't accumulate
// as backend failures
func TestMultipleContextTimeouts(t *testing.T) {
	// Create a healthy listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer ln.Close()
	backendAddr := ln.Addr().String()

	cm, err := NewConnectionManager([]string{backendAddr}, 0, false, false, false, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	// Simulate 5 consecutive context timeout failures
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		time.Sleep(1 * time.Millisecond) // Ensure timeout

		_, _, err = cm.ConnectWithProxy(ctx, "", "", 0, "", 0, nil)
		cancel()

		if err == nil {
			t.Errorf("Iteration %d: Expected timeout error", i)
		}
	}

	// Verify backend is STILL healthy after 5 context timeouts
	if !cm.IsBackendHealthy(backendAddr) {
		t.Error("Backend marked unhealthy after multiple context timeouts")
	}

	// Verify failure count is still zero
	cm.healthMu.RLock()
	health := cm.backendHealth[backendAddr]
	cm.healthMu.RUnlock()

	if health.FailureCount > 0 {
		t.Errorf("Backend has failure count %d after context timeouts (should be 0)", health.FailureCount)
	}

	if health.ConsecutiveFails > 0 {
		t.Errorf("Backend has consecutive failures %d after context timeouts (should be 0)", health.ConsecutiveFails)
	}
}

// TestMixedFailures verifies that context timeouts don't count as failures,
// but real connection failures do
func TestMixedFailures(t *testing.T) {
	// Create a healthy listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer ln.Close()
	backendAddr := ln.Addr().String()

	cm, err := NewConnectionManager([]string{backendAddr}, 0, false, false, false, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	// Simulate 2 context timeouts (should NOT count)
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		time.Sleep(1 * time.Millisecond)

		_, _, err = cm.ConnectWithProxy(ctx, "", "", 0, "", 0, nil)
		cancel()

		if err == nil {
			t.Errorf("Iteration %d: Expected timeout error", i)
		}
	}

	// Close the listener to cause a real connection failure
	ln.Close()

	// Now cause 1 real connection failure (with valid context)
	validCtx := context.Background()
	_, _, err = cm.ConnectWithProxy(validCtx, "", "", 0, "", 0, nil)
	if err == nil {
		t.Error("Expected connection failure after listener closed")
	}

	// Verify failure count is exactly 1 (only the real failure counts)
	cm.healthMu.RLock()
	health := cm.backendHealth[backendAddr]
	cm.healthMu.RUnlock()

	if health.FailureCount != 1 {
		t.Errorf("Expected FailureCount=1 (only real failure), got %d", health.FailureCount)
	}

	if health.ConsecutiveFails != 1 {
		t.Errorf("Expected ConsecutiveFails=1, got %d", health.ConsecutiveFails)
	}

	// Backend should still be healthy (needs 3 consecutive failures)
	if !cm.IsBackendHealthy(backendAddr) {
		t.Error("Backend marked unhealthy after only 1 real failure (threshold is 3)")
	}

	// Add 2 more real failures to reach the threshold
	for i := 0; i < 2; i++ {
		_, _, err = cm.ConnectWithProxy(validCtx, "", "", 0, "", 0, nil)
		if err == nil {
			t.Errorf("Iteration %d: Expected connection failure", i)
		}
	}

	// Now backend should be unhealthy (3 real failures)
	if cm.IsBackendHealthy(backendAddr) {
		t.Error("Backend should be unhealthy after 3 real consecutive failures")
	}

	cm.healthMu.RLock()
	health = cm.backendHealth[backendAddr]
	cm.healthMu.RUnlock()

	if health.FailureCount != 3 {
		t.Errorf("Expected FailureCount=3, got %d", health.FailureCount)
	}

	if health.ConsecutiveFails != 3 {
		t.Errorf("Expected ConsecutiveFails=3, got %d", health.ConsecutiveFails)
	}
}

// TestRemoteLookupBackendNotInPoolDoesNotAffectPoolHealth verifies that when
// remote_lookup returns a backend that is NOT in the pool, failures to that
// backend don't affect the health of pool backends
func TestRemoteLookupBackendNotInPoolDoesNotAffectPoolHealth(t *testing.T) {
	// Create a pool backend
	poolBackend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create pool backend: %v", err)
	}
	defer poolBackend.Close()
	poolAddr := poolBackend.Addr().String()

	// Setup ConnectionManager with the pool backend
	cm, err := NewConnectionManager([]string{poolAddr}, 0, false, false, false, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	// Verify pool backend is healthy
	if !cm.IsBackendHealthy(poolAddr) {
		t.Fatal("Pool backend should be healthy initially")
	}

	// Simulate remote_lookup returning a different backend (not in pool)
	// Use an address that will fail to connect
	remoteLookupBackend := "192.0.2.1:143" // TEST-NET-1, guaranteed to fail

	// Create routing info indicating this is a remote_lookup route
	routingInfo := &UserRoutingInfo{
		ServerAddress:         remoteLookupBackend,
		IsRemoteLookupAccount: true,
	}

	// Try to connect to the remote_lookup backend (not in pool)
	ctx := context.Background()
	_, _, err, _ = cm.tryPreferredAddress(ctx, remoteLookupBackend, "", 0, "", 0, routingInfo)

	// Should fail (backend doesn't exist)
	if err == nil {
		t.Error("Expected connection failure to remote_lookup backend")
	}

	// CRITICAL: Pool backend should still be healthy
	if !cm.IsBackendHealthy(poolAddr) {
		t.Error("Pool backend marked unhealthy after remote_lookup backend failure")
	}

	// Verify pool backend has NO failures recorded
	cm.healthMu.RLock()
	poolHealth := cm.backendHealth[poolAddr]
	cm.healthMu.RUnlock()

	if poolHealth.FailureCount > 0 {
		t.Errorf("Pool backend has FailureCount=%d (should be 0)", poolHealth.FailureCount)
	}

	// Verify remote_lookup backend is NOT in the health map (not managed)
	cm.healthMu.RLock()
	_, exists := cm.backendHealth[remoteLookupBackend]
	cm.healthMu.RUnlock()

	if exists {
		t.Error("Remote lookup backend (not in pool) should NOT be in health map")
	}
}

// TestRemoteLookupFailureConsumesContextButDoesNotAffectPoolBackends verifies
// the exact scenario you encountered: remote_lookup backend is slow/down,
// consumes context deadline, then pool backends fail with DeadlineExceeded
// but should NOT be marked unhealthy
func TestRemoteLookupFailureConsumesContextButDoesNotAffectPoolBackends(t *testing.T) {
	// Create a healthy pool backend
	poolBackend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create pool backend: %v", err)
	}
	defer poolBackend.Close()
	poolAddr := poolBackend.Addr().String()

	cm, err := NewConnectionManager([]string{poolAddr}, 0, false, false, false, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	// Create a context with a short deadline (simulating request timeout)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Simulate remote_lookup returning a slow/down backend
	slowBackend := "192.0.2.1:143" // Will timeout

	routingInfo := &UserRoutingInfo{
		ServerAddress:         slowBackend,
		IsRemoteLookupAccount: true,
	}

	// Try the remote_lookup backend first (this will consume most of the context deadline)
	_, _, err, fallback := cm.tryPreferredAddress(ctx, slowBackend, "", 0, "", 0, routingInfo)

	// Should fail and NOT fallback (remote_lookup routes fail hard)
	if err == nil {
		t.Error("Expected failure to remote_lookup backend")
	}
	if fallback {
		t.Error("Remote lookup route should NOT fallback")
	}

	// At this point, context is nearly expired or already expired
	// Now try to connect to pool backend with the same exhausted context
	_, _, err = cm.ConnectWithProxy(ctx, "", "", 0, "", 0, nil)

	// Will fail due to context deadline
	if err == nil {
		t.Error("Expected failure due to context deadline")
	}

	// CRITICAL: Pool backend should STILL be healthy because the failure
	// was due to context deadline, not backend health
	if !cm.IsBackendHealthy(poolAddr) {
		t.Error("Pool backend incorrectly marked unhealthy after context deadline failure")
	}

	cm.healthMu.RLock()
	poolHealth := cm.backendHealth[poolAddr]
	cm.healthMu.RUnlock()

	if poolHealth.FailureCount > 0 {
		t.Errorf("Pool backend has FailureCount=%d after context deadline (should be 0)", poolHealth.FailureCount)
	}
}

// TestDisableHealthChecks verifies that when health checks are disabled (remote_health_checks = false),
// all backends are always considered healthy regardless of connection failures.
func TestDisableHealthChecks(t *testing.T) {
	// Create a backend that will fail (not listening)
	failingBackend := "127.0.0.1:59999"

	// Create ConnectionManager with health checks DISABLED (disableHealthCheck = true)
	cm, err := NewConnectionManagerWithRoutingAndStartTLSAndHealthCheck(
		[]string{failingBackend},
		0,
		false, // remoteTLS
		false, // remoteTLSUseStartTLS
		false, // remoteTLSVerify
		false, // remoteUseProxyProtocol
		1*time.Second,
		nil,  // routingLookup
		"",   // serverName
		true, // disableHealthCheck = true (health checks disabled)
	)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	// Verify backend is initially healthy (should always be true when checks disabled)
	if !cm.IsBackendHealthy(failingBackend) {
		t.Error("Backend should be healthy when health checks are disabled (initial state)")
	}

	// Try to connect multiple times (will fail since backend is not listening)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, _, err := cm.ConnectWithProxy(ctx, "", "", 0, "", 0, nil)
		if err == nil {
			t.Error("Expected connection to fail (backend not listening)")
		}
	}

	// CRITICAL: Backend should STILL be healthy because health checks are disabled
	if !cm.IsBackendHealthy(failingBackend) {
		t.Error("Backend should remain healthy after failures when health checks are disabled")
	}

	// Check internal health tracking
	cm.healthMu.RLock()
	backendHealth := cm.backendHealth[failingBackend]
	cm.healthMu.RUnlock()

	// When health checks are disabled, IsBackendHealthy should return true
	// regardless of the internal health state
	if backendHealth != nil && backendHealth.FailureCount > 0 {
		// Failures may be tracked internally, but IsBackendHealthy should ignore them
		t.Logf("Internal FailureCount=%d (tracked but ignored when health checks disabled)", backendHealth.FailureCount)
	}
}

// TestEnableHealthChecks verifies that when health checks are enabled (default, remote_health_checks = true),
// backends are marked unhealthy after consecutive failures.
func TestEnableHealthChecks(t *testing.T) {
	// Create a backend that will fail (not listening)
	failingBackend := "127.0.0.1:59998"

	// Create ConnectionManager with health checks ENABLED (disableHealthCheck = false, the default)
	cm, err := NewConnectionManagerWithRoutingAndStartTLSAndHealthCheck(
		[]string{failingBackend},
		0,
		false, // remoteTLS
		false, // remoteTLSUseStartTLS
		false, // remoteTLSVerify
		false, // remoteUseProxyProtocol
		1*time.Second,
		nil,   // routingLookup
		"",    // serverName
		false, // disableHealthCheck = false (health checks enabled - DEFAULT)
	)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	// Verify backend is initially healthy
	if !cm.IsBackendHealthy(failingBackend) {
		t.Error("Backend should be healthy initially")
	}

	// Try to connect 3 times (threshold for marking unhealthy)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, _, err := cm.ConnectWithProxy(ctx, "", "", 0, "", 0, nil)
		if err == nil {
			t.Error("Expected connection to fail (backend not listening)")
		}
	}

	// CRITICAL: Backend should now be UNHEALTHY because health checks are enabled
	if cm.IsBackendHealthy(failingBackend) {
		t.Error("Backend should be unhealthy after 3 consecutive failures when health checks are enabled")
	}

	// Verify internal health tracking
	cm.healthMu.RLock()
	backendHealth := cm.backendHealth[failingBackend]
	cm.healthMu.RUnlock()

	if backendHealth == nil {
		t.Fatal("Backend health should be tracked")
	}

	if backendHealth.IsHealthy {
		t.Error("Backend should be marked unhealthy internally")
	}

	if backendHealth.ConsecutiveFails < 3 {
		t.Errorf("Backend should have at least 3 consecutive failures, got %d", backendHealth.ConsecutiveFails)
	}
}

// TestRemoteLookupBackendMarkedUnhealthyImmediately verifies that remote lookup backends
// (not in pool) are marked unhealthy after the FIRST failure (no threshold)
func TestRemoteLookupBackendMarkedUnhealthyImmediately(t *testing.T) {
	// Create a pool backend
	poolBackend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create pool backend: %v", err)
	}
	defer poolBackend.Close()
	poolAddr := poolBackend.Addr().String()

	// Setup ConnectionManager with the pool backend
	cm, err := NewConnectionManager([]string{poolAddr}, 0, false, false, false, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	// Simulate remote_lookup returning a backend NOT in pool (guaranteed to fail)
	remoteLookupBackend := "192.0.2.1:143" // TEST-NET-1

	// Create routing info indicating this is a remote_lookup route
	routingInfo := &UserRoutingInfo{
		ServerAddress:         remoteLookupBackend,
		IsRemoteLookupAccount: true,
	}

	// Try to connect to the remote_lookup backend
	ctx := context.Background()
	_, _, err, _ = cm.tryPreferredAddress(ctx, remoteLookupBackend, "", 0, "", 0, routingInfo)

	// Should fail (backend doesn't exist)
	if err == nil {
		t.Error("Expected connection failure to remote_lookup backend")
	}

	// CRITICAL: Remote lookup backend should be marked unhealthy after FIRST failure
	if cm.IsRemoteLookupBackendHealthy(remoteLookupBackend) {
		t.Error("Remote lookup backend should be unhealthy after first failure")
	}

	// Verify remote lookup backend is in remoteLookupHealth map
	cm.healthMu.RLock()
	health, exists := cm.remoteLookupHealth[remoteLookupBackend]
	cm.healthMu.RUnlock()

	if !exists {
		t.Fatal("Remote lookup backend should be in remoteLookupHealth map")
	}

	if health.IsHealthy {
		t.Error("Remote lookup backend health.IsHealthy should be false")
	}

	if health.ConsecutiveFails != 1 {
		t.Errorf("Expected 1 consecutive failure, got %d", health.ConsecutiveFails)
	}

	if health.FailureCount != 1 {
		t.Errorf("Expected 1 failure count, got %d", health.FailureCount)
	}

	// Verify pool backend is still healthy (not affected)
	if !cm.IsBackendHealthy(poolAddr) {
		t.Error("Pool backend should still be healthy")
	}
}

// TestRemoteLookupBackendAutoRecoveryAfter1Minute verifies that remote lookup backends
// auto-recover after 1 minute of being unhealthy
func TestRemoteLookupBackendAutoRecoveryAfter1Minute(t *testing.T) {
	// Create a pool backend
	poolBackend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create pool backend: %v", err)
	}
	defer poolBackend.Close()
	poolAddr := poolBackend.Addr().String()

	// Setup ConnectionManager with the pool backend
	cm, err := NewConnectionManager([]string{poolAddr}, 0, false, false, false, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	// Manually create an unhealthy remote lookup backend
	remoteLookupBackend := "192.0.2.1:143"
	cm.healthMu.Lock()
	cm.remoteLookupHealth[remoteLookupBackend] = &BackendHealth{
		IsHealthy:        false,
		LastFailure:      time.Now().Add(-2 * time.Minute), // 2 minutes ago
		FailureCount:     5,
		ConsecutiveFails: 5,
	}
	cm.healthMu.Unlock()

	// Should be unhealthy initially (last failure > 1 minute ago means auto-recovery)
	// But the IsRemoteLookupBackendHealthy method should auto-recover it
	if !cm.IsRemoteLookupBackendHealthy(remoteLookupBackend) {
		t.Error("Remote lookup backend should auto-recover after 1 minute")
	}

	// Verify health was updated
	cm.healthMu.RLock()
	health := cm.remoteLookupHealth[remoteLookupBackend]
	cm.healthMu.RUnlock()

	if !health.IsHealthy {
		t.Error("Remote lookup backend should be marked healthy after auto-recovery")
	}

	if health.ConsecutiveFails != 0 {
		t.Errorf("ConsecutiveFails should be reset to 0, got %d", health.ConsecutiveFails)
	}
}

// TestRemoteLookupBackendCircuitBreakerPreventsConnection verifies that when a remote lookup
// backend is unhealthy, tryPreferredAddress fails immediately without attempting connection
func TestRemoteLookupBackendCircuitBreakerPreventsConnection(t *testing.T) {
	// Create a pool backend
	poolBackend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create pool backend: %v", err)
	}
	defer poolBackend.Close()
	poolAddr := poolBackend.Addr().String()

	// Setup ConnectionManager with the pool backend
	cm, err := NewConnectionManager([]string{poolAddr}, 0, false, false, false, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	// Manually create an unhealthy remote lookup backend (recent failure)
	remoteLookupBackend := "192.0.2.1:143"
	cm.healthMu.Lock()
	cm.remoteLookupHealth[remoteLookupBackend] = &BackendHealth{
		IsHealthy:        false,
		LastFailure:      time.Now(), // Recent failure
		FailureCount:     3,
		ConsecutiveFails: 3,
	}
	cm.healthMu.Unlock()

	// Create routing info indicating this is a remote_lookup route
	routingInfo := &UserRoutingInfo{
		ServerAddress:         remoteLookupBackend,
		IsRemoteLookupAccount: true,
	}

	// Try to connect - should fail immediately without attempting connection
	ctx := context.Background()
	startTime := time.Now()
	_, _, err, shouldFallback := cm.tryPreferredAddress(ctx, remoteLookupBackend, "", 0, "", 0, routingInfo)
	duration := time.Since(startTime)

	// Should fail
	if err == nil {
		t.Error("Expected immediate failure for unhealthy remote lookup backend")
	}

	// Should NOT fallback (remote lookup routes are definitive)
	if shouldFallback {
		t.Error("Should not fallback for remote lookup routes")
	}

	// Should fail IMMEDIATELY (< 10ms), not after connection timeout
	if duration > 10*time.Millisecond {
		t.Errorf("Should fail immediately (circuit breaker), took %v", duration)
	}

	// Error message should indicate unhealthy backend
	if !strings.Contains(err.Error(), "unhealthy") {
		t.Errorf("Error should mention unhealthy backend, got: %v", err)
	}
}

// TestRemoteLookupBackendSuccessRecording verifies that successful connections to
// remote lookup backends are recorded and mark backends as healthy
func TestRemoteLookupBackendSuccessRecording(t *testing.T) {
	// Create a pool backend that we'll use for the test
	poolBackend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create pool backend: %v", err)
	}
	defer poolBackend.Close()
	poolAddr := poolBackend.Addr().String()

	// Also create a "remote lookup" backend that we'll actually connect to
	// (in reality it's just another backend, but we'll treat it as remote lookup)
	remoteLookupListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create remote lookup backend: %v", err)
	}
	defer remoteLookupListener.Close()
	remoteLookupAddr := remoteLookupListener.Addr().String()

	// Accept one connection
	go func() {
		conn, _ := remoteLookupListener.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	// Setup ConnectionManager with ONLY the pool backend
	cm, err := NewConnectionManager([]string{poolAddr}, 0, false, false, false, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	// Pre-mark the remote lookup backend as unhealthy
	cm.healthMu.Lock()
	cm.remoteLookupHealth[remoteLookupAddr] = &BackendHealth{
		IsHealthy:        false,
		LastFailure:      time.Now().Add(-2 * time.Minute), // Will auto-recover
		FailureCount:     3,
		ConsecutiveFails: 3,
	}
	cm.healthMu.Unlock()

	// Create routing info indicating this is a remote_lookup route
	routingInfo := &UserRoutingInfo{
		ServerAddress:         remoteLookupAddr,
		IsRemoteLookupAccount: true,
	}

	// Try to connect to the remote_lookup backend
	ctx := context.Background()
	conn, addr, err, _ := cm.tryPreferredAddress(ctx, remoteLookupAddr, "", 0, "", 0, routingInfo)

	// Should succeed
	if err != nil {
		t.Fatalf("Expected successful connection, got error: %v", err)
	}
	if conn != nil {
		conn.Close()
	}

	if addr != remoteLookupAddr {
		t.Errorf("Expected address %s, got %s", remoteLookupAddr, addr)
	}

	// Verify backend is now healthy
	if !cm.IsRemoteLookupBackendHealthy(remoteLookupAddr) {
		t.Error("Remote lookup backend should be healthy after successful connection")
	}

	// Verify health tracking
	cm.healthMu.RLock()
	health := cm.remoteLookupHealth[remoteLookupAddr]
	cm.healthMu.RUnlock()

	if !health.IsHealthy {
		t.Error("Remote lookup backend health.IsHealthy should be true")
	}

	if health.ConsecutiveFails != 0 {
		t.Errorf("ConsecutiveFails should be reset to 0, got %d", health.ConsecutiveFails)
	}

	if health.LastSuccess.IsZero() {
		t.Error("LastSuccess should be set")
	}
}

// TestRemoteLookupBackendContextCancellationDoesNotMarkUnhealthy verifies that
// context cancellation/timeout does NOT mark remote lookup backends unhealthy
func TestRemoteLookupBackendContextCancellationDoesNotMarkUnhealthy(t *testing.T) {
	// Create a pool backend
	poolBackend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create pool backend: %v", err)
	}
	defer poolBackend.Close()
	poolAddr := poolBackend.Addr().String()

	// Setup ConnectionManager with the pool backend
	cm, err := NewConnectionManager([]string{poolAddr}, 0, false, false, false, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	// Use a backend that will timeout (blackhole address)
	remoteLookupBackend := "192.0.2.1:143" // TEST-NET-1, guaranteed to timeout

	// Create routing info indicating this is a remote_lookup route
	routingInfo := &UserRoutingInfo{
		ServerAddress:         remoteLookupBackend,
		IsRemoteLookupAccount: true,
	}

	// Use a very short context timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Wait for context to expire
	time.Sleep(5 * time.Millisecond)

	// Try to connect with expired context
	_, _, err, _ = cm.tryPreferredAddress(ctx, remoteLookupBackend, "", 0, "", 0, routingInfo)

	// Should fail
	if err == nil {
		t.Error("Expected connection failure")
	}

	// CRITICAL: Remote lookup backend should NOT be in health map (context error, not backend health issue)
	cm.healthMu.RLock()
	_, exists := cm.remoteLookupHealth[remoteLookupBackend]
	cm.healthMu.RUnlock()

	if exists {
		t.Error("Remote lookup backend should NOT be tracked when failure is due to context cancellation")
	}

	// Should still be considered healthy (unknown = healthy)
	if !cm.IsRemoteLookupBackendHealthy(remoteLookupBackend) {
		t.Error("Remote lookup backend should be healthy (unknown) when context cancellation occurs")
	}
}

// TestGetBackendHealthStatusesIncludesBothPoolAndRemoteLookup verifies that
// GetBackendHealthStatuses returns both pool backends and remote lookup backends
func TestGetBackendHealthStatusesIncludesBothPoolAndRemoteLookup(t *testing.T) {
	// Create two pool backends
	poolBackend1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create pool backend 1: %v", err)
	}
	defer poolBackend1.Close()
	poolAddr1 := poolBackend1.Addr().String()

	poolBackend2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create pool backend 2: %v", err)
	}
	defer poolBackend2.Close()
	poolAddr2 := poolBackend2.Addr().String()

	// Setup ConnectionManager with pool backends
	cm, err := NewConnectionManager([]string{poolAddr1, poolAddr2}, 0, false, false, false, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	// Add some remote lookup backends
	remoteLookup1 := "remote1.example.com:143"
	remoteLookup2 := "remote2.example.com:143"

	cm.healthMu.Lock()
	cm.remoteLookupHealth[remoteLookup1] = &BackendHealth{
		IsHealthy:        true,
		LastSuccess:      time.Now(),
		FailureCount:     0,
		ConsecutiveFails: 0,
	}
	cm.remoteLookupHealth[remoteLookup2] = &BackendHealth{
		IsHealthy:        false,
		LastFailure:      time.Now(),
		FailureCount:     3,
		ConsecutiveFails: 3,
	}
	cm.healthMu.Unlock()

	// Get all backend health statuses
	statuses := cm.GetBackendHealthStatuses()

	// Should have 4 backends total (2 pool + 2 remote lookup)
	if len(statuses) != 4 {
		t.Fatalf("Expected 4 backends, got %d", len(statuses))
	}

	// Count pool vs remote lookup backends
	poolCount := 0
	remoteLookupCount := 0
	for _, status := range statuses {
		if status.IsRemoteLookup {
			remoteLookupCount++
		} else {
			poolCount++
		}
	}

	if poolCount != 2 {
		t.Errorf("Expected 2 pool backends, got %d", poolCount)
	}

	if remoteLookupCount != 2 {
		t.Errorf("Expected 2 remote lookup backends, got %d", remoteLookupCount)
	}

	// Verify remote lookup backends are marked correctly
	for _, status := range statuses {
		if status.Address == remoteLookup1 {
			if !status.IsRemoteLookup {
				t.Error("remoteLookup1 should be marked as remote lookup backend")
			}
			if !status.IsHealthy {
				t.Error("remoteLookup1 should be healthy")
			}
		}
		if status.Address == remoteLookup2 {
			if !status.IsRemoteLookup {
				t.Error("remoteLookup2 should be marked as remote lookup backend")
			}
			if status.IsHealthy {
				t.Error("remoteLookup2 should be unhealthy")
			}
			if status.ConsecutiveFails != 3 {
				t.Errorf("remoteLookup2 should have 3 consecutive fails, got %d", status.ConsecutiveFails)
			}
		}
	}

	// Verify pool backends are NOT marked as remote lookup
	for _, status := range statuses {
		if status.Address == poolAddr1 || status.Address == poolAddr2 {
			if status.IsRemoteLookup {
				t.Errorf("Pool backend %s should NOT be marked as remote lookup", status.Address)
			}
		}
	}
}
