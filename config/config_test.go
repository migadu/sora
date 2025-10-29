package config

import (
	"testing"
	"time"
)

func TestRelayQueueConfig_CircuitBreakerDefaults(t *testing.T) {
	cfg := RelayQueueConfig{}

	// Test default threshold
	threshold := cfg.GetCircuitBreakerThreshold()
	if threshold != 5 {
		t.Errorf("Expected default threshold 5, got %d", threshold)
	}

	// Test default timeout
	timeout, err := cfg.GetCircuitBreakerTimeout()
	if err != nil {
		t.Fatalf("Failed to get default timeout: %v", err)
	}
	if timeout != 30*time.Second {
		t.Errorf("Expected default timeout 30s, got %v", timeout)
	}

	// Test default max requests
	maxRequests := cfg.GetCircuitBreakerMaxRequests()
	if maxRequests != 3 {
		t.Errorf("Expected default max requests 3, got %d", maxRequests)
	}
}

func TestRelayQueueConfig_CircuitBreakerCustomValues(t *testing.T) {
	cfg := RelayQueueConfig{
		CircuitBreakerThreshold:   10,
		CircuitBreakerTimeout:     "1m",
		CircuitBreakerMaxRequests: 5,
	}

	// Test custom threshold
	threshold := cfg.GetCircuitBreakerThreshold()
	if threshold != 10 {
		t.Errorf("Expected threshold 10, got %d", threshold)
	}

	// Test custom timeout
	timeout, err := cfg.GetCircuitBreakerTimeout()
	if err != nil {
		t.Fatalf("Failed to parse timeout: %v", err)
	}
	if timeout != 1*time.Minute {
		t.Errorf("Expected timeout 1m, got %v", timeout)
	}

	// Test custom max requests
	maxRequests := cfg.GetCircuitBreakerMaxRequests()
	if maxRequests != 5 {
		t.Errorf("Expected max requests 5, got %d", maxRequests)
	}
}

func TestRelayQueueConfig_CircuitBreakerInvalidTimeout(t *testing.T) {
	cfg := RelayQueueConfig{
		CircuitBreakerTimeout: "invalid",
	}

	_, err := cfg.GetCircuitBreakerTimeout()
	if err == nil {
		t.Error("Expected error for invalid timeout, got nil")
	}
}
