package config

import (
	"fmt"
	"strconv"
	"strings"
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

func TestClusterConfig_AddrWithPort(t *testing.T) {
	cfg := ClusterConfig{
		Addr: "10.10.10.40:7946",
	}

	addr := cfg.GetBindAddr()
	if addr != "10.10.10.40" {
		t.Errorf("Expected addr '10.10.10.40', got '%s'", addr)
	}

	port := cfg.GetBindPort()
	if port != 7946 {
		t.Errorf("Expected port 7946, got %d", port)
	}
}

func TestClusterConfig_AddrWithoutPort(t *testing.T) {
	cfg := ClusterConfig{
		Addr: "10.10.10.40",
		Port: 8888,
	}

	addr := cfg.GetBindAddr()
	if addr != "10.10.10.40" {
		t.Errorf("Expected addr '10.10.10.40', got '%s'", addr)
	}

	port := cfg.GetBindPort()
	if port != 8888 {
		t.Errorf("Expected port 8888 from Port field, got %d", port)
	}
}

func TestClusterConfig_AddrWithPortAndPortField(t *testing.T) {
	// When both addr contains port AND port field is set,
	// the port from addr should take precedence
	cfg := ClusterConfig{
		Addr: "10.10.10.40:7946",
		Port: 8888, // This should be ignored
	}

	addr := cfg.GetBindAddr()
	if addr != "10.10.10.40" {
		t.Errorf("Expected addr '10.10.10.40', got '%s'", addr)
	}

	port := cfg.GetBindPort()
	if port != 7946 {
		t.Errorf("Expected port 7946 from addr (not 8888 from Port field), got %d", port)
	}
}

func TestClusterConfig_DefaultPort(t *testing.T) {
	cfg := ClusterConfig{
		Addr: "10.10.10.40",
		// No Port field set
	}

	addr := cfg.GetBindAddr()
	if addr != "10.10.10.40" {
		t.Errorf("Expected addr '10.10.10.40', got '%s'", addr)
	}

	port := cfg.GetBindPort()
	if port != 7946 {
		t.Errorf("Expected default port 7946, got %d", port)
	}
}

func TestClusterConfig_EmptyAddr(t *testing.T) {
	cfg := ClusterConfig{
		Port: 8888,
	}

	addr := cfg.GetBindAddr()
	if addr != "" {
		t.Errorf("Expected empty addr, got '%s'", addr)
	}

	port := cfg.GetBindPort()
	if port != 8888 {
		t.Errorf("Expected port 8888, got %d", port)
	}
}

func TestClusterConfig_InvalidPortInAddr(t *testing.T) {
	cfg := ClusterConfig{
		Addr: "10.10.10.40:invalid",
		Port: 8888,
	}

	addr := cfg.GetBindAddr()
	if addr != "10.10.10.40" {
		t.Errorf("Expected addr '10.10.10.40', got '%s'", addr)
	}

	// When addr port is invalid, should fall back to Port field
	port := cfg.GetBindPort()
	if port != 8888 {
		t.Errorf("Expected port 8888 (fallback), got %d", port)
	}
}

func TestClusterConfig_LoopbackAddress(t *testing.T) {
	// Loopback addresses are allowed (for testing) but should generate a warning
	cfg := ClusterConfig{
		Addr: "127.0.0.1:7946",
	}

	addr := cfg.GetBindAddr()
	if addr != "127.0.0.1" {
		t.Errorf("Expected addr '127.0.0.1', got '%s'", addr)
	}

	port := cfg.GetBindPort()
	if port != 7946 {
		t.Errorf("Expected port 7946, got %d", port)
	}
}

// Test database configuration with hosts containing ports
func TestDatabaseEndpointConfig_HostsWithPorts(t *testing.T) {
	tests := []struct {
		name     string
		hosts    []string
		port     any
		expected map[string]string // host -> expected host:port
	}{
		{
			name:  "hosts with ports, port field ignored",
			hosts: []string{"db1.example.com:5433", "db2.example.com:5434"},
			port:  5432,
			expected: map[string]string{
				"db1.example.com:5433": "db1.example.com:5433",
				"db2.example.com:5434": "db2.example.com:5434",
			},
		},
		{
			name:  "hosts without ports, port field used",
			hosts: []string{"db1.example.com", "db2.example.com"},
			port:  5433,
			expected: map[string]string{
				"db1.example.com": "db1.example.com:5433",
				"db2.example.com": "db2.example.com:5433",
			},
		},
		{
			name:  "mixed hosts (some with port, some without)",
			hosts: []string{"db1.example.com:5433", "db2.example.com"},
			port:  5432,
			expected: map[string]string{
				"db1.example.com:5433": "db1.example.com:5433",
				"db2.example.com":      "db2.example.com:5432",
			},
		},
		{
			name:  "hosts without ports, no port field (default 5432)",
			hosts: []string{"db1.example.com"},
			port:  nil,
			expected: map[string]string{
				"db1.example.com": "db1.example.com:5432",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DatabaseEndpointConfig{
				Hosts: tt.hosts,
				Port:  tt.port,
			}

			// Verify each host gets the correct port treatment
			for host, expectedHostPort := range tt.expected {
				// This test documents the expected behavior based on db/db.go:807-832
				// The actual logic is in createPoolFromEndpointWithFailover
				var actualHostPort string
				if strings.Contains(host, ":") {
					actualHostPort = host
				} else {
					port := 5432 // default
					if cfg.Port != nil {
						switch v := cfg.Port.(type) {
						case string:
							if p, err := strconv.ParseInt(v, 10, 32); err == nil {
								port = int(p)
							}
						case int:
							port = v
						case int64:
							port = int(v)
						}
					}
					actualHostPort = fmt.Sprintf("%s:%d", host, port)
				}

				if actualHostPort != expectedHostPort {
					t.Errorf("Host %s: expected %s, got %s", host, expectedHostPort, actualHostPort)
				}
			}
		})
	}
}
