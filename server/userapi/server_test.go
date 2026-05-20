package userapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsIPAllowed(t *testing.T) {
	tests := []struct {
		name         string
		allowedHosts []string
		clientIP     string
		expected     bool
	}{
		{
			name:         "empty allowed hosts",
			allowedHosts: []string{},
			clientIP:     "192.168.1.1",
			expected:     false,
		},
		{
			name:         "exact match allowed IP",
			allowedHosts: []string{"192.168.1.1", "10.0.0.1"},
			clientIP:     "192.168.1.1",
			expected:     true,
		},
		{
			name:         "exact match blocked IP",
			allowedHosts: []string{"192.168.1.1", "10.0.0.1"},
			clientIP:     "192.168.1.2",
			expected:     false,
		},
		{
			name:         "allowed CIDR - IP in range",
			allowedHosts: []string{"192.168.1.0/24"},
			clientIP:     "192.168.1.50",
			expected:     true,
		},
		{
			name:         "blocked CIDR - IP outside range",
			allowedHosts: []string{"192.168.1.0/24"},
			clientIP:     "192.168.2.50",
			expected:     false,
		},
		{
			name:         "invalid CIDR - fallback to literal",
			allowedHosts: []string{"192.168.1.50", "invalid-cidr"},
			clientIP:     "192.168.1.50",
			expected:     true,
		},
		{
			name:         "invalid CIDR - fallback to literal blocked",
			allowedHosts: []string{"192.168.1.50", "invalid-cidr"},
			clientIP:     "192.168.1.51",
			expected:     false,
		},
		{
			name:         "IPv6 CIDR - IP in range",
			allowedHosts: []string{"2001:db8::/32"},
			clientIP:     "2001:db8::1",
			expected:     true,
		},
		{
			name:         "IPv6 CIDR - IP outside range",
			allowedHosts: []string{"2001:db8::/32"},
			clientIP:     "2001:db9::1",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isIPAllowed(tt.clientIP, tt.allowedHosts)
			if result != tt.expected {
				t.Errorf("isIPAllowed(%q, %v) = %v, want %v", tt.clientIP, tt.allowedHosts, result, tt.expected)
			}
		})
	}
}

func TestAllowedHostsMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	tests := []struct {
		name                 string
		allowedHosts         []string
		clientIP             string
		expectedStatus       int
		expectedBodyContains string
	}{
		{
			name:                 "no restrictions - allow all",
			allowedHosts:         []string{},
			clientIP:             "192.168.1.100",
			expectedStatus:       http.StatusOK,
			expectedBodyContains: "success",
		},
		{
			name:                 "allowed IP - exact match",
			allowedHosts:         []string{"192.168.1.100", "10.0.0.1"},
			clientIP:             "192.168.1.100",
			expectedStatus:       http.StatusOK,
			expectedBodyContains: "success",
		},
		{
			name:                 "blocked IP - not in allowed list",
			allowedHosts:         []string{"192.168.1.100", "10.0.0.1"},
			clientIP:             "192.168.1.200",
			expectedStatus:       http.StatusForbidden,
			expectedBodyContains: "Host not allowed",
		},
		{
			name:                 "allowed CIDR - IP in range",
			allowedHosts:         []string{"192.168.1.0/24"},
			clientIP:             "192.168.1.50",
			expectedStatus:       http.StatusOK,
			expectedBodyContains: "success",
		},
		{
			name:                 "blocked CIDR - IP outside range",
			allowedHosts:         []string{"192.168.1.0/24"},
			clientIP:             "192.168.2.50",
			expectedStatus:       http.StatusForbidden,
			expectedBodyContains: "Host not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &Server{
				allowedHosts: tt.allowedHosts,
			}

			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.clientIP + ":12345"

			rr := httptest.NewRecorder()
			middleware := server.allowedHostsMiddleware(handler)
			middleware.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("allowedHostsMiddleware() status = %v, want %v", rr.Code, tt.expectedStatus)
			}

			if !strings.Contains(rr.Body.String(), tt.expectedBodyContains) {
				t.Errorf("allowedHostsMiddleware() body = %v, want to contain %v", rr.Body.String(), tt.expectedBodyContains)
			}
		})
	}
}
