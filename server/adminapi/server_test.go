package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Utility function tests

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expectedIP string
	}{
		{
			name: "X-Forwarded-For single IP",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.100",
			},
			remoteAddr: "10.0.0.1:12345",
			expectedIP: "192.168.1.100",
		},
		{
			name: "X-Forwarded-For multiple IPs",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.100, 10.0.0.5, 172.16.0.1",
			},
			remoteAddr: "10.0.0.1:12345",
			expectedIP: "192.168.1.100",
		},
		{
			name: "X-Real-IP header",
			headers: map[string]string{
				"X-Real-IP": "192.168.1.200",
			},
			remoteAddr: "10.0.0.1:12345",
			expectedIP: "192.168.1.200",
		},
		{
			name: "X-Forwarded-For takes precedence over X-Real-IP",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.100",
				"X-Real-IP":       "192.168.1.200",
			},
			remoteAddr: "10.0.0.1:12345",
			expectedIP: "192.168.1.100",
		},
		{
			name:       "fallback to RemoteAddr",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.50:12345",
			expectedIP: "192.168.1.50",
		},
		{
			name:       "IPv6 RemoteAddr",
			headers:    map[string]string{},
			remoteAddr: "[::1]:12345",
			expectedIP: "::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			ip := getClientIP(req)
			if ip != tt.expectedIP {
				t.Errorf("getClientIP() = %v, want %v", ip, tt.expectedIP)
			}
		})
	}
}

func TestAuthMiddleware(t *testing.T) {
	server := &Server{
		apiKey: "test-api-key-12345",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	tests := []struct {
		name                 string
		authHeader           string
		expectedStatus       int
		expectedBodyContains string
	}{
		{
			name:                 "no auth header",
			authHeader:           "",
			expectedStatus:       http.StatusUnauthorized,
			expectedBodyContains: "Authorization header required",
		},
		{
			name:                 "invalid auth format",
			authHeader:           "InvalidFormat",
			expectedStatus:       http.StatusUnauthorized,
			expectedBodyContains: "Authorization header must be 'Bearer",
		},
		{
			name:                 "wrong auth type",
			authHeader:           "Basic dGVzdA==",
			expectedStatus:       http.StatusUnauthorized,
			expectedBodyContains: "Authorization header must be 'Bearer",
		},
		{
			name:                 "invalid API key",
			authHeader:           "Bearer wrong-key",
			expectedStatus:       http.StatusForbidden,
			expectedBodyContains: "Invalid API key",
		},
		{
			name:                 "valid API key",
			authHeader:           "Bearer test-api-key-12345",
			expectedStatus:       http.StatusOK,
			expectedBodyContains: "success",
		},
		{
			name:                 "case insensitive bearer",
			authHeader:           "bearer test-api-key-12345",
			expectedStatus:       http.StatusOK,
			expectedBodyContains: "success",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			middleware := server.authMiddleware(handler)
			middleware.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("authMiddleware() status = %v, want %v", rr.Code, tt.expectedStatus)
			}

			if !strings.Contains(rr.Body.String(), tt.expectedBodyContains) {
				t.Errorf("authMiddleware() body = %v, want to contain %v", rr.Body.String(), tt.expectedBodyContains)
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
		{
			name:                 "mixed allowed - IP matches CIDR",
			allowedHosts:         []string{"10.0.0.1", "192.168.1.0/24"},
			clientIP:             "192.168.1.100",
			expectedStatus:       http.StatusOK,
			expectedBodyContains: "success",
		},
		{
			name:                 "invalid CIDR - treated as exact IP",
			allowedHosts:         []string{"192.168.1.0/invalid"},
			clientIP:             "192.168.1.50",
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

func TestWriteJSON(t *testing.T) {
	server := &Server{}

	tests := []struct {
		name           string
		status         int
		data           interface{}
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "simple object",
			status:         http.StatusOK,
			data:           map[string]string{"message": "hello"},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"hello"}`,
		},
		{
			name:           "error response",
			status:         http.StatusBadRequest,
			data:           map[string]string{"error": "invalid request"},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"invalid request"}`,
		},
		{
			name:           "nil data",
			status:         http.StatusNoContent,
			data:           nil,
			expectedStatus: http.StatusNoContent,
			expectedBody:   "null",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			server.writeJSON(rr, tt.status, tt.data)

			if rr.Code != tt.expectedStatus {
				t.Errorf("writeJSON() status = %v, want %v", rr.Code, tt.expectedStatus)
			}

			if rr.Header().Get("Content-Type") != "application/json" {
				t.Errorf("writeJSON() Content-Type = %v, want application/json", rr.Header().Get("Content-Type"))
			}

			body := strings.TrimSpace(rr.Body.String())
			if body != tt.expectedBody {
				t.Errorf("writeJSON() body = %v, want %v", body, tt.expectedBody)
			}
		})
	}
}

func TestWriteError(t *testing.T) {
	server := &Server{}

	tests := []struct {
		name           string
		status         int
		message        string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "bad request error",
			status:         http.StatusBadRequest,
			message:        "Invalid input",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"Invalid input"}`,
		},
		{
			name:           "server error",
			status:         http.StatusInternalServerError,
			message:        "Internal server error",
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   `{"error":"Internal server error"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			server.writeError(rr, tt.status, tt.message)

			if rr.Code != tt.expectedStatus {
				t.Errorf("writeError() status = %v, want %v", rr.Code, tt.expectedStatus)
			}

			body := strings.TrimSpace(rr.Body.String())
			if body != tt.expectedBody {
				t.Errorf("writeError() body = %v, want %v", body, tt.expectedBody)
			}
		})
	}
}

// Request validation tests

func TestCreateAccountRequestValidation(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "invalid JSON",
			requestBody:    "invalid-json",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid JSON body",
		},
		{
			name: "missing email for single account",
			requestBody: CreateAccountRequest{
				Password: "test-password",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Email is required",
		},
		{
			name: "missing password and hash for single account",
			requestBody: CreateAccountRequest{
				Email: "test@example.com",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Either password or password_hash is required",
		},
		{
			name: "both password and hash provided",
			requestBody: CreateAccountRequest{
				Email:        "test@example.com",
				Password:     "test-password",
				PasswordHash: "hashed-password",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Cannot specify both password and password_hash",
		},
		{
			name: "invalid credentials with email and credentials array",
			requestBody: CreateAccountRequest{
				Email: "test@example.com",
				Credentials: []CreateCredentialSpec{
					{Email: "test@example.com", Password: "password"},
				},
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Cannot specify email, password, or password_hash when using credentials array",
		},
		{
			name: "credentials array with missing email",
			requestBody: CreateAccountRequest{
				Credentials: []CreateCredentialSpec{
					{Password: "password"},
				},
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Credential 1: email is required",
		},
		{
			name: "credentials array with missing password and hash",
			requestBody: CreateAccountRequest{
				Credentials: []CreateCredentialSpec{
					{Email: "test@example.com"},
				},
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Credential 1: either password or password_hash is required",
		},
		{
			name: "credentials array with both password and hash",
			requestBody: CreateAccountRequest{
				Credentials: []CreateCredentialSpec{
					{
						Email:        "test@example.com",
						Password:     "password",
						PasswordHash: "hash",
					},
				},
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Credential 1: cannot specify both password and password_hash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			var err error

			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, err = json.Marshal(tt.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}
			}

			req := httptest.NewRequest("POST", "/api/v1/accounts", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer test-api-key")

			// Create a server with minimal setup just for validation testing
			server := &Server{
				apiKey: "test-api-key",
			}

			rr := httptest.NewRecorder()
			server.handleCreateAccount(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("handleCreateAccount() status = %v, want %v", rr.Code, tt.expectedStatus)
			}

			if !strings.Contains(rr.Body.String(), tt.expectedError) {
				t.Errorf("handleCreateAccount() body = %v, want to contain %v", rr.Body.String(), tt.expectedError)
			}
		})
	}
}

func TestUpdateAccountRequestValidation(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "invalid JSON",
			requestBody:    "invalid-json",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid JSON body",
		},
		{
			name:           "missing password and hash",
			requestBody:    UpdateAccountRequest{},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Either password or password_hash is required",
		},
		{
			name: "both password and hash provided",
			requestBody: UpdateAccountRequest{
				Password:     "test-password",
				PasswordHash: "hashed-password",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Cannot specify both password and password_hash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			var err error

			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, err = json.Marshal(tt.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}
			}

			req := httptest.NewRequest("PUT", "/api/v1/accounts/test@example.com", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer test-api-key")

			// Create a server with minimal setup just for validation testing
			server := &Server{
				apiKey: "test-api-key",
			}

			rr := httptest.NewRecorder()
			server.handleUpdateAccount(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("handleUpdateAccount() status = %v, want %v", rr.Code, tt.expectedStatus)
			}

			if !strings.Contains(rr.Body.String(), tt.expectedError) {
				t.Errorf("handleUpdateAccount() body = %v, want to contain %v", rr.Body.String(), tt.expectedError)
			}
		})
	}
}

func TestAddCredentialRequestValidation(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "invalid JSON",
			requestBody:    "invalid-json",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid JSON body",
		},
		{
			name: "missing email",
			requestBody: AddCredentialRequest{
				Password: "test-password",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Email is required",
		},
		{
			name: "missing password and hash",
			requestBody: AddCredentialRequest{
				Email: "test@example.com",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Either password or password_hash is required",
		},
		{
			name: "both password and hash provided",
			requestBody: AddCredentialRequest{
				Email:        "test@example.com",
				Password:     "test-password",
				PasswordHash: "hashed-password",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Cannot specify both password and password_hash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			var err error

			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, err = json.Marshal(tt.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}
			}

			req := httptest.NewRequest("POST", "/api/v1/accounts/primary@example.com/credentials", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer test-api-key")

			// Create a server with minimal setup just for validation testing
			server := &Server{
				apiKey: "test-api-key",
			}

			rr := httptest.NewRecorder()
			server.handleAddCredential(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("handleAddCredential() status = %v, want %v", rr.Code, tt.expectedStatus)
			}

			if !strings.Contains(rr.Body.String(), tt.expectedError) {
				t.Errorf("handleAddCredential() body = %v, want to contain %v", rr.Body.String(), tt.expectedError)
			}
		})
	}
}
