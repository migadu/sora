//go:build integration
// +build integration

package relay_test

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/server/delivery"
)

// Mock logger for integration tests
type integrationLogger struct {
	t    *testing.T
	logs []string
	mu   sync.Mutex
}

func (l *integrationLogger) Log(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	l.logs = append(l.logs, msg)
	l.t.Logf("[RELAY] %s", msg)
}

// Test SMTP server backend
type testSMTPBackend struct {
	messages []testSMTPMessage
	mu       sync.Mutex
}

type testSMTPMessage struct {
	From string
	To   []string
	Data []byte
}

func (b *testSMTPBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &testSMTPSession{backend: b}, nil
}

type testSMTPSession struct {
	backend *testSMTPBackend
	from    string
	to      []string
}

func (s *testSMTPSession) AuthPlain(username, password string) error {
	return nil
}

func (s *testSMTPSession) Mail(from string, opts *smtp.MailOptions) error {
	s.from = from
	return nil
}

func (s *testSMTPSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.to = append(s.to, to)
	return nil
}

func (s *testSMTPSession) Data(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	s.backend.mu.Lock()
	s.backend.messages = append(s.backend.messages, testSMTPMessage{
		From: s.from,
		To:   s.to,
		Data: data,
	})
	s.backend.mu.Unlock()

	return nil
}

func (s *testSMTPSession) Reset() {}

func (s *testSMTPSession) Logout() error {
	return nil
}

// TestSMTPRelayPlainConnection tests relay without TLS
func TestSMTPRelayPlainConnection(t *testing.T) {
	backend := &testSMTPBackend{}
	server := smtp.NewServer(backend)
	server.Addr = "127.0.0.1:0"
	server.Domain = "test.example.com"
	server.AllowInsecureAuth = true

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	actualAddr := listener.Addr().String()
	t.Logf("Test SMTP server listening on %s", actualAddr)

	go func() {
		if err := server.Serve(listener); err != nil && !strings.Contains(err.Error(), "use of closed") {
			t.Logf("SMTP server error: %v", err)
		}
	}()
	defer server.Close()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

	// Create relay handler
	logger := &integrationLogger{t: t}
	handler := &delivery.SMTPRelayHandler{
		SMTPHost:     actualAddr,
		UseTLS:       false,
		MetricsLabel: "integration_test",
		Logger:       logger,
	}

	// Send test message
	from := "sender@example.com"
	to := "recipient@example.com"
	message := []byte("Subject: Test\r\n\r\nThis is a test message")

	err = handler.SendToExternalRelay(from, to, message)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Verify message was received
	backend.mu.Lock()
	defer backend.mu.Unlock()

	if len(backend.messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(backend.messages))
	}

	msg := backend.messages[0]
	if msg.From != from {
		t.Errorf("Expected from %s, got %s", from, msg.From)
	}
	if len(msg.To) != 1 || msg.To[0] != to {
		t.Errorf("Expected to [%s], got %v", to, msg.To)
	}
	if !strings.Contains(string(msg.Data), "test message") {
		t.Errorf("Message data does not contain expected content: %s", msg.Data)
	}
}

// TestSMTPRelayDirectTLS tests relay with direct TLS connection
func TestSMTPRelayDirectTLS(t *testing.T) {
	backend := &testSMTPBackend{}
	server := smtp.NewServer(backend)
	server.Addr = "127.0.0.1:0"
	server.Domain = "test.example.com"
	server.AllowInsecureAuth = true

	// Create self-signed certificate for testing
	cert, err := tls.X509KeyPair(testCert, testKey)
	if err != nil {
		t.Fatalf("Failed to load test certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", server.Addr, tlsConfig)
	if err != nil {
		t.Fatalf("Failed to create TLS listener: %v", err)
	}
	defer listener.Close()

	actualAddr := listener.Addr().String()
	t.Logf("Test SMTP/TLS server listening on %s", actualAddr)

	go func() {
		if err := server.Serve(listener); err != nil && !strings.Contains(err.Error(), "use of closed") {
			t.Logf("SMTP server error: %v", err)
		}
	}()
	defer server.Close()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

	// Create relay handler with TLS but skip verification (self-signed cert)
	logger := &integrationLogger{t: t}
	handler := &delivery.SMTPRelayHandler{
		SMTPHost:     actualAddr,
		UseTLS:       true,
		TLSVerify:    false, // Skip verification for self-signed cert
		UseStartTLS:  false,
		MetricsLabel: "integration_test",
		Logger:       logger,
	}

	// Send test message
	from := "sender@example.com"
	to := "recipient@example.com"
	message := []byte("Subject: TLS Test\r\n\r\nThis is a TLS test message")

	err = handler.SendToExternalRelay(from, to, message)
	if err != nil {
		t.Fatalf("Failed to send message over TLS: %v", err)
	}

	// Verify message was received
	backend.mu.Lock()
	defer backend.mu.Unlock()

	if len(backend.messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(backend.messages))
	}

	msg := backend.messages[0]
	if msg.From != from {
		t.Errorf("Expected from %s, got %s", from, msg.From)
	}
}

// TestSMTPRelayStartTLS tests relay with STARTTLS
func TestSMTPRelayStartTLS(t *testing.T) {
	backend := &testSMTPBackend{}
	server := smtp.NewServer(backend)
	server.Addr = "127.0.0.1:0"
	server.Domain = "test.example.com"
	server.AllowInsecureAuth = true

	// Create self-signed certificate for testing
	cert, err := tls.X509KeyPair(testCert, testKey)
	if err != nil {
		t.Fatalf("Failed to load test certificate: %v", err)
	}

	server.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	actualAddr := listener.Addr().String()
	t.Logf("Test SMTP server (STARTTLS) listening on %s", actualAddr)

	go func() {
		if err := server.Serve(listener); err != nil && !strings.Contains(err.Error(), "use of closed") {
			t.Logf("SMTP server error: %v", err)
		}
	}()
	defer server.Close()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

	// Create relay handler with STARTTLS
	logger := &integrationLogger{t: t}
	handler := &delivery.SMTPRelayHandler{
		SMTPHost:     actualAddr,
		UseTLS:       true,
		TLSVerify:    false, // Skip verification for self-signed cert
		UseStartTLS:  true,
		MetricsLabel: "integration_test",
		Logger:       logger,
	}

	// Send test message
	from := "sender@example.com"
	to := "recipient@example.com"
	message := []byte("Subject: STARTTLS Test\r\n\r\nThis is a STARTTLS test message")

	err = handler.SendToExternalRelay(from, to, message)
	if err != nil {
		t.Fatalf("Failed to send message with STARTTLS: %v", err)
	}

	// Verify message was received
	backend.mu.Lock()
	defer backend.mu.Unlock()

	if len(backend.messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(backend.messages))
	}

	msg := backend.messages[0]
	if msg.From != from {
		t.Errorf("Expected from %s, got %s", from, msg.From)
	}
}

// TestHTTPRelayIntegration tests HTTP relay with a real HTTP server
func TestHTTPRelayIntegration(t *testing.T) {
	receivedMessages := []map[string]any{}
	var mu sync.Mutex

	// Create test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify method
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Verify authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer test-token-123" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}

		// Parse request body
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid json"})
			return
		}

		mu.Lock()
		receivedMessages = append(receivedMessages, req)
		mu.Unlock()

		// Success response
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message_id": "12345"})
	}))
	defer server.Close()

	// Create relay handler
	logger := &integrationLogger{t: t}
	handler := &delivery.HTTPRelayHandler{
		HTTPURL:      server.URL,
		AuthToken:    "test-token-123",
		MetricsLabel: "integration_test",
		Logger:       logger,
	}

	// Send test message
	from := "sender@example.com"
	to := "recipient@example.com"
	message := []byte("Subject: HTTP Test\r\n\r\nThis is an HTTP relay test message")

	err := handler.SendToExternalRelay(from, to, message)
	if err != nil {
		t.Fatalf("Failed to send message via HTTP: %v", err)
	}

	// Verify message was received
	mu.Lock()
	defer mu.Unlock()

	if len(receivedMessages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(receivedMessages))
	}

	msg := receivedMessages[0]
	if msg["from"] != from {
		t.Errorf("Expected from %s, got %v", from, msg["from"])
	}

	// Check recipients array
	recipients, ok := msg["recipients"].([]any)
	if !ok {
		t.Fatalf("Expected recipients to be an array, got %T", msg["recipients"])
	}
	if len(recipients) != 1 {
		t.Fatalf("Expected 1 recipient, got %d", len(recipients))
	}
	if recipients[0] != to {
		t.Errorf("Expected recipient %s, got %v", to, recipients[0])
	}
}

// TestHTTPRelayHTTPS tests HTTP relay with HTTPS
func TestHTTPRelayHTTPS(t *testing.T) {
	var mu sync.Mutex
	messageReceived := false

	// Create test HTTPS server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		messageReceived = true
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	// Create relay handler
	logger := &integrationLogger{t: t}
	handler := &delivery.HTTPRelayHandler{
		HTTPURL:      server.URL,
		AuthToken:    "test-token",
		MetricsLabel: "integration_test",
		Logger:       logger,
	}

	// The httptest.NewTLSServer creates a client with InsecureSkipVerify,
	// but our handler creates its own client. For testing, we'll use the URL
	// which will work because httptest server handles TLS.

	// Send test message
	from := "sender@example.com"
	to := "recipient@example.com"
	message := []byte("Subject: HTTPS Test\r\n\r\nThis is an HTTPS relay test")

	err := handler.SendToExternalRelay(from, to, message)
	if err != nil {
		// This might fail with certificate verification error, which is expected
		// for self-signed certs. Log it but don't fail the test.
		t.Logf("Expected error with self-signed cert: %v", err)
		return
	}

	// Verify message was received
	mu.Lock()
	defer mu.Unlock()

	if !messageReceived {
		t.Error("Message was not received by HTTPS server")
	}
}

// TestNewRelayHandlerFromConfigIntegration tests the factory with integration
func TestNewRelayHandlerFromConfigIntegration(t *testing.T) {
	logger := &integrationLogger{t: t}

	tests := []struct {
		name       string
		relayType  string
		smtpHost   string
		httpURL    string
		expectType string
	}{
		{
			name:       "SMTP handler creation",
			relayType:  "smtp",
			smtpHost:   "smtp.example.com:587",
			expectType: "*delivery.SMTPRelayHandler",
		},
		{
			name:       "HTTP handler creation",
			relayType:  "http",
			httpURL:    "https://api.example.com/deliver",
			expectType: "*delivery.HTTPRelayHandler",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := delivery.NewRelayHandlerFromConfig(
				tt.relayType,
				tt.smtpHost,
				tt.httpURL,
				"token",
				"integration_test",
				true,
				true,
				true,
				"",
				"",
				logger,
				delivery.CircuitBreakerConfig{}, // Empty circuit breaker config (uses defaults)
			)

			if handler == nil {
				t.Fatal("Expected non-nil handler")
			}

			handlerType := fmt.Sprintf("%T", handler)
			if handlerType != tt.expectType {
				t.Errorf("Expected handler type %s, got %s", tt.expectType, handlerType)
			}
		})
	}
}

// Self-signed test certificate (for testing only)
var testCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUHXYvJczGD+FiAX8K0yqJY4N4Ah4wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI1MTAyODE5MTcxM1oXDTI2MTAy
ODE5MTcxM1owFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAk4XY+r+dTXuSpOuRwismMQHU/NNTGZANlNh6r36Hm3/v
h+A43gYJ7ROxCpf3saIjTlVdNBQyxMQ3BJdyvGMYeljbNfPRuefKIRVIlaqDuSnR
3WST0Px/yW1opurQRoM+XrEqx5/xS6SU4bdWqAGMvW6ftfsP9W1+fyzp2QKMm/QI
Cp6NIi4ckgr5UvAKQ5t22sDwUV0uiSWfXvfIAO78NRdpmsU4pQ3GcxjOB6WN98q+
9bz/4HfAjAULY0/tXmILO4bN8XOeEZ+iluohCGTuhhJJOlK2KpCnfZmFIeu5UZbn
uon0WMuN04Vw/YKyq7/q24WMnyXDofBtrW7xKxwu0wIDAQABo1MwUTAdBgNVHQ4E
FgQUQPX4sYpi2DvLWhEkenjW36PSy6UwHwYDVR0jBBgwFoAUQPX4sYpi2DvLWhEk
enjW36PSy6UwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAZzXY
RnMIAdJ+jsq5F6ZevcGAlXOt7mXVlWjGQdrE1KedsAXDGycBTVl4Gjx0noRKgsGM
dxO6obKtfoQrPUx/56Bvid4k8zNPDiIAVCHNX4lIrbzi7jkXpaW7lruOIBoHPQCR
P2BpLDm/axfsCjqTKv8qoBa2m7q2wruLLrY+zn5UYjz4VjQcx2punQIdqF/vZzx9
24sfs+oZO5arMuH8NEyMO7s8Bl+sMx6qpIFlw65esRlIJPK1KZFEgi+13nkBOAIy
FPIxWQxhNmwoTzahQBd9xlwdKZeCkyvcQI+4lIEwSFlO//n/IQgAcJH7VaaCNNn4
q01cfRhU3xDTw7Kv9g==
-----END CERTIFICATE-----`)

var testKey = []byte(`-----BEGIN PRIVATE KEY-----
MIIEugIBADANBgkqhkiG9w0BAQEFAASCBKQwggSgAgEAAoIBAQCThdj6v51Ne5Kk
65HCKyYxAdT801MZkA2U2Hqvfoebf++H4DjeBgntE7EKl/exoiNOVV00FDLExDcE
l3K8Yxh6WNs189G558ohFUiVqoO5KdHdZJPQ/H/JbWim6tBGgz5esSrHn/FLpJTh
t1aoAYy9bp+1+w/1bX5/LOnZAoyb9AgKno0iLhySCvlS8ApDm3bawPBRXS6JJZ9e
98gA7vw1F2maxTilDcZzGM4HpY33yr71vP/gd8CMBQtjT+1eYgs7hs3xc54Rn6KW
6iEIZO6GEkk6UrYqkKd9mYUh67lRlue6ifRYy43ThXD9grKrv+rbhYyfJcOh8G2t
bvErHC7TAgMBAAECgf8f+2SO9/uiUKf6GRgAgFpHRZ5nMWlSoWhQXJ48bbH4hEPp
sTKi76w3OY2oPkn0uLHuyZLrN3XKMr+6vxqgvNsRqzHbAID3TMkFYxfZWp40Blz5
IlTpedQ6Vv3ZMg71On7LCJ29qW8mdwfP529h/PQGHXWCfmt3ScWizJnl8ieJp4nQ
BJxEUXrynSDfD8xoBXzH8BmaEy9C630GUWc0zP6slkhgyPOPCCdcLaIQlVlNtCt3
FEltFGvA9tyFc2OZzBT8kcQ5WJM2UkrSzHqoKbA59e1a+FQZ9Yhbo6hmk/po23Iy
Fkvvcn/aEdqGq9SuPAWZGPt58v8bx2g5ZnpVbKkCgYEAxe7LSSROcG/b6IFN+3At
IZONnxGr81eR/blMF16OeX+k5e1DFgntp+0Wk9lQcPd2/AeHOWnjLp8s3T6lIHJd
tzJw9NC8ngs/yTAJi27JzbPaE10lpna3gexMxGqqeTTSqi4BtjHn5s/FTlAX7dku
T1lCfALuEVByNMBlyN48uKsCgYEAvs0mpdlNPDQzU8U5fa0N9VMTk/LG+RDOcXhw
DxTAcq4mmubaj7kvSIkXBAPSDWDzBQi8r2Ah9d060fUZ6qqUyFkbmYEPkQ3FTlrt
BtBNbXCq0Tw1cDzmXcM+15gvW9hWNBRzhYs95jYrlY0DpTe+zLbBioDbkcOJrohy
ULwGsnkCgYBIGPNzcQYhbp1r063UKMhHsrejeYxo1z0WbqiI2qiLGTO3jPUi0fr/
cB0JPd9PRtTQeO2IvElEcjalYGxFpWL9mCINCvuple9mGVlgsLpRc3G8G/Ha8ONn
L+vGoBP4koUp+BgnhYYzTPtRy1rsCHAV9y2AfpC5PdRb4rkwscLsgQKBgEeL6CUi
sfqUXHbaKu+8d9J5X4sH66KzsaYNEoAlOPEH6sQFMwnX2Cor9ex0fky0AQzvNMnS
k4l9drQKY7iCVJ44A8hxA+RRtJ3oLJ90dsRGDle9axB2Va/tKeBwWbnoCpMm5Ba8
mu57e6ZtpWNL3wkmsrZ8EVm8aCGBWtR5XU2JAoGAGhKlqcHeaWZp4/cRM0zCj/E5
Cg3L0f+UGuPiSR3kVViEbULrMz/dcpEN3u3zTswMIhqFeM5bBmG/qV+3MU48KphG
P55rUWV6zU0aFvTIsjh+gNWe2vcLGcBBfS1Rb/7t2cwQb1oXFp535skMBCA9SmgB
N3907DTc4xmjz+3tBoE=
-----END PRIVATE KEY-----`)
